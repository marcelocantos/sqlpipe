# sqlpipe

Streaming replication protocol for SQLite. Two-file library: `dist/sqlpipe.h`
(public API) and `dist/sqlpipe.cpp` (implementation).

## Build

```sh
mk test     # build and run all tests
mk example  # build and run examples/loopback.cpp
mk clean    # remove build/
```

### Go wrapper

```sh
cd go/sqlpipe
go test -tags libsqlite3 ./...
```

The `-tags libsqlite3` flag is required — it tells mattn/go-sqlite3 to link
against the vendored SQLite rather than its bundled copy.

Requires C++23. Uses [mk](https://github.com/marcelocantos/mk) as the build
system (`mkfile`).

SQLite must be compiled with `-DSQLITE_ENABLE_SESSION
-DSQLITE_ENABLE_PREUPDATE_HOOK` (the mkfile sets these).

## Dependencies

- **SQLite3** — vendored in `vendor/src/sqlite3.c` + `vendor/include/sqlite3.h`
- **LZ4** — vendored in `vendor/src/lz4.c` + `vendor/include/lz4.h` (changeset compression)
- **spdlog** — git submodule at `vendor/github.com/gabime/spdlog` (header-only)
- **sqlift** — git submodule at `vendor/github.com/marcelocantos/sqlift` (structural schema diffing)
- **doctest** — vendored in `vendor/include/doctest.h` (test only)

## Architecture

### Protocol

Two modes of operation:

**Unidirectional** (Master/Replica): Master-replica replication over an abstract
message transport. The library is message-in / message-out; callers provide the
transport.

**Bidirectional** (Peer): Wraps Master + Replica behind a symmetric API. Each
side owns a disjoint set of tables. A `PeerMessage` wraps `Message` with a
`SenderRole` tag (`AsMaster`/`AsReplica`) for routing. Client requests ownership
in its HelloMsg; server validates via a callback. Wire format:
`[4B LE length][1B sender_role][1B tag][payload]`.

Two sync modes:
1. **Live streaming** — Master calls `flush()` after each write transaction;
   replica applies the resulting `ChangesetMsg`.
2. **Diff sync** — On reconnect, master and replica exchange bucketed row hashes
   to discover what differs, then the master sends only the delta as a
   `DiffReadyMsg` (INSERT patchset + per-table delete rowid lists).

### Key internals

- **Schema fingerprinting** (`compute_schema_fingerprint`): Uses sqlift to
  extract a structural schema, then hashes it (SHA-256 → FNV-1a 32-bit).
  Structural hashing means logically equivalent schemas produce the same
  fingerprint even after ALTER TABLE ADD COLUMN (which doesn't update
  `sqlite_master.sql` text).
- **Session extension**: `sqlite3session_create/attach/changeset` for change
  tracking. `sqlite3changeset_apply` on the replica side.
- **Pimpl**: `Master`, `Replica`, and `Peer` use `struct Impl` behind
  `std::unique_ptr` to keep the header dependency-free.
- **Internal tables**: `_sqlpipe_meta` (key-value, stores seq). Excluded from
  tracking. In Peer mode, Master and Replica use separate meta keys
  (`master_seq` / `replica_seq`) to avoid collision.
- **Table filtering**: `MasterConfig::table_filter` and
  `ReplicaConfig::table_filter` (`std::optional<std::set<std::string>>`)
  restrict which tables are tracked. `nullopt` = all tables, empty set = none.
  `compute_schema_fingerprint`, `get_tracked_tables`, and `get_schema_sql`
  accept an optional `const std::set<std::string>* filter` parameter.
- **Row hashing**: 64-bit FNV-1a over type-tagged column values. Used by the
  diff protocol to compare row content without sending data.
- **Bucket hashing**: Rows grouped into fixed-size buckets by rowid range
  (default 1024). Bucket hash = XOR of `fnv1a(rowid || row_hash)` for each row.
  Order-independent. Enables O(d + b) bandwidth for diff where d = differing
  rows and b = total buckets.
- **WITHOUT ROWID**: Not supported. Tables using `WITHOUT ROWID` are rejected
  during table discovery with `ErrorCode::WithoutRowidTable`.
- **Query subscriptions**: Replica-side feature. `Replica::subscribe(sql)`
  registers a query and returns the current result. After each
  `handle_message` that applies changes to a table the query reads from, the
  updated result appears in `HandleResult::subscriptions`. Table dependencies
  discovered via `sqlite3_set_authorizer` during prepare. Invalidation is
  table-level (any change to an overlapping table triggers re-evaluation).
- **`sync_handshake`**: Convenience functions that drive the handshake loop
  to completion — `sync_handshake(Master&, Replica&)` and
  `sync_handshake(Peer&, Peer&)`. Used by tests and examples.

### Wire format

`[4-byte LE length][1-byte tag][payload...]` — see `MessageTag` enum and
`serialize`/`deserialize` in `dist/sqlpipe.cpp`. Changeset blobs within messages
use a compression framing: `[u32 len][u8 type][data...]` where type `0x00` =
uncompressed, `0x01` = LZ4. Blobs < 64 bytes are stored uncompressed.

### Diff sync protocol

```
Replica                              Master
   |                                    |
   |-- HelloMsg(sv) ------------------>|
   |<-- HelloMsg(sv) -----------------|  schema mismatch → ErrorMsg
   |                                    |
   |-- BucketHashesMsg -------------->|
   |                                    |  compare bucket hashes
   |<-- NeedBucketsMsg (ranges) ------|  (empty if all match)
   |                                    |
   |-- RowHashesMsg ----------------->|  (skipped if NeedBuckets empty)
   |                                    |
   |<-- DiffReadyMsg(seq, patchset,  |
   |      deletes per table) ---------|
   |-- AckMsg ----------------------->|
   |                                    |
   |         [LIVE STREAMING]           |
```

## File layout

```
dist/sqlpipe.h      Public header (types, messages, Master, Replica, Peer)
dist/sqlpipe.cpp    Implementation (all internals)
tests/              doctest test files
examples/           loopback.cpp demo
vendor/             Third-party dependencies
mkfile              Build system (mk)
```

## Tests

Test cases across 7 files (all use doctest):

- `test_protocol.cpp` — Serialization round-trips for all message types
  including PeerMessage, diff protocol messages, and LZ4 compression paths
- `test_master.cpp` — Master state, flush behaviour, handshake state machine
- `test_replica.cpp` — Replica state transitions, subscribe/unsubscribe
- `test_integration.cpp` — End-to-end: live streaming, diff sync, multi-table,
  query subscriptions (fires/no-fire/JOIN/unsubscribe)
- `test_diff_sync.cpp` — Schema mismatch, populated/empty sync, overlap,
  already-in-sync, diff-then-live
- `test_peer.cpp` — Peer handshake, ownership negotiation, bidirectional
  streaming, diff sync after reconnect

Add new tests to the file matching the component under test.

## Conventions

- Use `SPDLOG_INFO`/`SPDLOG_WARN`/`SPDLOG_ERROR` macros (not `spdlog::info`).
- All tables must have explicit PRIMARY KEYs (SQLite session extension
  requirement).
- Apache 2.0 license with SPDX headers on all source files.
