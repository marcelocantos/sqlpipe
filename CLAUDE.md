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
go test ./...
```

The Go wrapper is self-contained — it compiles vendored SQLite with the
required session/preupdate flags via CGo. No build tags or system SQLite
needed. Sources are copied into `go/sqlpipe/internal/c/` so the module
works standalone via `go get`.

When `dist/sqlpipe.h`, `dist/sqlpipe.cpp`, or vendored dependencies change,
re-copy them into `go/sqlpipe/internal/c/`:
```sh
cp dist/sqlpipe.{h,cpp} go/sqlpipe/internal/c/
cp vendor/src/{sqlite3.c,lz4.c,sqlift.cpp} go/sqlpipe/internal/c/
cp vendor/include/{sqlite3.h,lz4.h,sqlift.h} go/sqlpipe/internal/c/
cp vendor/include/nlohmann/json.hpp go/sqlpipe/internal/c/nlohmann/
```

Also update the Swift package (`swift/Sources/CSqlpipe/`):
```sh
cp dist/sqlpipe.{h,cpp} swift/Sources/CSqlpipe/ && cp dist/sqlpipe.h swift/Sources/CSqlpipe/include/
cp vendor/src/{sqlite3.c,lz4.c,sqlift.cpp} swift/Sources/CSqlpipe/
cp vendor/include/{sqlite3.h,lz4.h,sqlift.h} swift/Sources/CSqlpipe/include/
cp vendor/include/nlohmann/json.hpp swift/Sources/CSqlpipe/include/nlohmann/
cp go/sqlpipe/sqlpipe_capi.{h,cpp} swift/Sources/CSqlpipe/ && cp go/sqlpipe/sqlpipe_capi.h swift/Sources/CSqlpipe/include/
```
Note: `sqlpipe_capi.cpp` in the Swift package uses `#include "include/..."` paths
(different from the Go copy which uses `#include "internal/c/..."`).

### Swift wrapper

```sh
cd swift && swift build                    # build SPM package
```

The Swift package (`swift/`) provides `SyncPeer` — a bidirectional sync
wrapper with binary decoding, sqldeep transpilation, and query support.
SPM package with two targets: `CSqlpipe` (C/C++ sources) and `Sqlpipe`
(Swift wrapper).

### Version strings

When bumping the version, update all of these:

1. `dist/sqlpipe.h` — `SQLPIPE_VERSION` + `_MAJOR`/`_MINOR`/`_PATCH`
2. `go/sqlpipe/types.go` — `Version` + `VersionMajor`/`VersionMinor`/`VersionPatch`
3. `web/package.json` — `"version"`
4. `STABILITY.md` — snapshot line + version macro table

After tagging the release, also create the Go module subdirectory tag:
```sh
git tag go/sqlpipe/v<VERSION> v<VERSION>
git push origin go/sqlpipe/v<VERSION>
```
This is required for `go get github.com/marcelocantos/sqlpipe/go/sqlpipe@v<VERSION>`
to resolve correctly (Go modules in subdirectories need path-prefixed tags).

### Wasm (browser)

```sh
mk wasm                              # build Wasm module (requires emscripten)
cd web && npx tsc && node dist/test/smoke.test.js  # TypeScript wrapper test
```

Builds sqlpipe + sqldeep + SQLite + LZ4 + sqlift into a single Wasm module.
The `sqldeep` variable in the mkfile defaults to `../sqldeep` (sibling directory).

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
go/sqlpipe/         Go CGo wrapper
web/                Wasm/TypeScript wrapper
  sqlpipe_wapi.cpp  Emscripten C API shim (Master, Replica, Peer, QueryWatch)
  sqldeep_wapi.cpp  Emscripten wrapper for sqldeep transpiler
  src/              TypeScript wrapper source
    index.ts        Public API (createSqlpipe, Database, Master, Replica, Peer, QueryWatch)
    types.ts        Type definitions
    decode.ts       Binary result decoder
    wasm.ts         Low-level Wasm bindings
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
