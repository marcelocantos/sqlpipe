# sqlpipe

Streaming replication protocol for SQLite. Two-file library: `sqlpipe.h`
(public API) and `sqlpipe.cpp` (implementation).

## Build

```sh
mk test     # build and run all tests (43 cases)
mk example  # build and run examples/loopback.cpp
mk clean    # remove build/
```

Requires C++20. Uses [mk](https://github.com/marcelocantos/mk) as the build
system (`mkfile`).

SQLite must be compiled with `-DSQLITE_ENABLE_SESSION
-DSQLITE_ENABLE_PREUPDATE_HOOK` (the mkfile sets these).

## Dependencies

- **SQLite3** — vendored in `vendor/src/sqlite3.c` + `vendor/include/sqlite3.h`
- **spdlog** — git submodule at `vendor/github.com/gabime/spdlog` (header-only)
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

Three sync modes:
1. **Live streaming** — Master calls `flush()` after each write transaction;
   replica applies the resulting `ChangesetMsg`.
2. **Catchup** — Replica reconnects behind; master replays missed changesets
   from `_sqlpipe_log`.
3. **Full resync** — Schema mismatch or log gap; master sends a complete
   database snapshot via `ResyncBegin/ResyncTable/ResyncEnd`.

### Key internals

- **Schema fingerprinting** (`compute_schema_fingerprint`): FNV-1a hash of
  sorted CREATE TABLE SQL. Used instead of `PRAGMA schema_version` because the
  pragma changes on every DDL, even if the logical schema is unchanged.
- **Session extension**: `sqlite3session_create/attach/changeset` for change
  tracking. `sqlite3changeset_apply` on the replica side.
- **Pimpl**: `Master`, `Replica`, and `Peer` use `struct Impl` behind
  `std::unique_ptr` to keep the header dependency-free.
- **Internal tables**: `_sqlpipe_meta` (key-value, stores seq) and
  `_sqlpipe_log` (seq + changeset blob, master only). Excluded from tracking.
  In Peer mode, Master and Replica use separate meta keys (`master_seq` /
  `replica_seq`) to avoid collision.
- **Table filtering**: `MasterConfig::table_filter` and
  `ReplicaConfig::table_filter` (`std::optional<std::set<std::string>>`)
  restrict which tables are tracked. `nullopt` = all tables, empty set = none.
  `compute_schema_fingerprint`, `get_tracked_tables`, and `get_schema_sql`
  accept an optional `const std::set<std::string>* filter` parameter.

### Wire format

`[4-byte LE length][1-byte tag][payload...]` — see `MessageTag` enum and
`serialize`/`deserialize` in `sqlpipe.cpp`.

## File layout

```
sqlpipe.h           Public header (types, messages, Master, Replica)
sqlpipe.cpp         Implementation (all internals)
tests/              doctest test files
examples/           loopback.cpp demo
vendor/             Third-party dependencies
mkfile              Build system (mk)
```

## Tests

43 test cases across 6 files (all use doctest):

- `test_protocol.cpp` — Serialization round-trips for all message types
  including PeerMessage
- `test_master.cpp` — Master state, flush behaviour, hello/catchup handling
- `test_replica.cpp` — Replica state transitions
- `test_integration.cpp` — End-to-end: live streaming, catchup, multi-table
- `test_resync.cpp` — Schema mismatch, log pruning, resync change events
- `test_peer.cpp` — Peer handshake, ownership negotiation, bidirectional
  streaming, catchup after reconnect

Add new tests to the file matching the component under test.

## Conventions

- Use `SPDLOG_INFO`/`SPDLOG_WARN`/`SPDLOG_ERROR` macros (not `spdlog::info`).
- All tables must have explicit PRIMARY KEYs (SQLite session extension
  requirement).
- Apache 2.0 license with SPDX headers on all source files.
