# sqlpipe

Streaming replication protocol for SQLite. Two-file library: `sqlpipe.h`
(public API) and `sqlpipe.cpp` (implementation).

## Build

```sh
make test     # build and run all tests (28 cases)
make example  # build and run examples/loopback.cpp
make clean    # remove build/
```

Requires C++20. Never pass `-j` to make; `MAKEFLAGS` handles parallelism.

SQLite must be compiled with `-DSQLITE_ENABLE_SESSION
-DSQLITE_ENABLE_PREUPDATE_HOOK` (the Makefile sets these).

## Dependencies

- **SQLite3** — vendored in `vendor/src/sqlite3.c` + `vendor/include/sqlite3.h`
- **spdlog** — git submodule at `vendor/github.com/gabime/spdlog` (header-only)
- **doctest** — vendored in `vendor/include/doctest.h` (test only)

## Architecture

### Protocol

Master-replica replication over an abstract message transport. The library is
message-in / message-out; callers provide the transport.

Three modes:
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
- **Pimpl**: Both `Master` and `Replica` use `struct Impl` behind
  `std::unique_ptr` to keep the header dependency-free.
- **Internal tables**: `_sqlpipe_meta` (key-value, stores seq) and
  `_sqlpipe_log` (seq + changeset blob, master only). Excluded from tracking.

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
Makefile            Build system
```

## Tests

28 test cases across 5 files (all use doctest):

- `test_protocol.cpp` — Serialization round-trips for all 9 message types
- `test_master.cpp` — Master state, flush behaviour, hello/catchup handling
- `test_replica.cpp` — Replica state transitions
- `test_integration.cpp` — End-to-end: live streaming, catchup, multi-table
- `test_resync.cpp` — Schema mismatch, log pruning, resync change events

Add new tests to the file matching the component under test.

## Conventions

- Use `SPDLOG_INFO`/`SPDLOG_WARN`/`SPDLOG_ERROR` macros (not `spdlog::info`).
- All tables must have explicit PRIMARY KEYs (SQLite session extension
  requirement).
- Apache 2.0 license with SPDX headers on all source files.
