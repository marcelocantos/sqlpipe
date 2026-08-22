# sqlpipe

Streaming replication protocol for SQLite. Two-file C++ library:
`dist/sqlpipe.h` (public API) and `dist/sqlpipe.cpp` (implementation,
with sqlift + sqldeep bundled in). C++23. Apache 2.0.

Outgoing protocol methods return `OutMessage` (`msg` + `delivery` hint),
not bare `Message`. `serialize` / `handle_message` take the inner
`Message`. Do not copy snippets that treat `flush()` as `vector<Message>`.

## Build

```sh
cv test     # C++ doctest suite (tests/test_*.cpp) — shipped C++ gate
cv wasm     # Wasm module (requires emscripten)
cv clean    # remove build/
cv fuzz     # libFuzzer harness (tests/fuzz_deserialize.cpp); not in CI
```

Build system is [cv](https://github.com/marcelocantos/cv) (`cvfile`).
Requires C++23. SQLite is compiled with `-DSQLITE_ENABLE_SESSION
-DSQLITE_ENABLE_PREUPDATE_HOOK` (set in the cvfile).

`cv example` (`examples/loopback.cpp`) does **not** compile: `flush()`
returns `std::vector<OutMessage>` and the example still takes
`vector<Message>`. CI does not run it. Use `tests/test_integration.cpp`
for a working in-process loop.

`compile_flags.txt` is stale (`-std=c++20`, a non-existent spdlog
include). Follow `cvfile`, not that file.

Logging is `SQLPIPE_LOG` → `LogCallback`. There is no spdlog submodule.

### Go wrapper

```sh
cd go/sqlpipe
GOWORK=off go test ./...
```

Self-contained CGo module: vendored SQLite with session/preupdate flags.
Sources live in `go/sqlpipe/internal/c/` so `go get` works standalone.
Go also has its own `Serialize`/`Deserialize` (a second live wire codec).

When `dist/sqlpipe.h`, `dist/sqlpipe.cpp`, or vendored dependencies
change, run `scripts/bundle-deps.sh` to regenerate the bundled dist and
copy into Go/Swift. That script is **not** a CI lockstep check.

sqlite3 / lz4 / nlohmann/json are **not** copied by the bundler — copy
those by hand if they change:

```sh
cp vendor/src/sqlite3.c go/sqlpipe/internal/c/
cp vendor/src/lz4.c go/sqlpipe/internal/c/
cp vendor/include/{sqlite3.h,lz4.h} go/sqlpipe/internal/c/
cp vendor/include/nlohmann/json.hpp go/sqlpipe/internal/c/nlohmann/
```

Swift (`swift/Sources/CSqlpipe/`):

```sh
cp vendor/src/{sqlite3.c,lz4.c} swift/Sources/CSqlpipe/
cp vendor/include/{sqlite3.h,lz4.h} swift/Sources/CSqlpipe/include/
cp vendor/include/nlohmann/json.hpp swift/Sources/CSqlpipe/include/nlohmann/
cp go/sqlpipe/sqlpipe_capi.{h,cpp} swift/Sources/CSqlpipe/ && cp go/sqlpipe/sqlpipe_capi.h swift/Sources/CSqlpipe/include/
```

`sqlpipe_capi.cpp` in Swift uses `#include "include/..."` (Go uses
`#include "internal/c/..."`). `Package.swift` `publicHeadersPath` is
`include/`; the extra root `swift/Sources/CSqlpipe/sqlpipe_capi.h` is
unused. `sqlift.cpp` / `sqldeep.cpp` under Swift are excluded leftovers
(already bundled into `sqlpipe.cpp`).

### Swift wrapper

```sh
cd swift && swift build
```

SPM package: `CSqlpipe` (C/C++) + `Sqlpipe` (Swift). `SyncPeer` is
bidirectional sync; `TruthReplica` is the prediction-capable replica.
CI runs `swift build` only — no in-package test target.

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

Required for `go get github.com/marcelocantos/sqlpipe/go/sqlpipe@v<VERSION>`
(subdirectory modules need path-prefixed tags). Releases go through the
`/release` skill; do not hand-roll.

### Wasm (browser)

```sh
cv wasm
cd web && npx tsc && node dist/test/smoke.test.js
```

**Reduced surface:** no prediction API; HandleResult encoding is
`[u32 count][serialized msg]…` with no delivery byte (unlike the Go
C-API). Smoke covers handshake + live insert + QueryWatch.

deepparser is linked from the `vendor/github.com/marcelocantos/deepparser`
submodule (not from a sibling `../sqldeep` path). The unused `sqldeep = ../sqldeep`
line in `cvfile` is leftover.

## Dependencies

- **SQLite3** — `vendor/src/sqlite3.c` + `vendor/include/sqlite3.h`
- **LZ4** — `vendor/src/lz4.c` + `vendor/include/lz4.h`
- **sqlift** — submodule `vendor/github.com/marcelocantos/sqlift` (bundled into dist)
- **sqldeep** — submodule `vendor/github.com/marcelocantos/sqldeep` (bundled into dist)
- **deepparser** — submodule `vendor/github.com/marcelocantos/deepparser` (linked, not bundled)
- **doctest** — `vendor/include/doctest.h` (test only)
- **nlohmann/json** — `vendor/include/nlohmann/json.hpp`

No spdlog.

## Architecture

### Protocol

**Unidirectional** (Master/Replica): message-in / message-out; callers
provide the transport.

**Bidirectional** (Peer): Master + Replica behind a symmetric API. Each
side owns a disjoint set of tables. `PeerMessage` wraps `Message` with
`SenderRole` (`AsMaster`/`AsReplica`). Wire:
`[4B LE length][1B sender_role][1B tag][payload]`.

**Relay**: Master + Replica + sinks on one `sqlite3*` for chain
replication. C++ only (no C ABI).

Preferred sync path is **convergence** (`Replica::converge()`), not
hello-handshake. Handshake (`hello()` / `sync_handshake`) remains for
ordered reliable channels and in-process tests.

1. **Live streaming** — `flush()` after each write txn → `ChangesetMsg`.
2. **Diff / converge** — bucketed row hashes, then `DiffReadyMsg`
   (INSERT patchset + per-table delete rowids). `converge()` needs no
   prior `HelloMsg`.

### Key internals

- **Schema fingerprinting** (`compute_schema_fingerprint`): sqlift
  structural schema, full SHA-256 as `SchemaVersion` =
  `[algorithm-id byte][32-byte digest]` (opaque; not a 32-bit fold —
  that fold was removed in v0.26.0). Protocol version 7.
- **Session extension**: `sqlite3session_*` / `sqlite3changeset_apply`.
- **Pimpl**: `Master`, `Replica`, `Peer`, `Relay`, `Database`,
  `QueryWatch` hide `Impl`. The public header is **not**
  dependency-free: it includes `sqlite3.h` and the STL.
- **Internal tables**: `_sqlpipe_meta` (seq). Peer uses `master_seq` /
  `replica_seq`.
- **Table filtering**: `nullopt` = all, empty set = none.
- **Row / bucket hashing**: 64-bit FNV-1a; buckets default 1024 rowids;
  bucket hash = XOR of `fnv1a(rowid || row_hash)`.
- **Primary key**: every tracked table must have a single
  `INTEGER PRIMARY KEY` (rowid alias). Other PK shapes →
  `ErrorCode::WithoutRowidTable`.
- **Query subscriptions**: `Replica::subscribe(sql)` returns
  `SubscriptionId` and does **not** evaluate. Results arrive on
  `HandleResult::subscriptions`. `Database::subscribe` is different:
  RAII `Subscription` + immediate callback. Shared engine is
  `QueryWatch`.
- **Prediction**: Replica-only SAVEPOINT sandbox
  (`begin_prediction` / `commit_prediction` / `end_prediction`).
  Not on Wasm.
- **`sync_handshake`**: in-process convenience for tests/examples.
  Prefer documenting `converge()` for new transport wiring.
- **Logging**: `on_log` `LogCallback`; `SQLPIPE_LOG` internally.

### Wire format

`[4-byte LE length][1-byte tag][payload...]`. Changeset blobs:
`[u32 len][u8 type][data...]` (`0x00` uncompressed, `0x01` LZ4).
Blobs < 64 bytes uncompressed.

### Diff / converge

```
Replica                              Master
   |                                    |
   |-- BucketHashesMsg --------------->|  converge(); no Hello required
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

Legacy hello-handshake still exists (HelloMsg first) for ordered
reliable channels.

## File layout

```
dist/sqlpipe.h                 Public C++ API
dist/sqlpipe.cpp               Implementation (sqlift + sqldeep bundled)
dist/sqlpipe-agents-guide.md   Condensed C++ consumer / agent API
tests/                         doctest files + fuzz_deserialize.cpp
examples/loopback.cpp          Stale vs OutMessage; not in CI
vendor/                        sqlite3, lz4, json, doctest, submodules
go/sqlpipe/                    Go CGo wrapper + C-API
swift/                         SPM: CSqlpipe + Sqlpipe
web/                           Wasm/TS (reduced surface)
  sqlpipe_wapi.cpp             Emscripten shim
  sqldeep_wapi.cpp             sqldeep transpiler shim
  src/                         TypeScript wrapper
formal/Convergence.tla         Abstract convergence model (not in CI)
cvfile                         Build system
```

## Tests

`cv test` compiles `tests/doctest_main.cpp` + `tests/test_*.cpp`.
Add new tests to the file matching the component:

- `test_database.cpp` — Database: open/exec/query, migration,
  subscriptions, sqldeep, Master/Replica + `notify()`
- `test_protocol.cpp` — serialize round-trips, PeerMessage, LZ4, size caps
- `test_master.cpp` — Master state, flush, on_flush, changeset queue
- `test_replica.cpp` — Replica states, subscribe/unsubscribe
- `test_integration.cpp` — live streaming, diff, subscriptions, Relay chain
- `test_diff_sync.cpp` — schema mismatch, overlap, converge()
- `test_peer.cpp` — ownership, bidirectional, reconnect, globs
- `test_prediction_queue.cpp` — prediction hold/drain/reset
- `test_query_watch.cpp` — standalone QueryWatch
- `test_bench.cpp` — large-row diff timing (still doctest)
- `test_stress.cpp` — random live / diff / peer
- `fuzz_deserialize.cpp` — libFuzzer; `cv fuzz`; not in default `cv test`

Do not cite a frozen case count in docs; read `cv test` output.

CI (`.github/workflows/ci.yml`): `cv test` (ubuntu+macos), `go test`,
`swift build`, `cv wasm` + TS smoke. Not: example, fuzz, TLC, Swift tests,
wrapper-copy lockstep.

## Conventions

- Log with `SQLPIPE_LOG` / `LogCallback`, not spdlog macros.
- Tracked tables: single `INTEGER PRIMARY KEY` rowid alias.
- Apache 2.0 with SPDX headers on source files.
- Agent-facing C++ API: `dist/sqlpipe-agents-guide.md`.
- Stability catalogue: `STABILITY.md` (must match `dist/sqlpipe.h`).
