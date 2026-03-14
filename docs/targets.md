# Targets

<!-- last-evaluated: e95a27f -->

## Active

### 🎯T1 Go CGo wrapper is complete and tested
- **Weight**: 1 (value 8 / cost 8)
- **Estimated-cost**: 8
- **Acceptance**:
  - `go test -tags libsqlite3 ./...` passes with coverage of Master, Replica, Peer, and QueryWatch APIs
  - All callback types (log, progress, schema mismatch, table filter) work through CGo trampolines
  - Integration tests demonstrate live streaming, diff sync, and peer bidirectional replication from Go
  - Wire-compatible with C++ (same protocol v5 messages cross the boundary)
- **Context**: Go is a major adoption vector for sqlpipe. The CGo wrapper lets Go consumers use sqlpipe without reimplementing the protocol. Foundation exists (~2200 lines, serialization tests pass) but needs full API coverage.
- **Status**: converging
- **Discovered**: 2026-03-12

### 🎯T2 sqlpipe reaches 1.0
- **Weight**: 4 (value 13 / cost 3)
- **Estimated-cost**: 3
- **Acceptance**:
  - 4 consecutive stable minor releases with no breaking wire/API changes, OR 4 months elapsed since v0.7.0 (2026-03-04)
  - All "must fix" items resolved (currently clear)
  - STABILITY.md documents the stability guarantee
  - v1.0.0 tag and GitHub release published
- **Context**: 1.0 signals production readiness and API stability. The settling threshold prevents premature commitment. Last breaking change was v0.7.0 (protocol v5, sqlift structural schema hashing, 2026-03-04).
- **Gates**: 🎯T1
- **Status**: identified
- **Discovered**: 2026-03-12

### 🎯T3 sqlpipe runs in the browser via Emscripten + JS wrapper
- **Weight**: 1 (value 8 / cost 13)
- **Estimated-cost**: 13
- **Acceptance**:
  - `dist/sqlpipe.cpp` + vendored SQLite + LZ4 + sqlift compile to Wasm via Emscripten
  - `extern "C"` API exposes Master, Replica, Peer, and QueryWatch to JS
  - TypeScript wrapper provides ergonomic API (Promises, EventTarget for subscriptions)
  - Messages cross as `Uint8Array` (wire-compatible with C++ and Go)
  - Integration test demonstrates live streaming replication between two in-browser instances
  - Published as npm package with bundled Wasm
- **Context**: Browser support opens web apps, collaborative editors, offline-first PWAs. The message-in/message-out architecture is naturally suited — JS just needs to handle transport (WebSocket, WebRTC, etc.).
- **Status**: converging (🎯T3.1 and 🎯T3.2 achieved, 🎯T3.3 remaining)
- **Discovered**: 2026-03-14

### 🎯T3.1 C++ compiles to Wasm via Emscripten
- **Weight**: 3 (value 8 / cost 3)
- **Estimated-cost**: 3
- **Acceptance**:
  - `emcc`/`em++` compiles sqlpipe.cpp + sqlite3.c + lz4.c + sqlift.cpp to a .wasm + .js module
  - Build integrated into mkfile as `mk wasm` target
- **Context**: Foundation for all browser work. No API shim yet — just prove compilation works.
- **Parent**: 🎯T3
- **Status**: achieved
- **Discovered**: 2026-03-14
- **Achieved**: 2026-03-14

### 🎯T3.2 extern "C" API shim for JS binding
- **Weight**: 2 (value 8 / cost 5)
- **Estimated-cost**: 5
- **Acceptance**:
  - `web/sqlpipe_wapi.cpp` provides opaque-handle C API for Master, Replica, Peer, QueryWatch
  - Callbacks use function pointer + int context pattern (Emscripten addFunction compatible)
  - Messages cross as raw byte buffers (serialized wire format)
  - sqldeep bundled via `web/sqldeep_wapi.cpp`
  - Compiles and links into the Wasm module
  - Node.js smoke test (`web/test_wasm.mjs`) verifies handshake, live streaming, QueryWatch, and sqldeep transpile
- **Context**: Bridge between C++ classes and JS. Similar pattern to the Go CGo shim.
- **Parent**: 🎯T3
- **Status**: achieved
- **Discovered**: 2026-03-14
- **Achieved**: 2026-03-14

### 🎯T3.3 TypeScript wrapper
- **Weight**: 1 (value 8 / cost 8)
- **Estimated-cost**: 8
- **Acceptance**:
  - TypeScript API wraps Wasm calls with ergonomic interface (classes for Database, Master, Replica, Peer, QueryWatch)
  - OPFS persistence support via serialize/deserialize + saveToOPFS/loadFromOPFS
  - sqldeep transpiler exposed as `sqlpipe.transpile(sql)`
  - Smoke test covers handshake, live streaming, QueryWatch, serialize/deserialize round-trip, and sqldeep
- **Context**: Makes sqlpipe usable by web developers without touching Wasm directly. OPFS provides load-time efficiency — replicas resume from cached state rather than full sync on every page load.
- **Parent**: 🎯T3
- **Status**: achieved
- **Discovered**: 2026-03-14
- **Achieved**: 2026-03-15

### 🎯T3.4 npm package published
- **Weight**: 1 (value 3 / cost 2)
- **Estimated-cost**: 2
- **Acceptance**:
  - npm package bundles .wasm + .js glue + TypeScript types
  - `npm install sqlpipe` works and provides typed imports
- **Context**: Deferred until ready to publish. The wrapper works from the repo in the meantime.
- **Parent**: 🎯T3
- **Status**: identified
- **Discovered**: 2026-03-15

### 🎯T5 Peer exposes subscribe/unsubscribe from its internal Replica
- **Weight**: 4 (value 5 / cost 1)
- **Estimated-cost**: 1
- **Acceptance**:
  - `Peer::subscribe(sql)` and `Peer::unsubscribe(id)` delegate to the internal Replica
  - `PeerHandleResult` includes a `subscriptions` field (populated from Replica's HandleResult)
  - Tests verify subscriptions fire through Peer after bidirectional sync
  - Go wrapper, Wasm C API, and TypeScript wrapper updated
- **Context**: Discovered by an agent using sqlpipe. Peer wraps Master+Replica but doesn't expose the Replica's subscription API, forcing users to manage a separate QueryWatch.
- **Status**: achieved
- **Discovered**: 2026-03-15
- **Achieved**: 2026-03-15

### 🎯T4 Reconnect skips diff sync when seq matches
- **Weight**: 3 (value 5 / cost 2)
- **Estimated-cost**: 2
- **Acceptance**:
  - HelloMsg carries `last_applied_seq` from the replica
  - Master compares replica seq to its own; if equal (and schema matches), transitions directly to Live without bucket hash exchange
  - Diff sync remains the fallback for seq mismatch
  - Protocol version bumped to v6
  - Test verifies fast-path reconnect (disconnect → reconnect → Live in one round-trip, no diff messages)
- **Context**: Common case is normal disconnect with near-instant reconnect. Currently triggers full diff sync (O(b) bucket hashes) even when nothing changed. Seq comparison makes this O(1).
- **Status**: identified
- **Discovered**: 2026-03-14

## Achieved
