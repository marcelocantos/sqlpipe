# Targets

<!-- last-evaluated: eff507fdd6922c4df1a1f84f5c870328128023f7 -->

## Active

### 🎯T1 Go CGo wrapper is complete and tested
- **Weight**: 1 (value 8 / cost 8)
- **Estimated-cost**: 8
- **Acceptance**:
  - `go test ./...` passes (no build tags) with coverage of Master, Replica, Peer, and QueryWatch APIs
  - All callback types (log, progress, schema mismatch, table filter, flush) work through CGo trampolines
  - Integration tests demonstrate live streaming, diff sync, and peer bidirectional replication from Go
  - Wire-compatible with C++ (same protocol v5 messages cross the boundary)
- **Context**: Go is a major adoption vector for sqlpipe. The CGo wrapper lets Go consumers use sqlpipe without reimplementing the protocol.
- **Status**: achieved
- **Discovered**: 2026-03-12
- **Achieved**: 2026-03-15

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
- **Status**: converging (🎯T3.1, 🎯T3.2, 🎯T3.3 achieved; 🎯T3.4 remaining)
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
- **Achieved**: 2026-03-30
- **Discovered**: 2026-03-15

### 🎯T6 Go wrapper is self-contained (no mattn/go-sqlite3 dependency)
- **Weight**: 5 (value 8 / cost 2)
- **Estimated-cost**: 2
- **Acceptance**:
  - `go test ./...` works without build tags or system SQLite
  - Wrapper compiles vendored SQLite with session/preupdate flags internally
  - No dependency on mattn/go-sqlite3 in go.mod
  - No `database/sql`, `*sql.DB`, `*sql.Conn`, or `extractDBHandle` in the API
  - `Database.Query(sql)` returns rows for one-shot read queries (wraps prepare/step/column/finalize internally)
  - Public API surface: Database, Master, Replica, Peer, QueryWatch (mirrors the Wasm/TypeScript wrapper)
  - `go get github.com/marcelocantos/sqlpipe/go/sqlpipe` works from outside the monorepo
- **Context**: Users interact exclusively with the sqlpipe API, never with raw SQLite. The mattn dependency creates confusing build failures, requires `-tags libsqlite3`, and exposes implementation details. The Wasm wrapper already demonstrates the right pattern — own the sqlite3* handles internally.
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
- **Status**: achieved
- **Discovered**: 2026-03-14
- **Achieved**: 2026-03-22

### 🎯T7 Peer role is explicit rather than inferred from callback presence
- **Weight**: 2 (value 3 / cost 2)
- **Estimated-cost**: 2
- **Acceptance**:
  - PeerConfig has an explicit role field (e.g., `PeerRole::Client` / `PeerRole::Server`)
  - `approve_ownership` callback is only valid on Server peers
  - `start()` is only valid on Client peers (already enforced, but tied to role not callback)
  - Existing implicit behavior preserved as default for backwards compatibility during pre-1.0
- **Context**: Previously the server role was inferred from `approve_ownership` being set. Now explicit via `PeerRole::Server`. Breaking change.
- **Status**: achieved
- **Discovered**: 2026-03-15
- **Achieved**: 2026-03-22

### 🎯T8 Prediction API for optimistic local updates
- **Weight**: 3 (value 8 / cost 3)
- **Estimated-cost**: 3
- **Acceptance**:
  - `Replica::begin_prediction()` creates a SQLite SAVEPOINT
  - `Replica::commit_prediction()` marks prediction as sent (savepoint stays open)
  - `Replica::rollback_prediction()` cancels before sending
  - `Replica::handle_message()` auto-rollbacks committed predictions before applying server data
  - `Replica::reset()` rolls back active predictions
  - Tests: confirmed, rejected, cancelled, reset, double-begin error
- **Context**: Interactive apps need instant feedback. Predictions use SQLite savepoints — the server remains authoritative.
- **Status**: achieved
- **Discovered**: 2026-03-22
- **Achieved**: 2026-03-22

### 🎯T9 Stress test SIGSEGV in test_stress.cpp:242 is fixed
- **Weight**: 4 (value 5 / cost 1)
- **Estimated-cost**: 1
- **Acceptance**:
  - `mk test` reports 0 failures (no SIGSEGV in stress tests)
  - Root cause identified and documented in commit message
- **Context**: Stress test wasn't updated for the T7 PeerRole breaking change. Missing `role = PeerRole::Server` on server PeerConfig.
- **Status**: achieved
- **Discovered**: 2026-03-22
- **Achieved**: 2026-03-22

### 🎯T10 sqlpipe replicates over tern with dual-channel transport

- **Weight**: 5 (value 13 / cost 8)
- **Estimated-cost**: 8
- **Acceptance**:
  - Go integration layer connects sqlpipe's Go wrapper to tern's `Conn` API
  - `Delivery::Reliable` messages route to `tern.Conn.Send()` (QUIC stream)
  - `Delivery::BestEffort` messages route to `tern.Conn.SendDatagram()` (QUIC datagram)
  - Changeset queue provides fast reconnect over the reliable channel
  - Convergence loop runs over datagrams for loss-tolerant state sync
  - End-to-end test: two Go processes replicate through a tern relay
- **Context**: tern provides both reliable streams and unreliable datagrams over QUIC. sqlpipe's `OutMessage` delivery hints (shipped in v0.15.0) map directly to these channels. The convergence loop replaces the linear diff sync handshake with a continuous, loss-tolerant state comparison protocol — bucket hashes over datagrams, with the diff protocol regenerating on loss rather than requiring retransmission.
- **Status**: identified
- **Discovered**: 2026-03-30

### 🎯T11 Unified database product combining sqlpipe, sqlift, and sqldeep
- **Weight**: 1 (value 13 / cost 13)
- **Estimated-cost**: 13
- **Acceptance**:
  - Single library/binary exposes a unified API for database access (CRUD operations, queries), replication (ad hoc masters/replicas, bidirectional peers), schema diffing (via integrated sqlift), and query transpilation (via integrated sqldeep)
  - Query subscriptions work on both master and replica sides, firing on changes regardless of replication direction
  - API allows dynamic hookup of replicas/masters/peers without restart or reconfiguration
  - Integration tests demonstrate end-to-end workflows: create DB, add replicas, run queries with subscriptions, perform schema migrations via sqlift, transpile queries via sqldeep
  - Backward compatibility maintained for existing sqlpipe usage (no breaking changes to current API)
- **Context**: Unifying sqlpipe (replication), sqlift (structural schema diffs), and sqldeep (query transpilation) into one product provides users with a complete, easy-to-use database solution. Discovered during strategic planning — current separation forces users to integrate manually, limiting adoption.
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.1 sqlift schema diffing integrated into sqlpipe core
- **Weight**: 2 (value 8 / cost 5)
- **Estimated-cost**: 5
- **Acceptance**: sqlift functions (e.g., structural diff, migration generation) bundled in sqlpipe library; used for enhanced schema fingerprinting and migrations in replication; no external sqlift dependency for users.
- **Parent**: 🎯T11
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.2 sqldeep query transpilation integrated into sqlpipe core
- **Weight**: 1 (value 5 / cost 5)
- **Acceptance**: sqldeep transpile functions available in sqlpipe library; supports converting queries between dialects; bundled without external dependency.
- **Parent**: 🎯T11
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.3 High-level database access API added
- **Weight**: 1 (value 13 / cost 13)
- **Acceptance**: Unified API provides Database class with methods for executing queries, CRUD operations, and result handling; abstracts raw SQLite calls; works with replication underneath.
- **Parent**: 🎯T11
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.4 Dynamic ad hoc replication hookup
- **Weight**: 2 (value 13 / cost 8)
- **Acceptance**: API methods to connect/disconnect replicas/masters/peers at runtime; supports bidirectional peers; maintains replication state during topology changes.
- **Parent**: 🎯T11
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.5 Unified query subscriptions on both replication ends
- **Weight**: 3 (value 8 / cost 3)
- **Acceptance**: Query subscriptions work identically on master and replica sides; changes from either end trigger notifications; integrates with bidirectional peer sync.
- **Parent**: 🎯T11
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.6 End-to-end integration tests and backward compatibility
- **Weight**: 1 (value 8 / cost 8)
- **Acceptance**: Tests cover: DB creation, replication hookup, queries with subscriptions, schema migrations via sqlift, query transpilation via sqldeep; existing sqlpipe API unchanged; all tests pass.
- **Parent**: 🎯T11
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.1.1 Ensure sqlift submodule is linked in mkfile
- **Weight**: 1 (value 3 / cost 2)
- **Estimated-cost**: 2
- **Acceptance**: `mk test` compiles sqlift code
- **Parent**: 🎯T11.1
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.1.2 Add sqlift headers to dist/sqlpipe.h includes
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: no compile errors
- **Parent**: 🎯T11.1
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.1.3 Expose generate_migration API
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: `generate_migration(const std::string& old_sql, const std::string& new_sql)` method callable, returns diff SQL
- **Parent**: 🎯T11.1
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.1.4 Update compute_schema_fingerprint to use sqlift
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: fingerprint ignores comments/renames
- **Parent**: 🎯T11.1
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.1.5 Write unit test for migration generation
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: test passes with sample schemas
- **Parent**: 🎯T11.1
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.2.1 Link sqldeep submodule in mkfile
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: compiles
- **Parent**: 🎯T11.2
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.2.2 Add sqldeep headers to includes
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: no errors
- **Parent**: 🎯T11.2
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.2.3 Expose transpile API
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: `transpile(const std::string& query, Dialect from, Dialect to)` transposes queries
- **Parent**: 🎯T11.2
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.2.4 Write unit test for transpilation
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: test passes with SQL samples
- **Parent**: 🎯T11.2
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.3.1 Define Database class skeleton in header
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: class compiles, holds sqlite3* handle
- **Parent**: 🎯T11.3
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.3.2 Implement Database::query
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: executes SELECT, returns ResultSet
- **Parent**: 🎯T11.3
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.3.3 Implement Database::execute
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: runs INSERT/UPDATE
- **Parent**: 🎯T11.3
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.3.4 Add ResultSet class
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: iterable rows/columns
- **Parent**: 🎯T11.3
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.3.5 Implement Database::insert
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: inserts row
- **Parent**: 🎯T11.3
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.3.6 Implement Database::update
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: updates rows
- **Parent**: 🎯T11.3
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.3.7 Implement Database::delete_
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: deletes rows
- **Parent**: 🎯T11.3
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.3.8 Write unit tests for DB methods
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: all CRUD tests pass
- **Parent**: 🎯T11.3
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.4.1 Extend MasterConfig for runtime replica addition
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: new field for connections
- **Parent**: 🎯T11.4
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.4.2 Implement Master::add_replica
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: starts replication to new replica
- **Parent**: 🎯T11.4
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.4.3 Extend PeerConfig for ad hoc connections
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: supports dynamic peers
- **Parent**: 🎯T11.4
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.4.4 Implement Peer::connect
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: connects and syncs
- **Parent**: 🎯T11.4
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.4.5 Write integration test for dynamic hookup
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: adds replica/peer at runtime, syncs
- **Parent**: 🎯T11.4
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.5.1 Verify master subscriptions fire on local changes
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: test passes
- **Parent**: 🎯T11.5
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.5.2 Verify replica subscriptions fire on received changes
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: test passes
- **Parent**: 🎯T11.5
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.5.3 Test bidirectional peer subscriptions
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: changes from either end notify both
- **Parent**: 🎯T11.5
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.6.1 Write end-to-end test for DB creation + replication + subscriptions
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: test runs workflows
- **Parent**: 🎯T11.6
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.6.2 Write test for schema migrations via sqlift
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: migrates and syncs
- **Parent**: 🎯T11.6
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.6.3 Write test for query transpilation via sqldeep
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: transposes and executes
- **Parent**: 🎯T11.6
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.6.4 Compile-check backward compatibility
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: existing code builds unchanged
- **Parent**: 🎯T11.6
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T11.6.5 Run full test suite
- **Weight**: 1 (value 3 / cost 2)
- **Acceptance**: no regressions
- **Parent**: 🎯T11.6
- **Status**: identified
- **Discovered**: 2026-04-03

### 🎯T12 Diff sync performance is characterised and acceptable at scale
- **Weight**: 3 (value 8 / cost 3)
- **Estimated-cost**: 3
- **Acceptance**:
  - Benchmark suite covering diff sync with 1k, 10k, 100k, and 1M rows
  - Diff sync with 10k rows and no differences completes in under 1 second
  - Diff sync with 10k rows and continuous writes (1 write/500ms) converges within 5 seconds
  - Reconnect after accumulating 10k rows while disconnected completes diff sync without stalling
  - Results documented with baseline numbers for regression tracking
- **Context**: The SRE dashboard demo revealed that diff sync stalls when the dataset grows during a session (the server generates data continuously, and reconnecting a replica triggers a diff sync that may never converge if writes continue during the handshake). The bucket hashing protocol is designed for O(d+b) efficiency, but the interaction between ongoing writes and the multi-round-trip handshake needs validation. Flush-during-handshake may be the root cause.
- **Status**: identified
- **Discovered**: 2026-04-06

## Achieved
