# Audit Log

Chronological record of audits, releases, documentation passes, and other
maintenance activities. Append-only — newest entries at the bottom.

## 2026-02-22 — initial-commit (reconstructed)

- **Commit**: `8848517`
- **Outcome**: Initial commit creating sqlpipe, a C++ streaming replication library for SQLite. Core Replica and single-direction replication established.

## 2026-02-22 — documentation-pass (reconstructed)

- **Commit**: `64e2213`
- **Outcome**: Added API docs, inline comments, and CLAUDE.md. Followed by complete API listings, resync diagram, and error handling docs (`0199006`), plus agents-guide.md for agentic coding tools (`2b618e0`). All on the same day.

## 2026-02-22 — ci-setup (reconstructed)

- **Commit**: `2d08b2d`
- **Outcome**: Added GitHub Actions CI workflow for build and test. Build system also migrated from Makefile to mkfile the same day (`f277a5c`).

## 2026-02-23 — release/v0.1.0 (reconstructed)

- **Commit**: `51f2484`
- **Outcome**: Tagged v0.1.0 at the bidirectional replication via Peer class commit. Core feature: Peer class enabling two-way replication between SQLite databases.

## 2026-02-23 — release/v0.2.0 (reconstructed)

- **Commit**: `2b8be6a`
- **Outcome**: Tagged v0.2.0 at hash-exchange diff sync protocol commit. Replaced journal/resync approach with a more efficient hash-exchange protocol.

## 2026-02-23 — release/v0.3.0 (reconstructed)

- **Commit**: `143f169`
- **Outcome**: Tagged v0.3.0 at query subscriptions commit. Added result-change detection so subscribers are only notified when query results actually change.

## 2026-02-25 — release/v0.4.0 (reconstructed)

- **Commit**: `b0a910c`
- **Outcome**: Tagged v0.4.0. Added table_filter on Peer, progress callbacks, fuzz/stress tests, and version macros.

## 2026-02-25 — release/v0.5.0 (reconstructed)

- **Commit**: `3a25c79`
- **Outcome**: Tagged v0.5.0. Added schema migration hooks, batched messages, size limits, and STABILITY.md tracking pre-1.0 surface stability.

## 2026-02-27 — release/v0.6.0 (reconstructed)

- **Commit**: `dd51d28`
- **Outcome**: Tagged v0.6.0 (via bump commit). Includes schema mismatch callback redesign, settling period principle added to STABILITY.md, and various stability fixes from PR #1.

## 2026-03-04 — /release v0.7.0

- **Commit**: `c98b843`
- **Outcome**: Released v0.7.0. Protocol v5 (sqlift structural schema hashing), callback logging replacing spdlog, Go CGo wrapper, dist/ layout, sync_handshake API. NOTICES updated with doctest and sqlift attribution.

## 2026-03-15 — /release v0.8.0

- **Commit**: `ab2cfee`
- **Outcome**: Released v0.8.0. Emscripten/Wasm build with TypeScript wrapper, Peer subscribe/unsubscribe, database serialize/deserialize, sqldeep bundled in Wasm, web demo app.

## 2026-03-15 — /release v0.9.0

- **Commit**: `53cf4b1`
- **Outcome**: Released v0.9.0. Automatic schema migration via sqlift, one-shot query() API, sqlift borrowing constructor.

## 2026-03-15 — /release v0.10.0

- **Commit**: `5eebeeb`
- **Outcome**: Released v0.10.0. FlushCallback auto-flush, Master::exec.

## 2026-03-16 — /release v0.11.0

- **Commit**: `9f09b0e`
- **Outcome**: Released v0.11.0. Self-contained Go wrapper (dropped mattn/go-sqlite3), Database type with params/transactions/iter.Seq, Peer.Subscribe/Unsubscribe in Go.

## 2026-03-21 — /release v0.12.0

- **Commit**: `3d24e09`
- **Outcome**: Released v0.12.0. Breaking: subscribe() returns SubscriptionId. Fix subscriptions not firing after diff sync. Defer eval until Live. Settling clock reset.

## 2026-03-21 — /release v0.13.0

- **Commit**: `dfcc5aa`
- **Outcome**: Released v0.13.0. Swift SPM package with SyncPeer wrapper.

## 2026-03-22 — /release v0.14.0

- **Commit**: `b7f1b08`
- **Outcome**: Released v0.14.0. Protocol v6 (fast reconnect), explicit PeerRole, prediction API, seq continuity check, Relay class, fan-out and chain replication tests.
