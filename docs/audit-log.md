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

## 2026-03-30 — /release v0.15.0

- **Commit**: `5e25bd8`
- **Outcome**: Released v0.15.0. Transport delivery hints (OutMessage/PeerOutMessage), changeset queue for fast reconnect replay, predicate-aware subscription invalidation via relational algebra and bytecode VM, liteparser integration, column relevance tracking, SQL three-valued NULL semantics. STABILITY.md updated, NOTICES updated for liteparser.

## 2026-03-30 — /release v0.16.0

- **Commit**: (pending)
- **Outcome**: Released v0.16.0. Convergence loop (stateless diff sync without handshake), transport adapter (Go), TLA+ formal verification, BucketHashesMsg with protocol/schema/seq fields, Go wrapper Replica.Converge(), end-to-end tern relay test, liteparser compiled in Go build.

## 2026-03-30 — /release v0.17.0

- **Commit**: (pending)
- **Outcome**: Released v0.17.0. Removed Delivery/OutMessage/PeerOutMessage — all methods return Message/PeerMessage directly. Protocol is fully datagram-safe via convergence loop; delivery hints were redundant. README updated, licence badge removed.

## 2026-04-02 — /release v0.18.0

- **Commit**: `0c7552d`
- **Outcome**: Released v0.18.0. Glob patterns for PeerConfig::owned_tables (use `"*"` to own all user tables). STABILITY.md updated to current surface — all items now Stable. README Mermaid diagrams.

## 2026-04-04 — /release v0.19.0

- **Commit**: `facd91d`
- **Outcome**: Released v0.19.0. Unified Database class with auto-migrating schema (sqlift), auto-transpiling queries (sqldeep), and RAII subscriptions. Single dist pair bundles sqlpipe + sqlift + sqldeep. Web demo with live subscriptions. Docs updated.

## 2026-04-05 — /release v0.20.0

- **Commit**: `a75ab05`
- **Outcome**: Released v0.20.0. sqldeep 0.12.0 bundled with XML literal support — SQL queries produce HTML/JSONML directly via xml_element/xml_attrs/xml_agg functions. Dual output modes (HTML strings and JSONML for React component trees). XML functions auto-registered on Database handle.

## 2026-04-07 — /release v0.21.0

- **Commit**: `b995c49`
- **Outcome**: Released v0.21.0. Diff sync performance benchmark suite (🎯T12) — 6 scenarios covering 10k–1M rows, continuous writes during handshake, and reconnect after disconnect. All pass well under acceptance criteria. Submodule vendoring for sqldeep/sqlift.
