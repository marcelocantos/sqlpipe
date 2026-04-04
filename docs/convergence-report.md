## Standing invariants: all green.

## Gap report

### 🎯T5 Peer exposes subscribe/unsubscribe from its internal Replica [high]
Gap: achieved
All acceptance criteria met — Peer subscriptions delegate to internal Replica.

### 🎯T9 Stress test SIGSEGV in test_stress.cpp:242 is fixed [high]
Gap: achieved
All acceptance criteria met — root cause identified and fixed.

### 🎯T2 sqlpipe reaches 1.0 [high]
Gap: not started
The settling period of 3 months since last breaking change (v0.17.0 on 2026-03-30) ends on 2026-06-30. As of 2026-04-03, 1.0 cannot yet be released.

### 🎯T6 Go wrapper is self-contained (no mattn/go-sqlite3 dependency) [medium] (status only)
Status: achieved
Changed files overlap: docs/targets.md — may be affected

### 🎯T8 Prediction API for optimistic local updates [medium] (status only)
Status: achieved
Changed files overlap: docs/targets.md — may be affected

### 🎯T4 Reconnect skips diff sync when seq matches [medium] (status only)
Status: achieved
Changed files overlap: docs/targets.md — may be affected

### 🎯T10 sqlpipe replicates over tern with dual-channel transport [medium] (status only)
Status: identified
Changed files overlap: docs/targets.md — may be affected

### 🎯T7 Peer role is explicit rather than inferred from callback presence [low] (status only)
Status: achieved
Changed files overlap: docs/targets.md — may be affected

### 🎯T1 Go CGo wrapper is complete and tested [low] (status only)
Status: achieved
Changed files overlap: docs/targets.md — may be affected

### 🎯T11 Unified database product combining sqlpipe, sqlift, and sqldeep [low] (status only)
Status: identified
Changed files overlap: docs/targets.md — may be affected

  🎯T11.5 Unified query subscriptions on both replication ends — identified
  🎯T11.4 Dynamic ad hoc replication hookup — identified
  🎯T11.1 sqlift schema diffing integrated into sqlpipe core — identified
  🎯T11.2 sqldeep query transpilation integrated into sqlpipe core — identified
  🎯T11.3 High-level database access API added — identified
  🎯T11.6 End-to-end integration tests and backward compatibility — identified

### 🎯T3 sqlpipe runs in the browser via Emscripten + JS wrapper [low]
Gap: converging (3/4 sub-targets achieved)

  [check] 🎯T3.1 C++ compiles to Wasm via Emscripten — achieved
  [check] 🎯T3.2 extern "C" API shim for JS binding — achieved
  [check] 🎯T3.3 TypeScript wrapper — achieved
  [ ] 🎯T3.4 npm package published — identified

## Movement

- 🎯T11 (new target)
- Others (unchanged)

## Recommendation

Work on: **🎯T2 sqlpipe reaches 1.0**
Reason: Highest priority unachieved target — the settling clock is ticking toward 1.0 eligibility.
Suggested action: Monitor the settling period; when 2026-06-30 arrives, verify no breaking changes since v0.17.0, then tag v1.0.0 and publish GitHub release.

<!-- convergence-deps
evaluated: 2026-04-03T15:00:00Z
sha: eff507fdd6922c4df1a1f84f5c870328128023f7

🎯T5:
  gap: achieved
  assessment: "All acceptance criteria met — Peer subscriptions delegate to internal Replica."
  read:

🎯T9:
  gap: achieved
  assessment: "All acceptance criteria met — root cause identified and fixed."
  read:

🎯T2:
  gap: not started
  assessment: "The settling period of 3 months since last breaking change (v0.17.0 on 2026-03-30) ends on 2026-06-30. As of 2026-04-03, 1.0 cannot yet be released."
  read:
    - STABILITY.md
-->
</content>
<parameter name="filePath">docs/convergence-report.md