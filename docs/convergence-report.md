## Standing invariants: all green.

CI last run: success (v0.20.0, 2026-04-05). No open PRs.

## Movement

- 🎯T2: (unchanged — still time-gated, eligible 2026-06-30; updated stale acceptance criteria to reference v0.17.0)
- 🎯T12: (new target — diff sync performance benchmarking)
- Others: (unchanged)

## Gap report

### 🎯T10 sqlpipe replicates over tern with dual-channel transport  [weight 1.6]
Gap: not started
Depends on tern's Conn API. No integration code exists yet.

### 🎯T12 Diff sync performance is characterised and acceptable at scale  [weight 2.7]
Gap: not started
No benchmark suite exists. No performance characterisation has been done. The target was discovered during an SRE dashboard demo where diff sync stalled under continuous writes.

### 🎯T2 sqlpipe reaches 1.0  [weight 4.3]
Gap: not started (time-gated)
The 3-month settling period from the last breaking change (v0.17.0, 2026-03-30) makes 1.0 eligible on 2026-06-30 — 84 days from now. STABILITY.md is up to date. "Fluid" items (Database, Subscription, SubscriptionCallback, generate_migration, sqldeep XML functions) may trigger further breaking changes before then, which would reset the clock. No action possible until settling completes.

### 🎯T11 Unified database product combining sqlpipe, sqlift, and sqldeep  [weight 1.0]  (status only)
Status: identified
Gap: not started (0/6 sub-targets achieved)

  [ ] 🎯T11.5 Unified query subscriptions on both replication ends — identified
  [ ] 🎯T11.4 Dynamic ad hoc replication hookup — identified
  [ ] 🎯T11.1 sqlift schema diffing integrated into sqlpipe core — identified
  [ ] 🎯T11.2 sqldeep query transpilation integrated into sqlpipe core — identified
  [ ] 🎯T11.3 High-level database access API added — identified
  [ ] 🎯T11.6 End-to-end integration tests and backward compatibility — identified

### 🎯T3 sqlpipe runs in the browser via Emscripten + JS wrapper  [weight 0.6]
Gap: converging (3/4 sub-targets achieved)

  [x] 🎯T3.1 C++ compiles to Wasm via Emscripten — achieved
  [x] 🎯T3.2 extern "C" API shim for JS binding — achieved
  [x] 🎯T3.3 TypeScript wrapper — achieved
  [ ] 🎯T3.4 npm package published — identified

### Achieved targets (no action needed)

🎯T5, 🎯T9, 🎯T6, 🎯T8, 🎯T4, 🎯T7, 🎯T1 — all achieved.

## Recommendation

Work on: **🎯T12 Diff sync performance is characterised and acceptable at scale**
Reason: Highest effective weight (2.7) among unachieved, unblocked, actionable targets. 🎯T2 has higher weight (4.3) but is purely time-gated with no work possible until 2026-06-30. 🎯T12 directly addresses a real-world issue discovered in the SRE dashboard demo and the results will inform whether protocol changes are needed before 1.0 (which would reset the settling clock anyway).

## Suggested action

Create a `tests/test_bench.cpp` benchmark file using doctest (consistent with existing test infrastructure). Start with the "10k rows, no differences" baseline: create a master and replica with 10k rows already in sync, then measure the wall-clock time for a full diff sync round-trip. Use `std::chrono::steady_clock` for timing. The acceptance criterion is under 1 second — this establishes whether the current bucket hashing protocol meets the bar before testing the harder scenarios (continuous writes during sync).

<!-- convergence-deps
evaluated: 2026-04-07T00:00:00Z
sha: 03775ef

🎯T2:
  gap: not started
  assessment: "Time-gated — eligible 2026-06-30 (84 days). Last breaking change v0.17.0 (2026-03-30). Fluid items may reset clock."
  read:
    - STABILITY.md

🎯T12:
  gap: not started
  assessment: "No benchmark suite exists. Discovered from SRE dashboard stall under continuous writes."
  read: []

🎯T10:
  gap: not started
  assessment: "No integration code exists. Depends on external tern project."
  read: []

🎯T5:
  gap: achieved
  assessment: "All acceptance criteria met."
  read: []

🎯T9:
  gap: achieved
  assessment: "All acceptance criteria met."
  read: []

🎯T6:
  gap: achieved
  assessment: "All acceptance criteria met."
  read: []

🎯T8:
  gap: achieved
  assessment: "All acceptance criteria met."
  read: []

🎯T4:
  gap: achieved
  assessment: "All acceptance criteria met."
  read: []

🎯T7:
  gap: achieved
  assessment: "All acceptance criteria met."
  read: []

🎯T1:
  gap: achieved
  assessment: "All acceptance criteria met."
  read: []
-->
