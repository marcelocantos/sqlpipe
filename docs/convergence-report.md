# Convergence report

Evaluated: 2026-07-11 (ownership pass — reconcile graph with shipped product).

## Standing invariants

Local `cv test`: **165 cases, 739 assertions, all pass.**  
CI master: last run success (2026-07-06, Swift deepparser vendoring #20).

## Movement this pass

- **Retired 🎯T11** and nearly all children — unified Database + sqlift + sqldeep shipped long ago; graph was ~99 days stale.
- **Set aside 🎯T11.4** (+ children) — internal connection registry rejected; transport stays caller-owned.
- **Retired 🎯T3** (Wasm/TS path); **set aside 🎯T3.4** (npm publish deferred to deliberate 1.0-era decision).
- **Retired 🎯T12** — bench suite + `docs/bench-diff-sync.md` baselines; SLOs met with large margin.
- **Refreshed 🎯T2** context — last break v0.26.0 (2026-07-06); 1.0 eligible **2026-10-06**.
- **Restored value/cost** on 🎯T13 / 🎯T14 (were 0/0 and invisible to portfolio ranking).

## Active frontier

| Target | Status | Note |
|---|---|---|
| 🎯T13 Go: FTS5 + sqlift + sqldeep Database API | actionable | Unblocks mnemo 🎯T26 |
| 🎯T14 bundle-deps syncs sqlift API block in headers | actionable | Hygiene; small |
| 🎯T10 sqlpipe over tern dual-channel | actionable | Strategic; depends on tern |
| 🎯T2 reaches 1.0 | time-gated | Eligible 2026-10-06 |

## Recommendation

Work on: **🎯T13** (Go wrapper parity with C++ Database features).  
Reason: only high-value unblocked work that unblocks another product (mnemo). 🎯T14 can ride the same PR if cheap. 🎯T2 cannot be forced. 🎯T10 is a multi-repo integration.

## Delivery

Project delivery: merged to master (default).
