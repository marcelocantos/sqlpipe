# Diff sync performance baselines

Oracle: `cv test` → `build/sqlpipe_tests --test-case='bench:*'`  
Hardware: developer workstation (local, not CI). Numbers vary by machine;
the **thresholds in `tests/test_bench.cpp`** are the regression contract.

## Baseline (2026-07-11)

| Scenario | Result | Threshold |
|---|---|---|
| 1k rows, already in sync | **2.2 ms** | < 1000 ms |
| 10k rows, already in sync | **10.4 ms** | < 1000 ms |
| 10k rows, 1% differences | **28.6 ms** | < 1000 ms |
| 100k rows, already in sync | **95.2 ms** | no hard bound (smoke) |
| 1M rows, already in sync | **964.8 ms** | no hard bound (smoke) |
| 10k rows + continuous writes during handshake (1 write/500 ms) | **2.4 ms** handshake; 7 writes interleaved | converge < 5000 ms |
| Reconnect after 10k rows accumulated while disconnected (1k→11k) | **110.5 ms** | no stall (handshake completes) |

## Acceptance (🎯T12)

- [x] Suite covers 1k, 10k, 100k, 1M
- [x] 10k no-diff under 1 s
- [x] 10k continuous writes converge within 5 s
- [x] Reconnect after 10k accumulated rows completes without stall
- [x] Baselines documented here for regression tracking

## Notes

- Continuous-write case injects master writes while the multi-round diff
  handshake is in flight; the protocol still reaches `Replica::State::Live`.
- Reconnect case seeds the replica with 1k rows, accumulates 10k more on the
  master while disconnected, then runs full diff sync.
- Re-record MESSAGE lines after material protocol changes (bucket size,
  hash, wire format) and update this table.
