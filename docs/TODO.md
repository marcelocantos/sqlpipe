# TODO

- [x] **Logging hook** — Done in v0.7.0 (callback logging replaced spdlog).
- [ ] **DDL propagation** — The SQLite session extension only tracks DML, not DDL. One option: an escape hatch where sqlpipe sends opaque SQL down the pipe for execution at both ends. Challenges:
  1. **Non-determinism** — SQL allows non-deterministic behaviour (e.g. `datetime('now')`, `random()`). Propagating raw SQL could produce different results on each side.
  2. **Disconnection recovery** — If DDL is sent as ephemeral messages, reconnection/diff-sync can't recover missed schema changes. Would need a DDL log or schema-version sequencing.
  3. **Session extension mid-flight** — Can the session extension handle schema changes while a session is active? Likely needs session teardown and recreation around DDL, which interacts with flush timing.
