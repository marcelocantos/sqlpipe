# sqlpipe

release_shipping: gated-push

## Delivery

Owner ships to `master` by gated push (`make gate`, then
`git push origin master`). The gate writes a per-clone tree attestation;
the pre-push hook checks that record instead of rerunning the suites.
Do not open an owner PR. Inbound PRs from others stay. After clone: `git config core.hooksPath scripts/hooks`.

## Gates

profile: library
override:
  - pr-workflow: skip
  - ci-green: skip

The owner gate is local `make gate` (ephemeral Docker Postgres +
`cv test` + Go tests (including the live Postgres binding) + Swift/Wasm
when those toolchains are on PATH).
`/release` runs that gate. There are no GitHub Actions workflows.
`make gate-linux` (Docker Ubuntu) and `make gate-windows` (Parallels
`hms-vm`) are optional extra OS checks; they are not part of `make gate`.
`cv test` alone still runs the SQLite suite and skips live Postgres if
`PG*` does not point at a server.

Streaming SQLite replication. Two-file C++ library: `dist/sqlpipe.h` +
`dist/sqlpipe.cpp` (sqlift + sqldeep bundled). C++23. Outgoing methods
return `OutMessage`, not bare `Message`. Shipped C++ gate is `cv test`;
`cv example` does not compile.

@AGENTS.md
