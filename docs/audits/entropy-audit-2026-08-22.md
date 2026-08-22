# Entropy audit — sqlpipe — 2026-08-22

Full-mode audit (architecture, redundancy, SDLC) plus explicit hygiene
validation. Production code was not modified.

## Executive summary

- **Snapshot:** `/Users/marcelo/work/github.com/marcelocantos/sqlpipe`
- **Branch:** `master` (tracking `origin/master`, ahead 2)
- **HEAD:** `dc372bb78dc49c79b924a892a209d5db2df075cc` —
  `Swift TruthReplica + sync CSqlpipe for prediction (v0.31)`
- **Initial dirty state:** clean (`git status --porcelain=v1 -b` showed only
  `## master...origin/master [ahead 2]`)
- **Date:** 2026-08-22
- **Declared version:** `0.31.0` (`SQLPIPE_VERSION` in `dist/sqlpipe.h`)
- **Headline mechanism:** A two-file C++ core is the intended source of
  truth, but the shipped product is an N-way fan-out: vendored copies of
  that core, a second live wire codec in Go, and two independently evolved
  FFI shims (C-API vs Wasm). The bundler that is supposed to keep copies
  aligned is not a CI oracle, so bindings, leftover files, and the advertised
  example have already drifted.
- **Highest-consequence findings:**
  - **ENT-001 (P1):** `dist/sqlpipe.{h,cpp}` is copied into Go and Swift with
    no CI lockstep check. Observed drift: stale
    `swift/Sources/CSqlpipe/sqlpipe_capi.h`; leftover excluded
    `sqlift.cpp` / `sqldeep.cpp`.
  - **ENT-002 (P1):** Go `Serialize`/`Deserialize` is a second live
    implementation of the wire format; Go `HandleMessage` encodes in Go then
    C++ decodes. No cross-language golden vector.
  - **ENT-003 (P1):** C-API and Wasm FFI encodings of the same
    `HandleResult` already disagree on the delivery byte; Wasm lacks the
    v0.31 prediction API.
  - **ENT-004 (P1):** Declared `cv example` fails to compile
    (`OutMessage` vs `Message`). CI does not build the example.
- **Unverified residue:** Swift package not built in this run (CI has
  `swift build`); libFuzzer and TLC not re-executed; no
  C++↔Go serialize corpus generated; `hygiene.yaml` absent so hygiene is
  undeclared rather than drifted.

## Scope and exclusions

**In scope:** `dist/`, `tests/`, `examples/loopback.cpp`, `cvfile`,
`Makefile`, `.github/workflows/ci.yml`, `scripts/bundle-deps.sh`,
`go/sqlpipe/` (excluding the size of vendored amalgams except as copy
inventory), `swift/Sources/Sqlpipe/` and Swift packaging,
`web/src/`, `web/sqlpipe_wapi.cpp`, `formal/Convergence.tla`,
`README.md`, `CLAUDE.md`, `STABILITY.md`, `docs/TODO.md`, `NOTICES`,
`compile_flags.txt`.

**Named exclusions (not mixed into production-code conclusions):**

| Tree | Role |
|---|---|
| `vendor/src/sqlite3.c`, `vendor/include/sqlite3.h` | Vendored SQLite amalgam (~9.2 MB) |
| `vendor/src/lz4.c`, `vendor/include/{lz4.h,nlohmann/json.hpp,doctest.h}` | Vendored third-party |
| `vendor/github.com/marcelocantos/{sqlift,sqldeep,deepparser}` | Git submodules; inputs to `scripts/bundle-deps.sh` |
| `go/sqlpipe/internal/c/**` except as copy-identity evidence | Wrapper-vendored amalgam + bundled `sqlpipe.cpp` |
| `swift/Sources/CSqlpipe/{sqlite3.c,lz4.c,deepparser/**,sqlpipe.cpp}` except as copy-identity | Same |
| `build/`, `web/dist/`, `web/node_modules/`, `examples/web/node_modules/`, `swift/.build/` | Build/output (gitignored) |
| `states/`, `formal/states/`, `formal/*_TTrace_*` | TLC dumps (gitignored) |
| `docs/audit/fable-2026-07.md`, `docs/research/**` | Prior audit / research, cited only as history |
| `bullseye.yaml` | Intent ledger; not executed (Jevons out of scope) |

Languages judged (from manifests): C++23 (`cvfile`), Go 1.25
(`go/sqlpipe/go.mod`), Swift 6 (`swift/Package.swift`), TypeScript
(`web/package.json`), TLA+ (`formal/`), Bash (`scripts/bundle-deps.sh`),
SQL embedded in tests. No Python/Rust production code.

## Commands run

All from repo root unless noted. Tool versions: `cv v0.10.0`,
Apple clang 21.0.0, `go1.26.4 darwin/arm64`, `emcc` at
`/opt/homebrew/bin/emcc`.

| Command | Exit | Shipped path? | Result / limitation |
|---|---|---|---|
| `git rev-parse HEAD`; `git status --porcelain=v1 -b` | 0 | n/a | HEAD `dc372bb…`; clean; ahead 2 |
| `git ls-files \| wc -l` | 0 | auxiliary | 145 tracked files |
| `shasum -a 256` of `dist` vs Go vs Swift `sqlpipe.{h,cpp}` | 0 | auxiliary | `sqlpipe.cpp` / `sqlpipe.h` currently identical across three trees |
| `shasum -a 256` of `sqlpipe_capi.{h,cpp}` copies | 0 | auxiliary | Go source = Go `internal/c` = Swift `include/`; Swift *root* `sqlpipe_capi.h` differs; Swift `sqlpipe_capi.cpp` differs only in include paths |
| `cv test` | 0 | **shipped** | `[doctest] test cases: 196 \| 196 passed`; `920` assertions |
| `GOWORK=off` `cd go/sqlpipe && go test ./...` | 0 | **shipped** | `ok sqlpipe` 0.755s; `ok sqlpipe/transport` 0.541s. (`GOWORK=/Users/marcelo/work/github.com/marcelocantos/go.work` otherwise fails `./...`) |
| `cv example` | 1 | **shipped (declared)** | 3 errors: `deliver(vector<Message>)` vs `Master::flush() -> vector<OutMessage>` |
| `cv wasm` | 0 | **shipped** | Linked `build/wasm/sqlpipe.js`. Did **not** rebuild stale `build/wasm/sqlpipe_wapi.o` (mtime 2026-07-06). 21 `-Wredundant-move` warnings from `dist/sqlpipe.cpp` |
| `cd web && npx tsc && node dist/test/smoke.test.js` | 0 | **shipped** (local objects) | Smoke passed; printed `sqlpipe 0.25.0` because `sqlpipe_wapi.o` was not rebuilt. CI clean checkout would recompile it. |
| `~/.claude/skills/hygiene/hygiene_check.py` | not run | n/a | `hygiene.yaml` absent; per contract, posture is undeclared and the file was not created |
| `cd swift && swift build` | not run | CI shipped path | Residue; CI job `swift` exists |
| `cv fuzz` / TLC | not run | auxiliary | Fuzz not in CI; TLA+ not in CI |

`cvfile` recipes name only the `.cpp` input, not headers, so a
header-only version bump does not rebuild `sqlpipe_wapi.o` locally.

## Observed architecture

### Declared

`CLAUDE.md` / `README.md`: two-file C++ library (`dist/sqlpipe.h` +
`dist/sqlpipe.cpp`) implementing transport-agnostic Master / Replica /
Peer / Relay plus bundled sqlift + sqldeep. Callers own the transport.
Go, Swift, and TypeScript/Wasm are bindings. `scripts/bundle-deps.sh`
is the declared way to regenerate the bundle and copy into wrappers.

### Observed runtime / build units

```
                    sqlite3 session (vendored amalgam)
                              ^
dist/sqlpipe.h  <── pimpl ──  dist/sqlpipe.cpp  (core + bundled sqlift/sqldeep)
        ^                            ^
        |                     deepparser.o (submodule, linked not bundled)
        |
   +----+------------------+---------------------------+
   |                      |                           |
C++ tests/examples    sqlpipe_capi.{h,cpp}      sqlpipe_wapi.cpp
                          |                           |
              Go wrapper.go / Swift Sqlpipe.swift   web/src/*.ts
              + Go serialize.go (2nd codec)         (decode.ts 3rd decoder)
```

- **Core types:** `Database` (owns `sqlite3*` + `QueryWatch`),
  `Master`, `Replica` (owns `QueryWatch` + prediction queue), `Peer`
  (Master+Replica), `Relay` (Master+Replica+sinks), `QueryWatch`.
- **Wire:** `[4B LE length][1B tag][payload]`. Tags in
  `dist/sqlpipe.h:657-666` match Go `go/sqlpipe/message.go:10-18`.
  Protocol version `7` (`dist/sqlpipe.h:499`, `go/sqlpipe/types.go:175`).
- **Subscription engine is shared, not triplicated:** `Database::Impl`
  (`dist/sqlpipe.cpp:4446`) and `Replica::Impl` (`dist/sqlpipe.cpp:4770`)
  both hold a `QueryWatch`. Peer/Relay subscribe by forwarding to Replica.
- **PK gate** (`dist/sqlpipe.cpp:813-854`) rejects non-`INTEGER PRIMARY KEY`
  rowid aliases — the Fable-5 F1 mechanism, still present.

### Declared vs observed

| Rule | Class |
|---|---|
| Two-file C++ dist is the consumer surface | Agreed (and currently hash-identical in wrappers) |
| Pimpl hides implementation | Agreed for Master/Replica/Peer/Relay/Database; header is **not** dependency-free (`sqlite3.h` + STL) |
| `bundle-deps.sh` keeps wrappers in lockstep | Convention-only; **not** a CI job. Already contradicted for Swift C-API header / leftover sqlift+sqldeep |
| Convergence loop preferred; handshake legacy | Agreed in README; `CLAUDE.md` still leads with handshake |
| spdlog for logging | **Contradicted:** logging is `SQLPIPE_LOG` → `LogCallback` since v0.7.0; no spdlog submodule |
| `cv example` works | **Contradicted** (ENT-004) |
| Test inventory in `CLAUDE.md` (8 files, README “146 cases”) | **Contradicted:** 11 `test_*.cpp` files, 196 doctest cases |
| C-API is one ABI for all managed languages | **Contradicted:** Wasm encoding omits delivery bytes by design (`web/sqlpipe_wapi.cpp:151-155`) |

### Dependency direction

Inbound: tests/examples/bindings → `dist/` → sqlite3/lz4/sqlift/sqldeep/deepparser.

No cycles found among the first-party modules. The surprising edges are
**copy edges** (same bytes in three trees) and **parallel codecs**
(Go serialize sitting beside C++ serialize), not import cycles.

High fan-in: `dist/sqlpipe.cpp` (40 commits in this history among
non-vendored files) and `dist/sqlpipe.h` (39). High fan-out: a new
`Replica` method must touch header, impl, C-API, Wasm WAPI, Go wrapper,
Swift wrapper, TS types, `STABILITY.md`.

## Dimension vector

| Dimension | State | Evidence summary | Change from baseline |
|---|---|---|---|
| Architecture topology | concern | Core layering is clear; three FFI/copy surfaces sit beside it without an ownership test | no prior entropy report; first baseline |
| Redundancy / sources of truth | concern | `sqlpipe.cpp` hashes match; C-API header, leftover sqlift/sqldeep, wire codec, HandleResult encoding, version macros do not share one oracle | first baseline |
| Change amplification | concern | v0.24 `OutMessage` missed the example; v0.31 prediction missed Wasm and one Swift header copy | first baseline |
| Local code quality | healthy | Linear core, pimpl, callback logging; dead `hash.go` and a global Swift log pointer are local | first baseline |
| Correctness / verification | concern | 196/196 C++ and Go tests green; example red; no cross-codec oracle; fuzz/TLA not in CI; Swift has no tests | first baseline |
| Security / dependencies | concern | Vendored amalgams, no scanner/SBOM/secret-scan; identifier interpolation in `PRAGMA table_info`; fuzz harness exists but is not gated | first baseline |
| Build / release / operations | concern | Version listed in four files; `cvfile` header deps incomplete; `cv example` not in CI; `gsed` required by bundler | first baseline |
| Documentation / governance | concern | `CLAUDE.md`/`README` stale vs tree; `docs/TODO.md` present; no `AGENTS.md`; no `hygiene.yaml` | first baseline |

Do not collapse this vector to a scalar.

## Findings

### ENT-001: Wrapper copies of the core are not CI-ratcheted and have already drifted

- **Priority:** P1
- **Dimensions:** Redundancy / sources of truth; Change amplification; Build / release / operations
- **Status:** observed fact
- **Evidence:**
  - `scripts/bundle-deps.sh:255-263` copies `dist/sqlpipe.{h,cpp}` to Go and
    Swift, and copies `sqlpipe_capi.{h,cpp}` only into
    `go/sqlpipe/internal/c/` — with an explicit comment that a stale C-API
    header *silently* feeds cgo the wrong prototypes.
  - SHA-256 of `dist/sqlpipe.cpp` =
    `go/sqlpipe/internal/c/sqlpipe.cpp` =
    `swift/Sources/CSqlpipe/sqlpipe.cpp`
    (`dc386028…`). Headers match too (`bf0b7aeb…`).
  - `swift/Sources/CSqlpipe/sqlpipe_capi.h` (230 lines, mtime 2026-07-06)
    lacks `queue_while_predicting` and the prediction entry points;
    `swift/Sources/CSqlpipe/include/sqlpipe_capi.h` (242 lines) matches Go.
    `Package.swift:25` uses `publicHeadersPath: "include"`, so the root
    copy is unused **and** stale.
  - `swift/Package.swift:20-24` excludes `sqldeep.cpp` and `sqlift.cpp`
    because they would duplicate symbols already in bundled `sqlpipe.cpp`.
    Those excluded files are still tracked and stale vs
    `vendor/src/{sqlift,sqldeep}.cpp` (93k/73k vs 108k/77k; dates 2026-03-21
    vs 2026-07-14).
  - Triple copy of `sqlite3.c` (9 215 145 bytes × 3) currently hash-match;
    `bundle-deps.sh` does not copy sqlite3/lz4/json (CLAUDE.md says do it
    by hand).
  - `.github/workflows/ci.yml` has no lockstep/`bundle-deps` job.
- **Mechanism:** Three trees are allowed to represent one implementation.
  The script that copies them is opt-in and incomplete (no Swift C-API
  copy, no sqlite3 copy, no deletion of leftover sqlift/sqldeep). A
  forgotten copy is how a silent ABI break ships in a wrapper that CI
  still compiles against its local tree.
- **Blast radius:** Go module consumers (`go get …/go/sqlpipe`) and Swift
  SPM consumers compile *their* vendored copy, not `dist/`. A missed
  `bundle-deps.sh` run after a core fix ships the old bug in those
  language ecosystems while C++ tests are green.
- **Counterevidence checked:** Current `sqlpipe.cpp` hashes match, so the
  core implementation is not drifted *today*. CI `swift` / `go` jobs
  compile whatever is committed, so a *committed* stale `sqlpipe.cpp`
  would fail only if it no longer compiled, not if it were merely old.
  The stale Swift *root* header is not the `publicHeadersPath`.
- **Smallest coherent remediation:** One generated-copy check in CI:
  after a clean `scripts/bundle-deps.sh` (or a dry-run hash compare),
  `git diff --exit-code` on the wrapper trees. Delete the unused Swift
  root `sqlpipe_capi.h` and the excluded leftover `sqlift.cpp` /
  `sqldeep.cpp`. Extend the script to copy C-API into Swift `include/`
  with the include-path rewrite, or compile Swift against the Go files
  via a single generated tree.
- **Verification:** CI job that fails if
  `shasum dist/sqlpipe.cpp go/sqlpipe/internal/c/sqlpipe.cpp swift/Sources/CSqlpipe/sqlpipe.cpp`
  are not identical, and if Swift `include/sqlpipe_capi.h` is not a
  known transform of `go/sqlpipe/sqlpipe_capi.h`.
- **Ratchet candidate:** `command:` or `ci_job: ci.yml#lockstep` once
  hygiene is declared.

### ENT-002: Go reimplements the wire codec on the live HandleMessage path

- **Priority:** P1
- **Dimensions:** Redundancy / sources of truth; Correctness / verification; Change amplification
- **Status:** observed fact (two implementations); inference (they can silently disagree); needs verification (no cross-language corpus exists)
- **Evidence:**
  - C++ `serialize` at `dist/sqlpipe.cpp:436-452` (HelloMsg:
    tag, protocol_version, fingerprint, owned_tables, last_seq).
  - Go `Serialize` at `go/sqlpipe/serialize.go:10-22` (same field order).
  - Live path: `go/sqlpipe/wrapper.go:1151-1157`
    `Master.HandleMessage` does `wire := Serialize(msg)` then
    `sqlpipe_master_handle_message` (C++ `deserialize`).
  - Same for replica (`wrapper.go:1293`) and peer (`wrapper.go:1510`).
  - Constants duplicated: `kProtocolVersion` / `ProtocolVersion` = 7;
    `MessageTag` enum (`dist/sqlpipe.h:657-666` vs
    `go/sqlpipe/message.go:10-18`); `kMaxMessageSize` /
    `MaxMessageSize` = 64 MiB; `kMaxArrayCount` / `MaxArrayCount` =
    10 000 000 (`dist/sqlpipe.h:250-253`, `go/sqlpipe/types.go:174-179`).
  - Tests are same-language round-trips:
    `tests/test_protocol.cpp:8-16` and `go/sqlpipe/serialize_test.go:13-24`
    both use `HelloMsg{… SchemaVersion{0x01, 0x03}}` — copied fixtures,
    not a shared vector.
  - `go/sqlpipe/hash.go` clones C++ FNV-1a (`dist/sqlpipe.cpp:965+`)
    and has **zero callers** outside itself (dead duplicate).
  - `go/sqlpipe/compress.go` reimplements the LZ4 changeset framing
    (`[u32][u8 type][data]`, threshold 64) using `pierrec/lz4`.
- **Mechanism:** A Go caller constructing a `HelloMsg` and passing it to
  `HandleMessage` trusts Go `Serialize` to be bit-identical to C++
  `serialize`. A tag, length prefix, fingerprint encoding, or LZ4 frame
  change made only in C++ (with green `cv test`) breaks Go peers, and
  vice versa.
- **Blast radius:** Every Go master/replica/peer and
  `go/sqlpipe/transport` (which also calls `Serialize`,
  `transport.go:78,87`). Interop with C++/Swift/Wasm peers.
- **Counterevidence checked:** Field order currently matches on HelloMsg;
  Go deserialize applies the same size caps; C++ and Go protocol tests
  are thorough *within* each language. Go still *must* decode C++-produced
  bytes (flush/converge results), so deserialize is load-bearing even if
  Serialize were removed from HandleMessage by passing an already-typed
  C++ message.
- **Smallest coherent remediation:** Keep C++ as the only encoder on the
  HandleMessage path (accept serialized bytes, or wrap C++ `serialize`
  via cgo). If a Go encoder is required for tests/transport, drive both
  from a committed golden corpus produced by C++ `serialize` and checked
  in both `test_protocol.cpp` and `serialize_test.go`.
- **Verification:** A test that `Serialize(m) == C.serialize(m)` for every
  `MessageTag`, including LZ4 and max-size errors.
- **Ratchet candidate:** `go test` golden-vector file plus a C++ test
  that SHA-256s the same fixtures.

### ENT-003: Two FFI shims, two HandleResult encodings, Wasm missing prediction

- **Priority:** P1
- **Dimensions:** Change amplification; Redundancy / sources of truth; Architecture topology
- **Status:** observed fact
- **Evidence:**
  - Go/Swift C-API encodes messages as
    `[u32 count][[serialized msg][u8 delivery]]…`
    (`go/sqlpipe/sqlpipe_capi.cpp:109-117`).
  - Wasm WAPI encodes `[u32 count][serialized msg]…` and documents the
    fork: “unlike the Go C-API, none is emitted”
    (`web/sqlpipe_wapi.cpp:151-155`).
  - TS `decodeHandleResult` (`web/src/decode.ts:128-142`) has no delivery
    byte; Go `decodeMessages` (`go/sqlpipe/wrapper.go:738-775`) does;
    Swift `stripCountAndDelivery` (`swift/Sources/Sqlpipe/Sqlpipe.swift:441-462`)
    does.
  - `web/sqlpipe_wapi.cpp` `to_replica_config` (`:272-328`) has no
    `queue_while_predicting`; no `sqlpipe_replica_begin_prediction` (grep
    over `web/` is empty). C++ API is at `dist/sqlpipe.h:861-887`; Go C
    API at `go/sqlpipe/sqlpipe_capi.h:193-199`; Swift `TruthReplica.swift`
    calls those symbols.
  - `sqlpipe_capi.cpp` itself is stored twice (Go tree + `internal/c/`)
    plus a path-rewritten Swift copy.
- **Mechanism:** Adding a field to `OutMessage` / `Replica` is not one
  change. The Wasm shim already chose a different framing than the C-API
  shim. Prediction (v0.31, HEAD) landed in C++, Go, and Swift include
  headers, and not in Wasm — the same fan-out missing a leaf.
- **Blast radius:** Any future delivery/prediction/HandleResult change;
  TS/browser consumers cannot use optimistic prediction; a developer
  copying Go decode into TS (or the reverse) misparses every message.
- **Counterevidence checked:** The WAPI comment makes the encoding fork
  deliberate, not accidental. Wasm smoke (`web/src/test/smoke.test.ts`)
  covers handshake + live insert + QueryWatch, which matches the slimmer
  TS API. Swift `TruthReplica` exercises prediction at the C ABI (untested
  in-package).
- **Smallest coherent remediation:** One FFI description (delivery byte
  either everywhere or nowhere) generated into both shims; add prediction
  to WAPI/TS or explicitly mark Wasm as a reduced surface in `STABILITY.md`
  and the agents guide. Delete the extra `sqlpipe_capi.cpp` copies in
  favour of one file with an include-path define.
- **Verification:** A round-trip test that the same `HandleResult` bytes
  decode in Go and TS; a TS test that `begin_prediction` exists *or* a
  catalogue test that it is listed as unsupported.
- **Ratchet candidate:** File rule that `sqlpipe_wapi.cpp` and
  `sqlpipe_capi.cpp` `encode_handle_result` stay in lockstep, *or* a
  documented surface matrix test.

### ENT-004: Advertised `cv example` does not build; CI never compiles it

- **Priority:** P1
- **Dimensions:** Correctness / verification; Change amplification; Documentation / governance
- **Status:** observed fact
- **Evidence:**
  - `README.md:198-199` documents `cv example` as a first-run command.
  - `cvfile:31-32,47-48` defines `!example` → `build/loopback`.
  - `examples/loopback.cpp:13` takes `const std::vector<Message>&`;
    `:83,94,102` call `deliver(master.flush(), replica)`.
  - `Master::flush` returns `std::vector<OutMessage>`
    (`dist/sqlpipe.h:746`).
  - `cv example` (this run): `error: no matching function for call to 'deliver'`
    × 3, exit 1.
  - `.github/workflows/ci.yml` jobs: `cv test`, `go test`, `swift build`,
    `cv wasm` + TS smoke. No `cv example`.
  - `STABILITY.md:73-75` records the `Message` → `OutMessage` restoration
    in v0.24.0; the example was not updated.
- **Mechanism:** The v0.24 delivery-hint change amplified across API
  signatures. Tests were updated (`tests/test_integration.cpp` uses
  `OutMessage`); the advertised loopback was not; CI has no example job,
  so the break is invisible on `master`.
- **Blast radius:** First-run clone path in README; any consumer using
  loopback as a template; confidence in “the example is the journey.”
- **Counterevidence checked:** `cv test` 196/196 still passes; integration
  tests cover handshake + flush. Relay *is* tested
  (`tests/test_integration.cpp:1141`).
- **Smallest coherent remediation:** Change `deliver` to take
  `const std::vector<OutMessage>&` and call `handler.handle_message(m.msg)`.
  Add `cv example` to CI (or to `Makefile` `bullseye`).
- **Verification:** `cv example` exit 0 on CI.
- **Ratchet candidate:** `ci.yml` step `cv example`; `make_target: example`
  if Makefile grows one.

### ENT-005: Instruction and catalogue surfaces disagree with the tree

- **Priority:** P2
- **Dimensions:** Documentation / governance; Redundancy / sources of truth
- **Status:** observed fact
- **Evidence:**
  - `README.md:198` “146 test cases”; this run: 196.
  - `docs/convergence-report.md:7` “165 cases, 739 assertions” (2026-07-11).
  - `CLAUDE.md:233-247` “Test cases across 8 files”; actual `tests/test_*.cpp`:
    11 files (adds `test_bench`, `test_prediction_queue`,
    `test_query_watch`, `test_stress`). Omits fuzz.
  - `CLAUDE.md:112` still lists spdlog submodule;
    `CLAUDE.md:253` requires `SPDLOG_*` macros.
    Logging is `SQLPIPE_LOG` (`dist/sqlpipe.cpp:16-17`). `.gitmodules`
    has sqlift/sqldeep/deepparser only. `README.md:626` still lists
    **spdlog — MIT**.
  - `compile_flags.txt:1` `-std=c++20` vs `cvfile:4` `-std=c++23`;
    `compile_flags.txt:9` `-Ivendor/github.com/gabime/spdlog/include`
    (path does not exist).
  - `STABILITY.md:240-242` and `README.md:417-419` show `Relay::hello()`
    returning `Message` / `vector<Message>`; header is `OutMessage`
    (`dist/sqlpipe.h:1122-1132`).
  - `CLAUDE.md` version-bump list omits nothing fatal (Swift inherits
    `SQLPIPE_VERSION` from the copied header) but does not mention the
    Go cgo sqlift enum in `wrapper.go`.
  - `docs/TODO.md` is a live TODO file (one open item: DDL propagation).
    Global agent instructions ban `docs/TODO.md` in favour of bullseye
    targets.
  - `cvfile:12` `sqldeep = ../sqldeep` is unused (deepparser comes from
    the vendor submodule).
  - `tests/fuzz_deserialize.cpp:5` still says `Build with: mk fuzz`
    (build system is `cv` since `f14714c`).
- **Mechanism:** Four human-maintained catalogues (README, CLAUDE.md,
  STABILITY.md, compile_flags) describe the same facts as the header
  and `cvfile`. They have already diverged, so agents and humans follow
  the wrong compile flags, logger, test map, and Relay types.
- **Blast radius:** Agent sessions (CLAUDE.md), new contributors, clangd
  via `compile_flags.txt`, stability reviews of Relay.
- **Counterevidence checked:** `STABILITY.md` version table *does* match
  `0.31.0`. Architecture narrative in README (converge vs handshake) is
  closer to the code than CLAUDE.md.
- **Smallest coherent remediation:** Derive test counts from `cv test`
  output in a tiny check; delete spdlog from README/CLAUDE/compile_flags;
  fix Relay snippets to `OutMessage`; replace `docs/TODO.md` with a
  bullseye target; drop unused `sqldeep = ../sqldeep`.
- **Verification:** A script that greps `SPDLOG` / `spdlog` in first-party
  docs and fails; CLAUDE.md test-file list equals `ls tests/test_*.cpp`.
- **Ratchet candidate:** `file:` hygiene item on `compile_flags.txt`
  matching `-std=c++23` and not matching `spdlog`.

### ENT-006: Swift surface has no test target; log callback is process-global

- **Priority:** P2
- **Dimensions:** Correctness / verification; Local code quality
- **Status:** observed fact
- **Evidence:**
  - `swift/Package.swift` defines `CSqlpipe` and `Sqlpipe` library
    targets only — no `testTarget`.
  - CI `.github/workflows/ci.yml:49-60` runs `cd swift && swift build`
    only, with a comment that this catches vendoring gaps, not behaviour.
  - `TruthReplica.swift` is new at HEAD (`dc372bb`) and has no in-repo
    Swift test.
  - `swift/Sources/Sqlpipe/Sqlpipe.swift:133` assigns
    `_currentLogHandler = logHandler`; `:487` is
    `private nonisolated(unsafe) var _currentLogHandler`. Two `SyncPeer`s
    clobber each other’s logs; concurrent create is a data race on that
    pointer.
- **Mechanism:** Swift is a shipped language binding whose behaviour is
  certified by linking, not by an oracle. The C callback has a `void* ctx`
  (`go/sqlpipe/sqlpipe_capi.h:75-76`) that the Swift wrapper does not use.
- **Blast radius:** iOS/macOS consumers of `SyncPeer` / `TruthReplica`;
  prediction regressions in Swift will not fail CI.
- **Counterevidence checked:** C++ `tests/test_prediction_queue.cpp` (26
  cases) and `go/sqlpipe/prediction_test.go` cover the C++/Go path. Swift
  compile in CI would catch missing C symbols that `TruthReplica` calls
  (prediction *is* in `include/sqlpipe_capi.h` and `sqlpipe_capi.cpp`).
- **Smallest coherent remediation:** Pass `logHandler` via the C `void*`
  context (as Go does with trampolines). Add a Swift test target that
  opens two in-memory peers and asserts a handshake + one insert.
- **Verification:** `swift test` in CI; a test that two SyncPeers log
  independently.
- **Ratchet candidate:** `ci_job: ci.yml#swift` step `swift test`.

### ENT-007: Several load-bearing oracles exist but are not gates

- **Priority:** P2
- **Dimensions:** Correctness / verification; Security / dependencies; Build / release / operations
- **Status:** observed fact
- **Evidence:**
  - `cvfile:34-36` `!fuzz` builds `tests/fuzz_deserialize.cpp` with
    `-fsanitize=fuzzer,address`. Not invoked in CI. Comment still says
    `mk fuzz`.
  - `formal/Convergence.tla` + `formal/Convergence.cfg` (MaxRows=5,
    MaxQueueLen=3, `INVARIANT Safety`, `PROPERTY Convergence`). No CI
    job. Model is abstract (integer row sets, two in-flight flags) — it
    does not cover prediction, Peer, PK rejection, or schema fingerprints.
  - Default `cv test` is unsanitized (`cvfile:44-45`).
  - `Makefile` `bullseye` runs `cv test`, `go test`, and dirty-tree;
    it does not run example, wasm, swift, fuzz, or TLA.
  - No CodeQL, Dependabot, secret-scan, or SBOM workflow under `.github/`.
  - `dist/sqlpipe.cpp:818` `PRAGMA table_info('" + name + "')` interpolates
    a sqlite_master identifier.
- **Mechanism:** The project has better tools than CI runs. Fuzz, TLC,
  ASan, and the example can rot without a red gate. Identifier
  concatenation is reachable if a user can create a table whose name
  contains a quote.
- **Blast radius:** Malformed-message crashes (fuzz would find);
  convergence-model drift vs code; example (ENT-004); SQL identifier
  breakout on hostile table names.
- **Counterevidence checked:** Deserialize already enforces
  `kMaxMessageSize` / `kMaxArrayCount` with tests in
  `tests/test_protocol.cpp:220+`. PK rejection closes the Fable F1
  data-loss path. Go transport tests cover lossy dual-channel reconnect.
- **Smallest coherent remediation:** Add a periodic/CI fuzz time-box
  (60s as the cvfile already suggests); run TLC on `Convergence.cfg`
  in CI or document it as `manual`; put `cv example` in CI (ENT-004);
  quote-escape table names in `PRAGMA table_info`.
- **Verification:** CI job logs for fuzz/TLC/example; a test table name
  containing `'` is rejected or safely quoted.
- **Ratchet candidate:** `ci_job`s for fuzz and `cv example`; scanner
  item once a tool is chosen.

### ENT-008: Go cgo preamble redeclares the sqlift C API

- **Priority:** P2
- **Dimensions:** Redundancy / sources of truth; Change amplification
- **Status:** observed fact
- **Evidence:**
  - `go/sqlpipe/wrapper.go:15-57` hand-declares `sqldeep_transpile`,
    `sqlift_apply_options`, `sqlift_error_type` enumerators, and
    `SQLIFT_ALLOW_*` instead of including `sqlpipe.h` (comment:
    “that header continues into C++”).
  - `scripts/bundle-deps.sh:52-161` already regenerates the sqlift block
    in `dist/sqlpipe.h` from `vendor/include/sqlift.h` for this exact
    class of miss.
- **Mechanism:** sqlift gaining an error code or allow-flag updates the
  bundled header automatically if bundle-deps runs, but the Go preamble
  stays frozen. CGo will not see the new enumerator; Go wrappers that
  pass `SQLIFT_ALLOW_ALL` can mask a new bit.
- **Blast radius:** Go `Database` migration / sqlift apply path
  (`wrapper.go` continues past the preamble into Database methods).
- **Counterevidence checked:** Current enum in the preamble matches
  `dist/sqlpipe.h:91-103` (0–10). Bundle-deps comment in CLAUDE.md
  already treats this class of bug as learned (C-API header).
- **Smallest coherent remediation:** Generate a `sqlift_capi.h` (C-only)
  from the same script that patches `sqlpipe.h`, and `#include` it from
  the cgo preamble.
- **Verification:** A test that `SQLIFT_ALLOW_ALL` in Go equals the C
  macro; bundle-deps dry-run diffs the preamble.
- **Ratchet candidate:** Extend `scripts/bundle-deps.sh` and
  `git diff --exit-code go/sqlpipe/wrapper.go` on the generated region.

### ENT-009: Dead and leftover files in the wrapper trees

- **Priority:** P3
- **Dimensions:** Redundancy / sources of truth; Local code quality
- **Status:** observed fact
- **Evidence:**
  - `go/sqlpipe/hash.go` — unexported FNV helpers, no references
    outside the file.
  - `swift/Sources/CSqlpipe/sqlpipe_capi.h` — stale duplicate of
    `include/sqlpipe_capi.h` (ENT-001).
  - `swift/Sources/CSqlpipe/{sqlift,sqldeep}.cpp` — excluded from the
    Swift target (`Package.swift:20-24`) and stale vs vendor.
- **Mechanism:** Dead copies invite edits to the wrong file (especially
  the extra `sqlpipe_capi.h`).
- **Blast radius:** Low unless someone removes the Package.swift exclude
  (duplicate sqlift/sqldeep symbols) or includes the stale header.
- **Counterevidence checked:** Package.swift exclude is documented as
  preventing duplicate symbols — the files are known residue, not
  mysterious.
- **Smallest coherent remediation:** Delete the three leftovers; delete
  or test `hash.go`.
- **Verification:** `git grep hashBucketEntry` empty; Swift package
  still builds.
- **Ratchet candidate:** `absent: file` hygiene items after deletion.

### ENT-010: Hygiene posture not declared; no supply-chain scanners

- **Priority:** P3
- **Dimensions:** Documentation / governance; Security / dependencies
- **Status:** observed fact
- **Evidence:** No `hygiene.yaml` at repo root. No Dependabot/CodeQL/secret
  scan workflow. `NOTICES` covers liteparser, doctest, LZ4 (and further
  third-party texts below the first 80 lines). LICENSE is Apache-2.0.
  No `AGENTS.md` (only `CLAUDE.md`).
- **Mechanism:** Steady-state controls cannot drift-fail because they
  are not declared. Fleet aggregation cannot see this repo’s floors.
- **Blast radius:** Process, not a current runtime defect.
- **Counterevidence checked:** CI *does* exist and covers C++/Go/Swift
  build/Wasm smoke; LICENSE and README are present (hygiene tier-1
  baseline ingredients, undeclared).
- **Smallest coherent remediation:** Onboard `hygiene.yaml` in a later
  session (not this audit). Do not invent TOML.
- **Verification:** `hygiene_check.py` exit 0 against a declared file.
- **Ratchet candidate:** The hygiene file itself.

## Redundancy and competing-source-of-truth inventory

| Fact | Authorities | Drift observed? |
|---|---|---|
| C++ implementation | `dist/sqlpipe.cpp` (canonical); copies in `go/sqlpipe/internal/c/` and `swift/Sources/CSqlpipe/` | No (hashes match) |
| Public C++ API | `dist/sqlpipe.h`; same two copies | No |
| C ABI | `go/sqlpipe/sqlpipe_capi.{h,cpp}` (canonical per bundle script); `internal/c/` copy; Swift `include/` + stale root `.h` + path-rewritten `.cpp` | Yes — Swift root header |
| Wasm ABI | `web/sqlpipe_wapi.cpp` | Yes vs C-API (delivery byte); prediction missing |
| Wire codec | C++ `serialize`/`deserialize`; Go `serialize.go`/`deserialize.go` | Not demonstrated; untested correspondence |
| HandleResult framing | C-API (with delivery) vs WAPI/TS (without) | Yes, documented |
| Version string | `dist/sqlpipe.h`, `go/sqlpipe/types.go`, `web/package.json`, `STABILITY.md` | Macros currently `0.31.0`; local wasm print was `0.25.0` due to stale `sqlpipe_wapi.o` |
| sqlift C API | `vendor/include/sqlift.h` → bundle script → `dist/sqlpipe.h`; Go cgo preamble | Not currently; two update paths |
| Message tags / protocol version / size caps | `dist/sqlpipe.h` vs `go/sqlpipe/{message,types}.go` | Values match today |
| sqlite3/lz4/json amalgams | `vendor/` vs Go `internal/c/` vs Swift `CSqlpipe` | Hashes match; copy is manual |
| deepparser | submodule vs Go/Swift vendored `deepparser/` | `parse.c` hashes match |
| Logging | callback (`SQLPIPE_LOG`) vs docs (spdlog) | Docs stale |
| Test census | README 146 / convergence-report 165 / this run 196 | Yes |
| Relay signatures | STABILITY/README `Message` vs header `OutMessage` | Yes |
| sqlift/sqldeep leftover in Swift | excluded tracked files vs vendor | Yes (stale) |

Deliberate duplication that should stay: sqlite3 amalgam in Go/Swift so
`go get` / SPM work without this repo’s `vendor/` tree; LZ4 frame on the
wire (C++ and Go must both speak it until Go stops encoding).

## Healthy structure worth retaining

- **Two-file dist for C++ consumers** with pimpl and a transport-agnostic
  message API. Header still includes sqlite3, but implementation details
  stay out of the public classes.
- **Shared `QueryWatch`** inside Database and Replica rather than a third
  evaluator (`dist/sqlpipe.cpp:4446`, `:4770`, `:5329-5330`).
- **Fail-closed INTEGER PRIMARY KEY gate** (`dist/sqlpipe.cpp:842-854`)
  — Fable F1 remaining closed; `WithoutRowidTable` is a real ErrorCode.
- **Full schema fingerprint** (`SchemaVersion` as `[algo][digest]`,
  protocol 7) rather than the 32-bit fold removed in v0.26.0.
- **Doctest suite on the shipped `cv test` path:** 196/196, 920
  assertions, including Relay chain tests and 26 prediction-queue cases.
- **Go tests on the shipped `go test` path,** including transport loss
  and serialize round-trips.
- **CI matrix** ubuntu+macos for C++; dedicated Go, Swift build, and
  Wasm+TS jobs. cv 0.10.0 pin matches the local tool.
- **`STABILITY.md` interaction catalogue** and Apache-2.0 + `NOTICES`.
- **TLA+ model exists** for the abstract convergence loop with explicit
  bounds (`MaxRows`, `MaxQueueLen`) — keep it, then gate it (ENT-007).
- **Bundle script already learned the silent-stale-cgo-header lesson**
  (`scripts/bundle-deps.sh:259-263`); extend that lesson to Swift and CI
  rather than replacing it.

## Hygiene posture

`hygiene.yaml` is **absent**. Hygiene posture **not declared**.

The validator was not run and was not used to initialize a file.

Overlap with entropy: CI jobs, LICENSE, README, and tests exist as
undeclared tier-1/2 ingredients. ENT-001/004/007 are the entropy
mechanisms that a future `hygiene.yaml` should ratchet (lockstep
command, `cv example`, fuzz). Do not treat this section as a held-tier
vector.

## Oracle coverage and residue

| Property | Decided by |
|---|---|
| C++ Master/Replica/Peer/Database/diff/prediction/Relay behaviour | **Shipped:** `cv test` (196/196) |
| Go wrapper + transport | **Shipped:** `go test ./...` |
| Wasm/TS handshake + live insert + QueryWatch | **Shipped in CI;** this run used a locally stale `sqlpipe_wapi.o` (version string) but the smoke assertions still passed |
| Loopback example compiles and runs | **Nothing** — `cv example` red, not in CI (ENT-004) |
| C++ ↔ Go wire identity | **Nothing** (ENT-002) |
| C-API ↔ Wasm HandleResult identity | **Accepted fork** today; no test that the fork stays intentional (ENT-003) |
| Swift SyncPeer / TruthReplica behaviour | **Compile-only** in CI (ENT-006) |
| Prediction on Wasm | **Unsupported**, undocumented as such (ENT-003) |
| Deserialize robustness | Auxiliary fuzz harness exists; **not gated** |
| Convergence under loss (abstract) | TLA+ model; **not gated**; C++/Go tests cover concrete reconnect |
| INTEGER PK requirement | Shipped tests + constructor throw |
| Wrapper copy lockstep | **Nothing** (ENT-001) |
| Secret/CVE/SBOM | **Nothing** |
| Header-only version bump rebuilds wasm | **Nothing** locally (`cvfile` lists `.cpp` only) |

**Owner residue (intent, not mechanical work):**

- Should Wasm remain a reduced surface (no prediction, no delivery byte),
  and if so should `STABILITY.md` say that?
- Should Go stop encoding the wire and only decode C++ bytes?
- Should Relay grow a C ABI, or stay C++-only?
- Onboard `hygiene.yaml` / add `AGENTS.md`, or keep CLAUDE.md-only?
- Is DDL propagation (`docs/TODO.md`) a bullseye target or accepted won’t-do?

## Remediation sequence

1. **Repair the obvious shipped-path hole:** fix `examples/loopback.cpp`
   for `OutMessage` and run `cv example` in CI (ENT-004). That is the
   oracle seam for “README commands work.”
2. **Converge copies:** CI lockstep on `dist` vs Go vs Swift; delete
   leftover Swift `sqlift.cpp` / `sqldeep.cpp` / root `sqlpipe_capi.h`;
   teach `bundle-deps.sh` to update Swift C-API include paths (ENT-001,
   ENT-009).
3. **Pick one encoder:** C++ owns serialize on the Go HandleMessage path
   or share golden vectors (ENT-002). Generate sqlift C declarations for
   cgo (ENT-008).
4. **Document or close the FFI fork:** prediction on Wasm or an explicit
   reduced-surface matrix; one HandleResult framing (ENT-003). Swift
   tests + real log context (ENT-006).
5. **Ratchet:** lockstep job, `cv example`, optional fuzz/TLC; then
   hygiene.yaml if the owner wants it declared. Refresh CLAUDE.md /
   README / compile_flags / STABILITY Relay snippets (ENT-005, ENT-007,
   ENT-010).
6. **Re-run this audit** against the same finding IDs and the same
   commands (`cv test`, `go test`, `cv example`, lockstep hashes).

No rewrite of `dist/sqlpipe.cpp` is required to close the P1s.
)