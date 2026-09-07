# Standing-invariants hook for bullseye_convergence (`make bullseye`).
# Primary build system remains cv (cvfile); this Makefile only wires checks.

.PHONY: bullseye gate hooks hooks-check cv-test go-test clean-tree

bullseye: cv-test go-test clean-tree

# The pre-push gate (think 🎯T8). Runs the oracles that already exist and are
# already green on this host: the C++ doctest suite via cv, and the Go tests.
# `clean-tree` is deliberately NOT part of the gate — a push of committed work
# from a tree with unrelated scratch files is not a defect.
gate: hooks-check gate-residue cv-test go-test

# Legs the gate does not run, declared every time so their absence cannot be
# mistaken for coverage. CI (.github/workflows/ci.yml) runs all three.
gate-residue:
	@echo "================================================================"
	@echo "gate residue — NOT exercised by this gate:"
	@echo "  swift/       swift build (macOS-only, minutes; CI job 'swift')"
	@echo "  web/         cv wasm + tsc + node smoke (needs emsdk; CI job 'wasm')"
	@echo "  ubuntu       the Linux half of the cv-test matrix"
	@echo "================================================================"

cv-test:
	@cv test >/dev/null 2>&1 && echo "✓ cv test" || \
	  (echo "✗ cv test failed"; cv test; exit 1)

go-test:
	@cd $(CURDIR)/go/sqlpipe && go test ./... >/dev/null 2>&1 && echo "✓ go test" || \
	  (echo "✗ go test failed"; cd $(CURDIR)/go/sqlpipe && go test ./...; exit 1)

clean-tree:
	@test -z "$$(git status --porcelain)" && echo "✓ clean tree" || \
	  (echo "✗ dirty tree:"; git status --short; exit 1)

# Wire the pre-push gate. A relative core.hooksPath resolves against
# whichever worktree the push runs from, so one setting covers them all.
# Redirecting hooksPath disables .git/hooks entirely; scripts/hooks/pre-push
# chains git-lfs's pre-push so LFS uploads would survive if this repo ever
# tracked LFS objects (it does not today).
hooks:
	@git config core.hooksPath scripts/hooks && chmod +x scripts/hooks/* && \
	 echo "✓ core.hooksPath=scripts/hooks (pre-push runs make gate)"

# Warning only: the gate must still run on a runner that has no hooks.
hooks-check:
	@if [ -z "$$GITHUB_ACTIONS" ] && [ "$$(git config --get core.hooksPath)" != "scripts/hooks" ]; then \
	  echo "⚠  pre-push gate is not wired in this clone: run 'make hooks'"; fi
