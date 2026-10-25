# Owner gate (`make gate`) is the CI oracle. /release B.7 runs it.
# `gate-linux` / `gate-windows` are optional extra OS checks.
# `bullseye` is the standing-invariants hook for bullseye_convergence.

.PHONY: gate gate-linux gate-windows bullseye cv-test go-test check-dirty

gate:
	./scripts/with-postgres.sh ./scripts/gate.sh

gate-linux:
	./scripts/gate-linux.sh

gate-windows:
	./scripts/gate-windows.sh

bullseye: gate check-dirty

cv-test:
	@cv test >/dev/null 2>&1 && echo "✓ cv test" || \
	  (echo "✗ cv test failed"; cv test; exit 1)

go-test:
	@cd $(CURDIR)/go/sqlpipe && go test ./... >/dev/null 2>&1 && echo "✓ go test" || \
	  (echo "✗ go test failed"; cd $(CURDIR)/go/sqlpipe && go test ./...; exit 1)

check-dirty:
	@dirty=$$(git status --porcelain | grep -vE 'bullseye\.yaml$$' || true); \
	if [ -z "$$dirty" ]; then echo "✓ working tree clean"; \
	else \
	  echo ""; \
	  echo "================================================================"; \
	  echo "⚠  DIRTY WORKING TREE"; \
	  echo ""; \
	  echo "Warning only — invariants still pass (exit 0)."; \
	  echo "Look at the files below before starting a new target."; \
	  echo "Leftover work from a different objective → park it in a commit first."; \
	  echo "This session's WIP on the recommended target → continue."; \
	  echo "================================================================"; \
	  echo "$$dirty"; \
	  echo "================================================================"; \
	  echo ""; \
	fi
