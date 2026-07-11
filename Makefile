# Standing-invariants hook for bullseye_convergence (`make bullseye`).
# Primary build system remains cv (cvfile); this Makefile only wires checks.

.PHONY: bullseye cv-test go-test clean-tree

bullseye: cv-test go-test clean-tree

cv-test:
	@cv test >/dev/null 2>&1 && echo "✓ cv test" || \
	  (echo "✗ cv test failed"; cv test; exit 1)

go-test:
	@cd $(CURDIR)/go/sqlpipe && go test ./... >/dev/null 2>&1 && echo "✓ go test" || \
	  (echo "✗ go test failed"; cd $(CURDIR)/go/sqlpipe && go test ./...; exit 1)

clean-tree:
	@test -z "$$(git status --porcelain)" && echo "✓ clean tree" || \
	  (echo "✗ dirty tree:"; git status --short; exit 1)
