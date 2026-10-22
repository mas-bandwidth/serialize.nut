# serialize-squirrel-ci: the CI workflow's own gate (DESIGN.md (i) THE
# RUNNER owns the interpreter pin; the wire's authority row owns the corpus
# pin). Files only: no network, no interpreter, no build.
.PHONY: check-ci
check-ci:
	@bash tools/checkci/check-ci.sh
