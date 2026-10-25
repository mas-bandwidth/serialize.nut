# serialize-squirrel-fuzz-differential: the fuzz differential against
# serialize.go v2.0.0 (fuzz/differential_test.go, fuzz/driver.nut). It needs
# the pinned interpreter (make dist-squirrel, DESIGN.md (i)) and Go; SQ is the
# pin the Makefile exports.
#
#   make fuzz                    the differential: 2000 programs from a fixed
#                                seed, with its in-run negative control
#   make fuzz-negative-control   the same test with -sabotage-widen-int (the Go
#                                writer writes each int range one bit wider);
#                                passes only when that test goes red
#
# Both pass FUZZ_ARGS through to the test (empty by default, so the per-push
# gate is unchanged), and FUZZ_TIMEOUT is go test's -timeout:
#
#   make fuzz FUZZ_ARGS='-seed random -duration 3600s -failures ../build/fuzz-failures' FUZZ_TIMEOUT=75m
#   make fuzz FUZZ_ARGS='-seed 0x...'      replay one logged round
#
# The test's own flags (-seed, -duration, -programs, -failures) are documented
# at the top of fuzz/differential_test.go. Paths in FUZZ_ARGS are relative to
# fuzz/, where go test runs.

FUZZ_ARGS    ?=
FUZZ_TIMEOUT ?= 600s
FUZZ_TEST := cd fuzz && go test -count=1 -timeout $(FUZZ_TIMEOUT) -run 'TestDifferentialAgainstSerializeGo'

.PHONY: fuzz
fuzz: toolchain-squirrel
	$(FUZZ_TEST) -v . $(FUZZ_ARGS)

.PHONY: fuzz-negative-control
fuzz-negative-control: toolchain-squirrel
	@mkdir -p build
	@if ( $(FUZZ_TEST) -v . -sabotage-widen-int $(FUZZ_ARGS) ) > build/fuzz-negative-control.log 2>&1; then \
		cat build/fuzz-negative-control.log; \
		echo "FAIL fuzz-negative-control: the differential stayed green with the int range widened by one bit"; exit 1; fi
	@grep -m 1 -E 'round [0-9]+: seed' build/fuzz-negative-control.log || true
	@grep -m 3 -A 4 'disagreement:' build/fuzz-negative-control.log || true
	@tail -n 2 build/fuzz-negative-control.log
	@grep -q 'disagreement:' build/fuzz-negative-control.log || { echo "FAIL fuzz-negative-control: red, but not by a disagreement"; exit 1; }
	@echo "ok fuzz-negative-control: the widened int range went red"
