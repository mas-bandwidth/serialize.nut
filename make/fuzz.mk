# serialize-squirrel-fuzz-differential: the fuzz differential against
# serialize.go v1.15.1 (fuzz/differential_test.go, fuzz/driver.nut). It needs
# the pinned interpreter (make dist-squirrel, DESIGN.md (i)) and Go; SQ is the
# pin the Makefile exports.
#
#   make fuzz                    the differential: 2000 programs from a fixed
#                                seed, with its in-run negative control
#   make fuzz-negative-control   the same test with -sabotage-widen-int (the Go
#                                writer writes each int range one bit wider);
#                                passes only when that test goes red

FUZZ_TEST := cd fuzz && go test -count=1 -timeout 600s -run 'TestDifferentialAgainstSerializeGo'

.PHONY: fuzz
fuzz: toolchain-squirrel
	$(FUZZ_TEST) -v .

.PHONY: fuzz-negative-control
fuzz-negative-control: toolchain-squirrel
	@mkdir -p build
	@if ( $(FUZZ_TEST) . -sabotage-widen-int ) > build/fuzz-negative-control.log 2>&1; then \
		cat build/fuzz-negative-control.log; \
		echo "FAIL fuzz-negative-control: the differential stayed green with the int range widened by one bit"; exit 1; fi
	@grep -m 3 -A 4 'disagreement:' build/fuzz-negative-control.log || true
	@tail -n 2 build/fuzz-negative-control.log
	@grep -q 'disagreement:' build/fuzz-negative-control.log || { echo "FAIL fuzz-negative-control: red, but not by a disagreement"; exit 1; }
	@echo "ok fuzz-negative-control: the widened int range went red"
