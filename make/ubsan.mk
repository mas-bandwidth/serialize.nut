# the UBSan leg (DESIGN.md (c), "the library never overflows"): the pinned
# interpreter built a second time with -fsanitize=undefined, and every test
# run on it. A signed overflow or a left shift that loses bits in the
# library's arithmetic is C++ undefined behaviour in the VM, and the run halts
# on the first one. The VM's own reports, which no script of this library
# causes, are named one by one in tools/ubsan/suppressions.txt.
#
#   make dist-squirrel-ubsan   build dist/squirrel-ubsan/bin/sq from the pinned tarball
#   make test-ubsan            make test on it (T=<name> narrows as for make test)

SQ_UBSAN := $(CURDIR)/dist/squirrel-ubsan/bin/sq

.PHONY: dist-squirrel-ubsan
dist-squirrel-ubsan: dist-squirrel
	@if [ ! -x $(SQ_UBSAN) ]; then \
		bash tools/ubsan/build.sh $(CURDIR)/dist/squirrel-$(SQUIRREL_VERSION).tar.gz $(CURDIR)/dist/squirrel-ubsan > dist/squirrel-ubsan-build.log 2>&1 || { cat dist/squirrel-ubsan-build.log; exit 1; }; fi
	@echo "sq-ubsan $(SQ_UBSAN)"

.PHONY: test-ubsan
test-ubsan:
	@if [ ! -x "$(SQ_UBSAN)" ]; then echo "test-ubsan REFUSES: $(SQ_UBSAN) does not resolve; run make dist-squirrel-ubsan"; exit 1; fi
	@mkdir -p build
	@if UBSAN_OPTIONS=halt_on_error=1 "$(SQ_UBSAN)" tools/ubsan/witness.nut > build/ubsan-witness.txt 2>&1; then \
		cat build/ubsan-witness.txt; echo "FAIL test-ubsan: the witness overflow did not halt the UBSan interpreter"; exit 1; fi
	@grep -q 'runtime error' build/ubsan-witness.txt || { cat build/ubsan-witness.txt; echo "FAIL test-ubsan: the witness failed, but not by a UBSan report"; exit 1; }
	@echo "ok test-ubsan witness: a script's signed overflow halts the interpreter"
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:suppressions=$(CURDIR)/tools/ubsan/suppressions.txt \
		$(MAKE) --no-print-directory test SQ=$(SQ_UBSAN) T=$(T)
