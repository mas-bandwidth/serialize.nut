#!/usr/bin/env bash
# build.sh -- the UBSan interpreter (make dist-squirrel-ubsan; make/ubsan.mk).
#
# DESIGN.md (c): SQInteger arithmetic is C++ `long long`, where signed overflow
# and a left shift that loses bits are undefined, so the library never
# overflows. This builds the pinned interpreter (the tarball `make
# dist-squirrel` fetched and checked against its sha256, never another) a
# second time, sq64 + SQUSEDOUBLE as the pin, with -fsanitize=undefined, into
# dist/squirrel-ubsan/bin/sq. The checks stay recoverable so the run can name
# the VM's own reports in tools/ubsan/suppressions.txt; make test-ubsan halts
# on the first report that is not suppressed.
#
#   tools/ubsan/build.sh <tarball> <out dir>

set -eu

tarball=$1
out=$2
cxx=${CXX:-c++}

rm -rf "$out"
mkdir -p "$out"
tar -xzf "$tarball" -C "$out" --strip-components=1
cd "$out"
mkdir -p lib bin

flags="-O1 -g -m64 -D_SQ64 -DSQUSEDOUBLE -fno-exceptions -fno-rtti -fno-strict-aliasing -fsanitize=undefined -fno-omit-frame-pointer"
for lib in squirrel sqstdlib; do
	(cd "$lib" && $cxx $flags -I../include -c ./*.cpp && ar rc "../lib/lib$lib.a" ./*.o && rm ./*.o)
done
(cd sq && $cxx $flags -o ../bin/sq sq.c -I../include -L../lib -lsquirrel -lsqstdlib)
echo "sq-ubsan $out/bin/sq"
