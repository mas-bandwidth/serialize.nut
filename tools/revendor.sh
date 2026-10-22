#!/usr/bin/env bash
# tools/revendor.sh <tag>: re-vendor the wire's authority from
# mas-bandwidth/serialize at <tag> (DESIGN.md's pins table): STANDARD.md,
# IMPLEMENTING.md, conformance/ and conformance-controls/, verbatim. It clones
# the tag into a scratch directory, replaces the four copies, and prints the
# diff stat against HEAD. Bump SERIALIZE_TAG in .github/workflows/ci.yml and
# the pin in DESIGN.md in the same change; make check-ci holds them together.
set -euo pipefail

tag=${1:?usage: tools/revendor.sh <tag>}
root=$(cd "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/revendor.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$tag" https://github.com/mas-bandwidth/serialize.git "$scratch/serialize"
cp "$scratch/serialize/STANDARD.md" "$root/STANDARD.md"
cp "$scratch/serialize/IMPLEMENTING.md" "$root/IMPLEMENTING.md"
for d in conformance conformance-controls; do
	rm -rf "${root:?}/$d"
	cp -R "$scratch/serialize/$d" "$root/$d"
done
git -C "$root" add -A STANDARD.md IMPLEMENTING.md conformance conformance-controls
git -C "$root" diff --cached --stat -- STANDARD.md IMPLEMENTING.md conformance conformance-controls
