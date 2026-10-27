#!/usr/bin/env bash
# tools/revendor.sh <ref>: re-vendor the wire's authority from
# mas-bandwidth/serialize at <ref> (DESIGN.md's pins table): STANDARD.md,
# IMPLEMENTING.md, conformance/ and conformance-controls/, verbatim. <ref> is a
# release tag (v2.0.0) or a full 40-hex commit sha. It fetches that ref into a
# scratch directory, replaces the four copies, and prints the diff stat against
# HEAD. Bump SERIALIZE_REF in .github/workflows/ci.yml and the pin in
# DESIGN.md in the same change; make check-ci holds them together.
set -euo pipefail

ref=${1:?usage: tools/revendor.sh <tag or full commit sha>}
root=$(cd "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/revendor.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

git init --quiet "$scratch/serialize"
git -C "$scratch/serialize" fetch --quiet --depth 1 https://github.com/mas-bandwidth/serialize.git "$ref"
git -C "$scratch/serialize" -c advice.detachedHead=false checkout --quiet FETCH_HEAD
echo "mas-bandwidth/serialize $ref at $(git -C "$scratch/serialize" rev-parse HEAD)"
cp "$scratch/serialize/STANDARD.md" "$root/STANDARD.md"
cp "$scratch/serialize/IMPLEMENTING.md" "$root/IMPLEMENTING.md"
for d in conformance conformance-controls; do
	rm -rf "${root:?}/$d"
	cp -R "$scratch/serialize/$d" "$root/$d"
done
git -C "$root" add -A STANDARD.md IMPLEMENTING.md conformance conformance-controls
git -C "$root" diff --cached --stat -- STANDARD.md IMPLEMENTING.md conformance conformance-controls
