#!/usr/bin/env bash
# check-ci.sh -- TestCheckCI: the CI workflow holds the design's pins.
#
# DESIGN.md (i) THE RUNNER: the interpreter is fetched and built by
# `make dist-squirrel`, and its URL and sha256 live in the Makefile and only
# there. DESIGN.md's pins table: STANDARD.md and conformance/ are vendored
# from mas-bandwidth/serialize tag v1.17.0.
#
# This reads files only. It fails, naming the file and line, when
# .github/workflows/ci.yml repeats the interpreter URL or a sha256, when it
# does not run `make dist-squirrel` and `make test`, or when its corpus tag
# differs from DESIGN.md's. Its own control is a scratch copy of ci.yml with a
# pasted sha256: that copy must fail too.

set -u

root=$(cd "$(dirname "$0")/../.." && pwd)
ci=${1:-"$root/.github/workflows/ci.yml"}
design="$root/DESIGN.md"
makefile="$root/Makefile"

# check_file <file> -- prints one --- FAIL line per broken rule, returns 1 if
# any rule broke.
check_file() {
	local file=$1
	local rc=0
	local line

	# An interpreter URL, by either its host path or its project name.
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		echo "--- FAIL TestCheckCI (${file}:${line%%:*} spells the interpreter URL)"
		rc=1
	done < <(grep -nEi 'https?://[^[:space:]]*(squirrel|albertodemichelis)|albertodemichelis|SQUIRREL_URL|squirrel/archive|tar\.gz|v3\.2' "$file" || true)

	# Any sha256 literal: the interpreter pin belongs in the Makefile, not here.
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		echo "--- FAIL TestCheckCI (${file}:${line%%:*} spells a sha256 (64 hex digits))"
		rc=1
	done < <(grep -nE '[0-9a-fA-F]{64}' "$file" || true)

	# The two commands the workflow must call, and only through make.
	if ! grep -vE '^[[:space:]]*#' "$file" | grep -qE '(^|[^[:alnum:]_-])make[[:space:]]+dist-squirrel([^[:alnum:]_-]|$)'; then
		echo "--- FAIL TestCheckCI ($file: no line runs make dist-squirrel)"
		rc=1
	fi
	if ! grep -vE '^[[:space:]]*#' "$file" | grep -qE '(^|[^[:alnum:]_-])make[[:space:]]+test([^[:alnum:]_-]|$)'; then
		echo "--- FAIL TestCheckCI ($file: no line runs make test)"
		rc=1
	fi

	# DESIGN.md's pins table names the corpus release; the workflow must name
	# the same release.
	local design_tag ci_tag
	design_tag=$(sed -n "s/.*wire's authority.*tag \`\(v[0-9][0-9.]*\)\`.*/\1/p" "$design" | head -n 1)
	ci_tag=$(sed -n 's/^[[:space:]]*SERIALIZE_TAG:[[:space:]]*\(v[0-9][0-9.]*\).*/\1/p' "$file" | head -n 1)
	if [ -z "$design_tag" ]; then
		echo "--- FAIL TestCheckCI ($design: no corpus pin in the wire's authority row)"
		rc=1
	elif [ -z "$ci_tag" ]; then
		echo "--- FAIL TestCheckCI ($file: no SERIALIZE_TAG names the corpus release)"
		rc=1
	elif [ "$ci_tag" != "$design_tag" ]; then
		echo "--- FAIL TestCheckCI ($file: corpus tag $ci_tag differs from DESIGN.md's $design_tag)"
		rc=1
	fi

	return "$rc"
}

if [ ! -f "$ci" ]; then
	echo "--- FAIL TestCheckCI ($ci: no such workflow file)"
	exit 1
fi

echo "RUN TestCheckCI"

# THE CONTROL. A scratch ci.yml with the interpreter pin pasted in is the
# mistake this gate exists to catch, so it must be red. Its failure is printed
# as evidence, indented so the gate's own verdict stays unambiguous.
pin=$(sed -n 's/^SQUIRREL_SHA256[[:space:]]*:=[[:space:]]*//p' "$makefile" | head -n 1)
if [ -z "$pin" ]; then
	echo "--- FAIL TestCheckCI ($makefile: no SQUIRREL_SHA256 pin)"
	exit 1
fi

scratch=$(mktemp -d "${TMPDIR:-/tmp}/checkci.XXXXXX") || exit 1
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT
cp "$ci" "$scratch/ci-pasted-sha.yml"
printf '\n# control: pasted interpreter sha256 %s\n' "$pin" >> "$scratch/ci-pasted-sha.yml"

control=$(check_file "$scratch/ci-pasted-sha.yml") || control_rc=$?
control_rc=${control_rc:-0}
if [ "$control_rc" -eq 0 ]; then
	echo "--- FAIL TestCheckCI (control: a pasted interpreter sha256 was accepted)"
	exit 1
fi
echo "control: a scratch ci.yml with a pasted sha256 fails as it must:"
printf '%s\n' "$control" | sed 's/^/  /'

if ! check_file "$ci"; then
	exit 1
fi

echo "--- PASS TestCheckCI"
exit 0
