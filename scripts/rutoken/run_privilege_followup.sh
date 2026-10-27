#!/bin/sh
# Self-contained bundle entry point. Use on a disposable Rutoken only.
set -eu

if [ "$#" -ne 5 ]; then
	printf 'Usage: %s PKCS11_TOOL MODULE SLOT EXPECTED_SERIAL NEW_OUTPUT_DIR\n' "$0" >&2
	exit 2
fi

bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$bundle_dir/rutoken-privilege-probe.c" ]; then
	helper_source="$bundle_dir/rutoken-privilege-probe.c"
	include_dir="$bundle_dir/src"
else
	helper_source="$bundle_dir/../../tests/rutoken-privilege-probe.c"
	include_dir="$bundle_dir/../../src"
fi
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/rutoken-privilege-followup.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM

cc -I "$include_dir" "$helper_source" \
	-o "$build_dir/rutoken-privilege-probe" -ldl

set +e
PYTHONDONTWRITEBYTECODE=1 python3 "$bundle_dir/privilege_scenarios.py" \
	--case followup --tool "$1" --module "$2" --slot "$3" \
	--expected-serial "$4" --output "$5" \
	--helper "$build_dir/rutoken-privilege-probe"
result=$?
set -e

if [ -d "$5" ]; then
	cp "$build_dir/rutoken-privilege-probe" "$5/helper-used"
fi
exit "$result"
