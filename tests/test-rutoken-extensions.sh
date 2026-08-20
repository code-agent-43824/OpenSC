#!/bin/sh

set -eu

SOURCE_PATH=${SOURCE_PATH:-..}
BUILD_PATH=${BUILD_PATH:-..}
CC=${CC:-cc}
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM

case "$(uname -s)" in
	Darwin)
		module_ext=dylib
		shared_flags='-dynamiclib'
		spy="$BUILD_PATH/src/pkcs11/.libs/pkcs11-spy.dylib"
		;;
	*)
		module_ext=so
		shared_flags='-shared -fPIC'
		spy="$BUILD_PATH/src/pkcs11/.libs/pkcs11-spy.so"
		;;
esac

stub="$test_dir/rutoken-stub.$module_ext"
log="$test_dir/spy.log"
tool="$BUILD_PATH/src/tools/pkcs11-tool"

# shellcheck disable=SC2086
$CC $shared_flags -I"$SOURCE_PATH/src" \
	"$SOURCE_PATH/tests/rutoken-stub.c" -o "$stub"

info=$(PKCS11SPY="$stub" PKCS11SPY_OUTPUT="$log" \
	"$tool" --module "$spy" --slot 7 --rutoken-info)
name=$(PKCS11SPY="$stub" PKCS11SPY_OUTPUT="$log" \
	"$tool" --module "$spy" --slot 7 --rutoken-name)

echo "$info" | grep -q 'token type         : 0x1'
echo "$info" | grep -q 'memory             : 2048 free / 4096 total'
echo "$name" | grep -q '^Rutoken name: Test Rutoken$'
grep -q 'C_EX_GetFunctionListExtended' "$log"
grep -q 'C_EX_GetTokenInfoExtended' "$log"
test "$(grep -c 'C_EX_GetTokenName' "$log")" -eq 2

echo "PASS: Rutoken extended info and name calls through pkcs11-spy"
