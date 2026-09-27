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
		driver_libs=
		spy="$BUILD_PATH/src/pkcs11/.libs/pkcs11-spy.dylib"
		;;
	*)
		module_ext=so
		shared_flags='-shared -fPIC'
		driver_libs=-ldl
		spy="$BUILD_PATH/src/pkcs11/.libs/pkcs11-spy.so"
		;;
esac

stub="$test_dir/rutoken-stub.$module_ext"
driver="$test_dir/rutoken-driver"
log="$test_dir/spy.log"
tool="$BUILD_PATH/src/tools/pkcs11-tool"

# shellcheck disable=SC2086
$CC $shared_flags -I"$SOURCE_PATH/src" \
	"$SOURCE_PATH/tests/rutoken-stub.c" -o "$stub"
# shellcheck disable=SC2086
$CC -I"$SOURCE_PATH/src" "$SOURCE_PATH/tests/rutoken-driver.c" \
	-o "$driver" $driver_libs

"$driver" "$spy" "$stub" "$log"

# The hardware probe must run to the end against a module that provides only
# part of the standard table.
probe="$test_dir/rutoken-hw-probe"
# shellcheck disable=SC2086
$CC -I"$SOURCE_PATH/src" "$SOURCE_PATH/tests/rutoken-hw-probe.c" \
	-o "$probe" $driver_libs
if ! "$probe" --pause-ms 0 "$stub" > "$test_dir/probe.log" ||
		! grep -q '^PROBE COMPLETE' "$test_dir/probe.log" ||
		! grep -q '34 of 34 function pointers are set' "$test_dir/probe.log" ||
		! grep -q '^  name: "Test Rutoken"$' "$test_dir/probe.log"; then
	cat "$test_dir/probe.log"
	exit 1
fi

info=$(PKCS11SPY="$stub" PKCS11SPY_OUTPUT="$log" \
	"$tool" --module "$spy" --slot 7 --rutoken-info)
name=$(PKCS11SPY="$stub" PKCS11SPY_OUTPUT="$log" \
	"$tool" --module "$spy" --slot 7 --rutoken-name)

echo "$info" | grep -q 'token type         : 0x1'
echo "$info" | grep -q 'memory             : 2048 free / 4096 total'
echo "$name" | grep -q '^Rutoken name: Test Rutoken$'
grep -q 'C_EX_GetFunctionListExtended' "$log"
grep -q 'C_EX_GetTokenInfoExtended' "$log"
test "$(grep -c 'C_EX_GetTokenName' "$log")" -ge 4

echo "PASS: all Rutoken wrappers plus extended info and name commands through pkcs11-spy"
echo "PASS: Rutoken hardware probe runs against the stub module"
