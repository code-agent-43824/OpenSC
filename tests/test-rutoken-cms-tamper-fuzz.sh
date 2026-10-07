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
		shared_flags=-dynamiclib
		;;
	*)
		module_ext=so
		shared_flags='-shared -fPIC'
		;;
esac

# shellcheck disable=SC2086
$CC $shared_flags -I"$SOURCE_PATH/src" \
	"$SOURCE_PATH/tests/rutoken-stub.c" -o "$test_dir/rutoken-stub.$module_ext"
python3 "$SOURCE_PATH/tests/rutoken-cms-tamper-fuzz.py" \
	"$BUILD_PATH/src/tools/pkcs11-tool" "$test_dir/rutoken-stub.$module_ext" \
	--spy "$BUILD_PATH/src/pkcs11/.libs/pkcs11-spy.$module_ext"
