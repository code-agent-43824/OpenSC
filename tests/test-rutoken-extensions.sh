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
		! grep -q '^  name: "Test Rutoken"$' "$test_dir/probe.log" ||
		! grep -q '^  ulPinID 5: CKR_OK' "$test_dir/probe.log"; then
	cat "$test_dir/probe.log"
	exit 1
fi

# The write tests create, use and delete a key pair and a certificate; the
# stub's C_Finalize fails if one of them or a returned buffer is left behind.
# The probe creates the --save-dir directory.
probe_out="$test_dir/probe-out"
probe_write="$test_dir/probe-write.log"
if ! RUTOKEN_PROBE_PIN=1234 "$probe" --pause-ms 0 --login \
		--pin-env RUTOKEN_PROBE_PIN --write-tests --assume-yes \
		--save-dir "$probe_out" "$stub" > "$probe_write" ||
		! grep -q '^PROBE COMPLETE' "$probe_write" ||
		! grep -q '^  C_GenerateKeyPair -> CKR_OK' "$probe_write" ||
		! grep -q '^  C_CreateObject(certificate) -> CKR_OK' "$probe_write" ||
		! grep -q '^  data 40 bytes, equal to the signed data; 1 signer' \
			"$probe_write" ||
		! grep -q '^  C_EX_PKCS7VerifyFinal -> CKR_SIGNATURE_INVALID' \
			"$probe_write" ||
		! grep -q '^  3 objects with the label' "$probe_write" ||
		! grep -q '^  C_Finalize -> CKR_OK' "$probe_write"; then
	cat "$probe_write"
	exit 1
fi
for file in certificate-temporary.der pkcs7-attached.der pkcs7-detached.der \
		csr.der csr-explicit-key.der csr-key-usage.der journal-pkcs7.bin; do
	if ! test -s "$probe_out/$file"; then
		echo "the probe did not save $file"
		exit 1
	fi
done
"$probe" --selftest-certificate "$test_dir/selftest.der" > /dev/null
if command -v openssl > /dev/null 2>&1; then
	for certificate in "$probe_out/certificate-temporary.der" \
			"$test_dir/selftest.der"; do
		openssl x509 -inform DER -in "$certificate" -noout -subject |
			grep -q 'CN *= *OpenSC probe temporary'
	done
fi

run_tool() {
	PKCS11SPY="$stub" PKCS11SPY_OUTPUT="$log" \
		"$tool" --module "$spy" --slot 7 "$@"
}

expect() {
	if ! grep -qF -- "$2" "$1"; then
		echo "missing in $1: $2"
		cat "$1"
		exit 1
	fi
}

info=$(run_tool --rutoken-info)
name=$(run_tool --rutoken-name)

echo "$info" | grep -q 'token type         : 0x1 (RUTOKEN_ECP)'
echo "$info" | grep -q 'memory             : 2048 free / 4096 total'
echo "$info" | grep -q 'flags              : 0x1c82 (USER_CHANGE_USER_PIN HAS_FLASH_DRIVE SUPPORT_JOURNAL USER_PIN_UTF8 ADMIN_PIN_UTF8)'
echo "$info" | grep -q 'battery            : not reported'
echo "$info" | grep -q 'firmware checksum  : 0xa5674611'
echo "$name" | grep -q '^Rutoken name: Test Rutoken$'
grep -q 'C_EX_GetFunctionListExtended' "$log"
grep -q 'C_EX_GetTokenInfoExtended' "$log"
test "$(grep -c 'C_EX_GetTokenName' "$log")" -ge 4

text="$test_dir/commands.txt"
run_tool --rutoken-license 2 --rutoken-journal --rutoken-volumes \
	--rutoken-cert-text --rutoken-pin-status > "$text"
expect "$text" 'Rutoken license 2: 72 bytes, not empty'
expect "$text" 'RSF type           : 0x03 (AGOST_PR)'
expect "$text" 'RSF flags          : 0x01 (KEY_EXCHANGE_ALLOWED)'
expect "$text" 'operation flags    : 0x01 (DEVICE_HASH)'
expect "$text" 'RSF ID             : 0x0005'
expect "$text" 'signature count    : 298'
expect "$text" 'device ID          : 3333333333333333'
expect "$text" 'Rutoken flash drive: 1024 MB'
expect "$text" 'volume 3: 256 MB, HIDDEN, owner local PIN 3, flags 0x0'
expect "$text" 'Certificate 2 (handle 0x66, ID 0304, label "Test certificate 2"):'
expect "$text" 'Subject: CN="Test" 2'
expect "$text" 'SO PIN change      : required'
expect "$text" 'local PIN 5        : length 4..32, retries 3 / 5, flags 0x4 (IS_UTF8)'
expect "$text" 'local PINs 6..31   : not reported, CKR_ARGUMENTS_BAD'

# The license reaches only the file, which only the owner may read.
license="$test_dir/license.bin"
run_tool --rutoken-license 2 --output-file "$license" > "$text"
expect "$text" "written to $license"
test "$(($(wc -c < "$license")))" -eq 72
test -n "$(find "$license" -perm 600)"
od -An -tx1 "$license" | head -n 1 | grep -q '01 02 03 04 05 06 07 08'
if grep -q '01 02 03 04 05 06 07 08' "$log"; then
	echo "the spy log contains the license"
	exit 1
fi

if run_tool --rutoken-license 4 > "$text" 2>&1; then
	echo "an unreadable license did not fail"
	exit 1
fi
expect "$text" 'C_EX_GetLicense failed: rv = CKR_RTPKCS11_DATA_CORRUPTED (0x80000004)'

json="$test_dir/commands.json"
run_tool --rutoken-info --rutoken-name --rutoken-license 1 --rutoken-journal \
	--rutoken-volumes --rutoken-cert-text --rutoken-pin-status \
	--rutoken-json > "$json"
if command -v python3 > /dev/null 2>&1; then
	python3 - "$json" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)
assert result["slot"] == 7
assert result["info"]["flag_names"] == [
    "USER_CHANGE_USER_PIN", "HAS_FLASH_DRIVE", "SUPPORT_JOURNAL",
    "USER_PIN_UTF8", "ADMIN_PIN_UTF8"]
assert result["info"]["battery"] is None
assert result["info"]["firmware_checksum"] == 0xA5674611
assert result["name"]["label"] == "Test Rutoken"
assert result["license"] == {"number": 1, "length": 72, "empty": True}
record = result["journal"]["records"][0]
assert record["operation_name"] == "SIGNATURE"
assert record["rsf_type"] == 3 and record["rsf_type_name"] == "AGOST_PR"
assert record["rsf_flag_names"] == ["KEY_EXCHANGE_ALLOWED"]
assert record["operation_flag_names"] == ["DEVICE_HASH"]
assert record["rsf_id"] == 5 and record["signature_count"] == 298
assert result["journal"]["format_valid"] is True
assert [v["owner_name"] for v in result["volumes"]["list"]] == [
    "USER", "SO", "LOCAL_PIN"]
certificates = result["certificates"]["list"]
assert [c["id"] for c in certificates] == ["0102", "0304", "0506"]
assert certificates[1]["text"] == 'Subject: CN="Test" 2\nIssuer: CN=Test CA\n'
assert certificates[2]["label"] == "\u00d2\u00e5\u00f1\u00f2"
assert certificates[2]["text"] == "Subject: CN=\u0422\u0435\u0441\u0442\tTab\n"
status = result["pin_status"]
assert status["user"] == {"change_required": False}
assert status["so"] == {"change_required": True}
assert [p["id"] for p in status["local_pins"]] == [3, 5]
assert len(status["local_pins_not_reported"]) == 27
PYTHON
else
	expect "$json" '"signature_count":298'
fi

# Every buffer from C_EX_GetCertificateInfoText was released, so the stub's
# C_Finalize never failed.
if grep -q 'CKR_GENERAL_ERROR' "$log"; then
	echo "a Rutoken buffer was not released"
	exit 1
fi
grep -q '^\[out\] pInfo\[2\]: idVolume = 3' "$log"
grep -q '^\[in\] pValue->ulPinID = 0x1f' "$log"

echo "PASS: all Rutoken wrappers and the --rutoken-* commands through pkcs11-spy"
echo "PASS: Rutoken hardware probe runs against the stub module, write tests included"
