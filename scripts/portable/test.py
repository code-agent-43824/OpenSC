#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List


RUTOKEN_FUNCTIONS = [
    "C_EX_GetFunctionListExtended", "C_EX_InitToken",
    "C_EX_GetTokenInfoExtended", "C_EX_UnblockUserPIN",
    "C_EX_SetTokenName", "C_EX_SetLicense", "C_EX_GetLicense",
    "C_EX_GetCertificateInfoText", "C_EX_PKCS7Sign", "C_EX_CreateCSR",
    "C_EX_FreeBuffer", "C_EX_GetTokenName", "C_EX_SetLocalPIN",
    "C_EX_LoadActivationKey", "C_EX_SetActivationPassword",
    "C_EX_GetVolumesInfo", "C_EX_GetDriveSize",
    "C_EX_ChangeVolumeAttributes", "C_EX_FormatDrive", "C_EX_TokenManage",
    "C_EX_GenerateActivationPassword", "C_EX_GetJournal",
    "C_EX_SignInvisibleInit", "C_EX_SignInvisible", "C_EX_SlotManage",
    "C_EX_WrapKey", "C_EX_UnwrapKey", "C_EX_PKCS7VerifyInit",
    "C_EX_PKCS7Verify", "C_EX_PKCS7VerifyUpdate", "C_EX_PKCS7VerifyFinal",
    "C_EX_Authenticate", "C_EX_Deauthenticate", "C_EX_UnblockAuthenticator",
]


def run(tool: Path, module: Path, arguments: List[str], env: Dict[str, str]) -> str:
    command = [str(tool), "--module", str(module), *arguments]
    result = subprocess.run(
        command,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )
    print(result.stdout, end="")
    if result.returncode:
        raise RuntimeError(f"pkcs11-tool failed with exit code {result.returncode}")
    return result.stdout


def scenario(
    tool: Path,
    module: Path,
    work_dir: Path,
    name: str,
    env: Dict[str, str],
) -> None:
    so_pin = "12345678"
    initial_pin = "123456"
    user_pin = "654321"
    token_label = f"opensc-{name}"
    object_label = f"portable-data-{name}"
    payload = work_dir / f"{name}-input.bin"
    output = work_dir / f"{name}-output.bin"
    payload.write_bytes(f"OpenSC portable {name} data object\n".encode("ascii"))

    run(tool, module, ["--slot-index", "0", "--init-token", "--label", token_label,
                       "--so-pin", so_pin], env)
    run(tool, module, ["--token-label", token_label, "--init-pin", "--login",
                       "--so-pin", so_pin, "--pin", initial_pin], env)
    run(tool, module, ["--token-label", token_label, "--change-pin", "--login",
                       "--pin", initial_pin, "--new-pin", user_pin], env)
    run(tool, module, ["--token-label", token_label, "--login", "--pin", user_pin,
                       "--write-object", str(payload), "--type", "data",
                       "--label", object_label], env)
    run(tool, module, ["--token-label", token_label, "--login", "--pin", user_pin,
                       "--read-object", "--type", "data", "--label", object_label,
                       "--output-file", str(output)], env)
    if output.read_bytes() != payload.read_bytes():
        raise RuntimeError("data object content differs from the written payload")
    run(tool, module, ["--token-label", token_label, "--login", "--pin", user_pin,
                       "--delete-object", "--type", "data", "--label", object_label], env)
    objects = run(tool, module, ["--token-label", token_label, "--login", "--pin", user_pin,
                                 "--list-objects", "--type", "data"], env)
    if object_label in objects:
        raise RuntimeError("deleted data object is still listed")


def verify_spy_log(log_path: Path) -> None:
    log = log_path.read_text(encoding="utf-8", errors="replace")
    if "OpenSC PKCS#11 spy" not in log or "Loaded:" not in log:
        raise RuntimeError("spy log does not contain its header and wrapped module path")
    if "Error:" in log:
        raise RuntimeError("spy reported an internal error")

    required = [
        "C_InitToken",
        "C_InitPIN",
        "C_SetPIN",
        "C_CreateObject",
        "C_GetAttributeValue",
        "C_DestroyObject",
    ]
    positions = []
    for function in required:
        match = re.search(
            rf"(?ms)^\d+: {re.escape(function)}\r?$.*?^Returned:\s+0 CKR_OK\r?$",
            log,
        )
        if not match:
            raise RuntimeError(f"spy log has no successful {function} call")
        positions.append(match.start())
    if positions != sorted(positions):
        raise RuntimeError("spy log function order does not match the test scenario")


def verify_rutoken_extensions(
    test_dir: Path,
    spy: Path,
    platform: str,
    work_dir: Path,
) -> None:
    if platform.startswith("windows-"):
        driver = test_dir / "rutoken-driver.exe"
        stub = test_dir / "rutoken-stub.dll"
    elif platform == "macos-universal":
        driver = test_dir / "rutoken-driver"
        stub = test_dir / "rutoken-stub.dylib"
    else:
        driver = test_dir / "rutoken-driver"
        stub = test_dir / "rutoken-stub.so"
    for path in (driver, stub):
        if not path.is_file():
            raise RuntimeError(f"Rutoken acceptance binary is missing: {path}")
    if not platform.startswith("windows-"):
        driver.chmod(driver.stat().st_mode | 0o111)

    log_path = work_dir / "rutoken-spy.log"
    result = subprocess.run(
        [str(driver), str(spy), str(stub), str(log_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )
    print(result.stdout, end="")
    if result.returncode:
        raise RuntimeError(
            f"Rutoken extension acceptance failed with exit code {result.returncode}"
        )
    if "PASS: all Rutoken extended spy wrappers" not in result.stdout:
        raise RuntimeError("Rutoken extension driver did not report success")

    log = log_path.read_text(encoding="utf-8", errors="replace")
    for function in RUTOKEN_FUNCTIONS:
        if not re.search(rf"(?m)^\d+: {re.escape(function)}\r?$", log):
            raise RuntimeError(f"Rutoken spy log has no {function} call")
    if "<redacted>" not in log:
        raise RuntimeError("Rutoken spy log did not redact sensitive input")


def verify_rutoken_cli(
    tool: Path,
    spy: Path,
    test_dir: Path,
    platform: str,
    work_dir: Path,
    env: Dict[str, str],
) -> None:
    if platform.startswith("windows-"):
        stub = test_dir / "rutoken-stub.dll"
    elif platform == "macos-universal":
        stub = test_dir / "rutoken-stub.dylib"
    else:
        stub = test_dir / "rutoken-stub.so"
    log_path = work_dir / "rutoken-cli-spy.log"
    license_path = work_dir / "rutoken-license.bin"
    cli_env = env.copy()
    cli_env["PKCS11SPY"] = str(stub)
    cli_env["PKCS11SPY_OUTPUT"] = str(log_path)

    def tool_output(arguments: List[str], expected_code: int = 0) -> str:
        result = subprocess.run(
            [str(tool), "--module", str(spy), "--slot", "7", *arguments],
            env=cli_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        if result.returncode != expected_code:
            print(stdout + stderr, end="")
            raise RuntimeError(
                f"pkcs11-tool {' '.join(arguments)} exited with {result.returncode}"
            )
        return stdout + stderr

    text = tool_output([
        "--rutoken-info", "--rutoken-name", "--rutoken-license", "2",
        "--output-file", str(license_path), "--rutoken-volumes",
        "--rutoken-cert-text", "--rutoken-pin-status",
    ])
    for expected in (
        "flags              : 0x1c82 (USER_CHANGE_USER_PIN HAS_FLASH_DRIVE "
        "SUPPORT_JOURNAL USER_PIN_UTF8 ADMIN_PIN_UTF8)",
        "Rutoken name: Test Rutoken",
        "Rutoken license 2: 72 bytes, not empty",
        "volume 3: 256 MB, HIDDEN, owner local PIN 3, flags 0x0",
        'Certificate 2 (handle 0x66, ID 0304, label "Test certificate 2"):',
        "SO PIN change      : required",
        "local PIN 4        : not reported, CKR_DEVICE_ERROR",
        "local PINs 6..31   : not reported, CKR_DEVICE_ERROR",
    ):
        if expected not in text:
            print(text, end="")
            raise RuntimeError(f"pkcs11-tool Rutoken output lacks: {expected}")
    if license_path.read_bytes() != bytes(range(1, 73)):
        raise RuntimeError("pkcs11-tool wrote a wrong Rutoken license file")

    failure = tool_output(["--rutoken-license", "4"], expected_code=1)
    if "CKR_RTPKCS11_DATA_CORRUPTED (0x80000004)" not in failure:
        print(failure, end="")
        raise RuntimeError("pkcs11-tool did not name the Rutoken return value")

    document = tool_output([
        "--rutoken-journal", "--rutoken-cert-text", "--rutoken-pin-status",
        "--rutoken-json",
    ])
    result = json.loads(document)
    record = result["journal"]["records"][0]
    certificates = result["certificates"]["list"]
    if (
        record["signature_count"] != 298
        or record["rsf_type_name"] != "AGOST_PR"
        or record["device_id"] != "33" * 8
        or [c["id"] for c in certificates] != ["0102", "0304", "0506"]
        or certificates[2]["label"] != "\u00d2\u00e5\u00f1\u00f2"
        or certificates[2]["text"] != "Subject: CN=\u0422\u0435\u0441\u0442\tTab\n"
        or [p["id"] for p in result["pin_status"]["local_pins"]] != [3, 5]
    ):
        print(document, end="")
        raise RuntimeError("pkcs11-tool Rutoken JSON has unexpected values")

    data_path = work_dir / "rutoken-data.txt"
    envelope_path = work_dir / "rutoken-attached.p7"
    data_out_path = work_dir / "rutoken-data.out"
    request_path = work_dir / "rutoken-request.der"
    data_path.write_bytes(b"OpenSC Rutoken test data\n")
    login = ["--login", "--pin", "12345678"]
    stage4 = (
        (["--rutoken-pkcs7-sign", "--id", "0102", "--input-file",
          str(data_path), "--output-file", str(envelope_path)], 0,
         "envelope           : 41 bytes written to"),
        (["--rutoken-pkcs7-verify", "--input-file", str(envelope_path),
          "--output-file", str(data_out_path), "--rutoken-trusted",
          str(data_path)], 0, "result             : valid (CKR_OK)"),
        (["--rutoken-pkcs7-verify", "--input-file", str(envelope_path)], 1,
         "certificate chain not verified (CKR_CERT_CHAIN_NOT_VERIFIED)"),
        (["--rutoken-csr", "--id", "0102", "--rutoken-dn", "CN=Test",
          "--output-file", str(request_path)], 0,
         "request            : 17 bytes written to"),
    )
    for arguments, code, expected in stage4:
        output = tool_output(login + arguments, expected_code=code)
        if expected not in output:
            print(output, end="")
            raise RuntimeError(f"pkcs11-tool Rutoken output lacks: {expected}")
    if data_out_path.read_bytes() != data_path.read_bytes():
        raise RuntimeError("pkcs11-tool wrote wrong Rutoken signed data")
    if request_path.read_bytes() != b"stub CSR: CN=Test":
        raise RuntimeError("pkcs11-tool wrote a wrong Rutoken request")

    # Stage 5: each run starts from the stub's factory state. PINs that a
    # function takes directly come from the environment.
    secrets = {
        "RUTOKEN_TEST_NEW_SO_PIN": "24680135",
        "RUTOKEN_TEST_NEW_USER_PIN": "13572460",
        "RUTOKEN_TEST_LOCAL_PIN": "97531864",
    }
    cli_env.update(secrets)
    cli_env["RUTOKEN_TEST_USER_PIN"] = "12345678"
    cli_env["RUTOKEN_TEST_SO_PIN"] = "87654321"
    license_in_path = work_dir / "rutoken-license-in.bin"
    license_in_path.write_bytes(b"L" * 72)
    emitent_key_path = work_dir / "rutoken-emitent.key"
    emitent_key_path.write_bytes(b"K" * 32)
    so_login = ["--login", "--login-type", "so", "--so-pin", "87654321"]
    new_pins = ["--rutoken-new-so-pin", "env:RUTOKEN_TEST_NEW_SO_PIN",
                "--new-pin", "env:RUTOKEN_TEST_NEW_USER_PIN"]
    license_write = login + ["--rutoken-set-license", "3", "--input-file",
                             str(license_in_path)]
    stage5 = (
        (login + ["--rutoken-set-name", "Stage 5 name", "--rutoken-name"], 0,
         "Rutoken name: Stage 5 name"),
        (license_write, 1, "Repeat with --rutoken-confirm=set-license"),
        (license_write + ["--rutoken-confirm", "set-license"], 0,
         "Rutoken license 3 written: 72 bytes"),
        (["--rutoken-set-local-pin", "4", "--rutoken-auth-pin",
          "env:RUTOKEN_TEST_USER_PIN", "--new-pin", "env:RUTOKEN_TEST_LOCAL_PIN",
          "--rutoken-pin-status"], 0,
         "local PIN 4        : length 6..249, retries 10 / 10"),
        (so_login + ["--rutoken-unblock-user-pin"], 0,
         "Rutoken user PIN unblocked"),
        (so_login + ["--rutoken-token-manage", "default-user-pin", "--new-pin",
                     "env:RUTOKEN_TEST_NEW_USER_PIN", "--rutoken-info"], 0,
         "USER_PIN_NOT_DEFAULT"),
        (so_login + ["--rutoken-token-manage", "reset-user-pin",
                     "--rutoken-confirm", "reset-user-pin"], 1,
         "TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN)"),
        (["--rutoken-init-token", "--so-pin", "env:RUTOKEN_TEST_SO_PIN",
          *new_pins, "--label", "Stage 5", "--rutoken-confirm", "init-token"], 0,
         'label              : "Stage 5"'),
        (["--rutoken-init-token", "--so-pin", "87654321", *new_pins,
          "--rutoken-confirm", "init-token"], 1,
         "--so-pin: give this PIN as env:<name>"),
        (["--rutoken-restore-factory-defaults", "--so-pin",
          "env:RUTOKEN_TEST_SO_PIN", *new_pins, "--rutoken-emitent-key",
          str(emitent_key_path), "--rutoken-confirm",
          "restore-factory-defaults"], 0,
         "emitent key        : Kuznyechik, 10 attempts"),
    )
    for arguments, code, expected in stage5:
        output = tool_output(arguments, expected_code=code)
        if expected not in output:
            print(output, end="")
            raise RuntimeError(f"pkcs11-tool Rutoken output lacks: {expected}")

    log = log_path.read_text(encoding="utf-8", errors="replace")
    if "CKR_GENERAL_ERROR" in log:
        raise RuntimeError("a Rutoken buffer was not released through pkcs11-spy")
    if '[in] dn[1] = "Test"' not in log:
        raise RuntimeError("the pkcs11-spy log lacks the Rutoken request subject")
    if "01 02 03 04 05 06 07 08" in log:
        raise RuntimeError("the pkcs11-spy log contains the Rutoken license")
    for expected in (
        "[in] pInitInfo->pNewAdminPin = <redacted>, length = 8",
        "[in] ulMode = 0x6 (MODE_RESTORE_FACTORY_DEFAULTS)",
        "[in] pValue->pNewEmitentKey = <redacted>, length = 32",
        "[in] pValue->pPinValue = <redacted>, length = 8",
    ):
        if expected not in log:
            raise RuntimeError(f"the pkcs11-spy log lacks: {expected}")
    for secret in (*secrets.values(), "LLLLLLLL", "KKKKKKKK"):
        if secret in log:
            raise RuntimeError("the pkcs11-spy log contains a Rutoken secret")
    print("PASS: pkcs11-tool Rutoken commands through pkcs11-spy, stage 5 "
          "included")


def verify_spy_config(
    tool: Path,
    spy: Path,
    module: Path,
    work_dir: Path,
    env: Dict[str, str],
) -> None:
    config = spy.parent / "pkcs11-spy.conf"
    if not config.is_file():
        raise RuntimeError(f"pkcs11-spy config template is missing: {config}")
    template = config.read_bytes()
    config_log = spy.parent / "pkcs11-spy-config-test.log"
    fallback_log = work_dir / "pkcs11-spy-config-fallback.log"
    relative_module = os.path.relpath(module, spy.parent)
    invalid_module = work_dir / "missing-pkcs11-module"

    try:
        config.write_text(
            f"PKCS11SPY={relative_module}\n"
            f"PKCS11SPY_OUTPUT={config_log.name}\n",
            encoding="utf-8",
        )
        config_env = env.copy()
        config_env["PKCS11SPY"] = str(invalid_module)
        config_env["PKCS11SPY_OUTPUT"] = str(work_dir / "wrong-environment.log")
        run(tool, spy, ["--show-info"], config_env)
        config_text = config_log.read_text(encoding="utf-8", errors="replace")
        if "Loaded:" not in config_text or module.name not in config_text:
            raise RuntimeError("pkcs11-spy did not prefer its local config file")

        config.write_text("UNKNOWN_SETTING=value\n", encoding="utf-8")
        fallback_env = env.copy()
        fallback_env["PKCS11SPY"] = str(module)
        fallback_env["PKCS11SPY_OUTPUT"] = str(fallback_log)
        run(tool, spy, ["--show-info"], fallback_env)
        fallback_text = fallback_log.read_text(encoding="utf-8", errors="replace")
        if "Loaded:" not in fallback_text or str(module) not in fallback_text:
            raise RuntimeError("pkcs11-spy did not fall back to environment variables")
    finally:
        config.write_bytes(template)
        config_log.unlink(missing_ok=True)


def main() -> None:
    if len(sys.argv) == 1:
        testkit_dir = Path(__file__).resolve().parent
        package_dir = testkit_dir / "opensc-package"
        softhsm_dir = testkit_dir / "softhsm-package"
        rutoken_test_dir = testkit_dir / "rutoken-test"
        platform = (testkit_dir / "platform.txt").read_text(encoding="ascii").strip()
    elif len(sys.argv) == 4:
        package_dir = Path(sys.argv[1]).resolve()
        softhsm_dir = Path(sys.argv[2]).resolve()
        rutoken_test_dir = None
        platform = sys.argv[3]
    else:
        raise SystemExit("usage: test.py [<OpenSC package dir> <SoftHSM package dir> <platform>]")
    if platform.startswith("windows-"):
        tool = package_dir / "bin" / "pkcs11-tool.exe"
        spy = package_dir / "lib" / "pkcs11-spy.dll"
        softhsm = softhsm_dir / "softhsm2.dll"
    elif platform == "macos-universal":
        tool = package_dir / "bin" / "pkcs11-tool"
        spy = package_dir / "lib" / "pkcs11-spy.dylib"
        softhsm = softhsm_dir / "libsofthsm2.dylib"
    else:
        tool = package_dir / "bin" / "pkcs11-tool"
        spy = package_dir / "lib" / "pkcs11-spy.so"
        softhsm = softhsm_dir / "libsofthsm2.so"

    for path in (tool, spy, softhsm):
        if not path.is_file():
            raise RuntimeError(f"required file is missing: {path}")
    if not platform.startswith("windows-"):
        tool.chmod(tool.stat().st_mode | 0o111)

    with tempfile.TemporaryDirectory(prefix="opensc-portable-test-") as temp:
        work_dir = Path(temp)
        home = work_dir / "home"
        home.mkdir()
        env = os.environ.copy()
        env["HOME"] = str(home)
        env["USERPROFILE"] = str(home)
        env.pop("SOFTHSM2_CONF", None)
        env.pop("PKCS11SPY", None)
        env.pop("PKCS11SPY_OUTPUT", None)

        if rutoken_test_dir is not None:
            verify_rutoken_extensions(rutoken_test_dir, spy, platform, work_dir)
            verify_rutoken_cli(tool, spy, rutoken_test_dir, platform, work_dir, env)
            verify_spy_config(tool, spy, softhsm, work_dir, env)

        scenario(tool, softhsm, work_dir, "direct", env)

        spy_log = work_dir / "pkcs11-spy.log"
        env["PKCS11SPY"] = str(softhsm)
        env["PKCS11SPY_OUTPUT"] = str(spy_log)
        scenario(tool, spy, work_dir, "spy", env)
        verify_spy_log(spy_log)

    print("PASS: Rutoken extension and data-object scenarios completed")


if __name__ == "__main__":
    main()
