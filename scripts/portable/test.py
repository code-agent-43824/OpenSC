#!/usr/bin/env python3
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

        scenario(tool, softhsm, work_dir, "direct", env)

        spy_log = work_dir / "pkcs11-spy.log"
        env["PKCS11SPY"] = str(softhsm)
        env["PKCS11SPY_OUTPUT"] = str(spy_log)
        scenario(tool, spy, work_dir, "spy", env)
        verify_spy_log(spy_log)

    print("PASS: Rutoken extension and data-object scenarios completed")


if __name__ == "__main__":
    main()
