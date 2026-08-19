#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List


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


def main() -> None:
    if len(sys.argv) == 1:
        testkit_dir = Path(__file__).resolve().parent
        package_dir = testkit_dir / "opensc-package"
        softhsm_dir = testkit_dir / "softhsm-package"
        platform = (testkit_dir / "platform.txt").read_text(encoding="ascii").strip()
    elif len(sys.argv) == 4:
        package_dir = Path(sys.argv[1]).resolve()
        softhsm_dir = Path(sys.argv[2]).resolve()
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

        scenario(tool, softhsm, work_dir, "direct", env)

        spy_log = work_dir / "pkcs11-spy.log"
        env["PKCS11SPY"] = str(softhsm)
        env["PKCS11SPY_OUTPUT"] = str(spy_log)
        scenario(tool, spy, work_dir, "spy", env)
        verify_spy_log(spy_log)

    print("PASS: direct and pkcs11-spy data-object scenarios completed")


if __name__ == "__main__":
    main()
