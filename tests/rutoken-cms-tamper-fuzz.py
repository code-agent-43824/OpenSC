#!/usr/bin/env python3
import argparse
import os
import re
import subprocess
import tempfile
from collections import Counter
from pathlib import Path


def call(tool, module, arguments, env):
    return subprocess.run(
        [str(tool), "--module", str(module), "--slot", "7", *arguments],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, errors="replace",
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", type=Path)
    parser.add_argument("stub", type=Path)
    parser.add_argument("--spy", type=Path)
    parser.add_argument("--runs", type=int, default=50)
    args = parser.parse_args()
    if not 50 <= args.runs <= 100 and args.runs != 1:
        parser.error("--runs must be 50..100 (or 1 for a sanitizer smoke test)")

    with tempfile.TemporaryDirectory(prefix="rutoken-cms-tamper-") as directory:
        root = Path(directory)
        payload = bytes(range(256)) * 4
        input_file = root / "input.bin"
        valid_file = root / "valid.p7"
        output_file = root / "output.bin"
        input_file.write_bytes(payload)
        login = ["--login", "--pin", "12345678"]
        signed = call(args.tool, args.stub, [*login, "--rutoken-pkcs7-sign",
            "--id", "0102", "--input-file", str(input_file),
            "--output-file", str(valid_file)], os.environ.copy())
        if signed.returncode != 0:
            raise RuntimeError(f"synthetic signing failed: {signed.stdout}")
        valid = valid_file.read_bytes()
        if len(valid) <= 100:
            raise RuntimeError("synthetic envelope is too short for truncation tests")

        cases = [("valid", valid, "CKR_OK")]
        for label, offset in (("start", 0), ("middle", len(valid) // 2),
                              ("tail", len(valid) - 10)):
            changed = bytearray(valid)
            changed[offset] ^= 0xff
            cases.append((f"flip-{label}", bytes(changed), None))
        for count in range(1, 51):
            cases.append((f"truncate-start-{count}", valid[count:], None))
            cases.append((f"truncate-end-{count}", valid[:-count], None))

        counts = Counter()
        for label, envelope, expected in cases:
            test_file = root / "test.p7"
            test_file.write_bytes(envelope)
            for repeat in range(args.runs):
                output_file.unlink(missing_ok=True)
                result = call(args.tool, args.stub, [*login,
                    "--rutoken-pkcs7-verify", "--input-file", str(test_file),
                    "--rutoken-verify-flag", "check-signature-only",
                    "--output-file", str(output_file)], os.environ.copy())
                if any(marker in result.stdout for marker in
                       ("AddressSanitizer", "LeakSanitizer", "runtime error:")):
                    raise RuntimeError(f"sanitizer failure in {label} #{repeat}: {result.stdout}")
                if expected:
                    if result.returncode != 0 or expected not in result.stdout:
                        raise RuntimeError(f"valid {label} #{repeat}: exit {result.returncode}: {result.stdout}")
                    if output_file.read_bytes() != payload:
                        raise RuntimeError(f"valid {label} #{repeat}: attached data changed")
                    counts["CKR_OK"] += 1
                else:
                    errors = ("CKR_SIGNATURE_INVALID", "CKR_DATA_INVALID", "CKR_ARGUMENTS_BAD")
                    matched = next((code for code in errors if code in result.stdout), None)
                    if result.returncode != 1 or not matched:
                        raise RuntimeError(f"invalid {label} #{repeat}: exit {result.returncode}: {result.stdout}")
                    if output_file.exists():
                        raise RuntimeError(f"invalid {label} #{repeat}: unverified data was written")
                    counts[matched] += 1

        if args.spy:
            log = root / "spy.log"
            changed = bytearray(valid)
            changed[-10] ^= 0xff
            (root / "test.p7").write_bytes(changed)
            env = os.environ.copy()
            env["PKCS11SPY"] = str(args.stub)
            env["PKCS11SPY_OUTPUT"] = str(log)
            env["RUTOKEN_STUB_PARTIAL_VERIFY_OUTPUTS"] = "1"
            result = call(args.tool, args.spy, [*login,
                "--rutoken-pkcs7-verify", "--input-file", str(root / "test.p7"),
                "--rutoken-verify-flag", "check-signature-only"], env)
            trace = log.read_text(encoding="utf-8", errors="replace")
            if result.returncode != 1 or "CKR_SIGNATURE_INVALID" not in result.stdout:
                raise RuntimeError(f"partial output error: exit {result.returncode}: {result.stdout}")
            if not re.search(r"\d+: C_Finalize\r?\n.*?Returned:\s+0 CKR_OK", trace, re.S):
                raise RuntimeError("partial output buffers were not released before C_Finalize")
            counts["partial-output-error"] += 1

            detached_file = root / "detached.p7"
            signed = call(args.tool, args.stub, [*login, "--rutoken-pkcs7-sign",
                "--id", "0102", "--rutoken-detached", "--input-file", str(input_file),
                "--output-file", str(detached_file)], os.environ.copy())
            if signed.returncode != 0:
                raise RuntimeError(f"synthetic detached signing failed: {signed.stdout}")
            env.pop("RUTOKEN_STUB_PARTIAL_VERIFY_OUTPUTS")
            env["RUTOKEN_STUB_FAIL_VERIFY_UPDATE"] = "1"
            env["PKCS11SPY_OUTPUT"] = str(root / "update-spy.log")
            result = call(args.tool, args.spy, [*login, "--rutoken-pkcs7-verify",
                "--input-file", str(detached_file), "--rutoken-data-file", str(input_file),
                "--rutoken-verify-flag", "check-signature-only"], env)
            trace = (root / "update-spy.log").read_text(encoding="utf-8", errors="replace")
            if result.returncode != 1 or "C_EX_PKCS7VerifyUpdate" not in result.stdout \
                    or "CKR_DATA_INVALID" not in result.stdout:
                raise RuntimeError(f"detached update error: exit {result.returncode}: {result.stdout}")
            if not re.search(r"\d+: C_Finalize\r?\n.*?Returned:\s+0 CKR_OK", trace, re.S):
                raise RuntimeError("VerifyFinal buffers were not released after failed update")
            counts["update-error"] += 1

        print(f"PASS: {len(cases)} synthetic envelope variants, {args.runs} repeats each, "
              f"{sum(counts.values())} checks, 0 crashes; return codes: {dict(counts)}")


if __name__ == "__main__":
    main()
