#!/usr/bin/env python3
"""Run Rutoken privilege scenarios without prompts on a disposable token.

The companion C probe handles combinations that pkcs11-tool rejects before
calling the module. Raw output and PINs are not written to the report.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path


class ScenarioError(RuntimeError):
    pass


def write_private(path, value):
    temporary = path.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    temporary.replace(path)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generated_pins(stderr):
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", "replace")
    pins = {}
    for role in ("SO", "user"):
        match = re.search(r"new " + role + r" PIN\s*:\s*(\S+)", stderr or "")
        if match:
            pins[role.lower()] = match.group(1)
    return pins


class Runner:
    def __init__(self, args):
        self.args = args
        self.env = os.environ.copy()
        self.env["RT_ACTIVE_SO_PIN"] = self.env["RT_SO_PIN"]
        self.env["RT_ACTIVE_USER_PIN"] = self.env["RT_USER_PIN"]
        self.report = {"version": 1, "case": args.case, "slot": args.slot,
                       "status": "running", "steps": [],
                       "tool_sha256": sha256(args.tool),
                       "module_sha256": sha256(args.module),
                       "helper_sha256": sha256(args.helper)}
        self.save()

    def save(self):
        write_private(self.args.output / "report.json", self.report)

    def invoke(self, name, command, probe=False, capture=False):
        try:
            process = subprocess.run(
                command, env=self.env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, errors="replace", timeout=self.args.timeout)
        except subprocess.TimeoutExpired as exc:
            if name == "repair.generated.call":
                pins = generated_pins(exc.stderr)
                if pins:
                    write_private(self.args.output / "generated-pins.json", pins)
            raise ScenarioError(f"{name}: timed out") from exc
        try:
            data = json.loads(process.stdout)
        except json.JSONDecodeError:
            data = None
        rv = data.get("rv") if probe and isinstance(data, dict) else None
        stage = data.get("stage") if probe and isinstance(data, dict) else None
        if not probe and isinstance(data, dict):
            for value in data.values():
                if isinstance(value, dict) and isinstance(value.get("error"), dict):
                    rv = value["error"].get("rv")
                    stage = value["error"].get("function")
                    break
        if rv is None:
            rv = "CKR_OK" if process.returncode == 0 else "CLI_REJECTED_OR_FAILED"
        row = {"name": name, "source": "probe" if probe else "pkcs11-tool",
               "exit_code": process.returncode, "stage": stage, "rv": rv}
        if probe and isinstance(data, dict):
            row["code"] = data.get("code")
            for key in ("model_hex", "hardware", "firmware",
                        "module_version", "object_count"):
                if key in data:
                    row[key] = data[key]
        self.report["steps"].append(row)
        self.save()
        print(f"{name}: {stage or row['source']} -> {rv}", flush=True)
        if probe and (process.returncode or not isinstance(data, dict)):
            raise ScenarioError(f"{name}: direct probe failed")
        return row, data, process.stderr if capture else None

    def cli(self, name, *options, capture=False):
        return self.invoke(
            name, [str(self.args.tool), "--module", str(self.args.module),
                   "--slot", str(self.args.slot), *options], capture=capture)

    def probe(self, name, operation, role="none", access="rw", value=None):
        pin_env = {"none": "-", "user": "RT_ACTIVE_USER_PIN",
                   "so": "RT_ACTIVE_SO_PIN"}[role]
        command = [str(self.args.helper), str(self.args.module),
                   str(self.args.slot), operation, role, access, pin_env]
        if value is not None:
            command.append(str(value))
        row, data, _ = self.invoke(name, command, probe=True)
        return row, data

    def info(self, name):
        row, data, _ = self.cli(name, "--rutoken-info", "--rutoken-name",
                                "--rutoken-json")
        if row["exit_code"] or not isinstance(data, dict) or "info" not in data:
            raise ScenarioError(f"{name}: token information unavailable")
        info = data["info"]
        if info.get("serial", "").lower() != self.args.expected_serial.lower():
            raise ScenarioError(f"{name}: selected token serial changed")
        row["observed"] = {key: info.get(key) for key in (
            "token_type_name", "microcode", "flag_names",
            "admin_retries_left", "admin_retries_max", "user_retries_left")}
        row["observed"]["serial_sha256"] = hashlib.sha256(
            info["serial"].encode("ascii")).hexdigest()
        label = data.get("name", {}).get("label", "")
        row["observed"]["name_utf8_bytes"] = len(label.encode("utf-8"))
        self.save()
        return data

    def login(self, name, role, pin=None):
        key = "RT_ACTIVE_SO_PIN" if role == "so" else "RT_ACTIVE_USER_PIN"
        if pin is not None:
            key = "RT_CHECK_PIN"
            self.env[key] = pin
        return self.cli(name, "--test-login", "--login", "--login-type", role,
                        "--so-pin" if role == "so" else "--pin", "env:" + key)[0]

    def initialize(self, name, policy):
        row, _, _ = self.cli(
            name, "--rutoken-init-token", "--so-pin", "env:RT_ACTIVE_SO_PIN",
            "--rutoken-new-so-pin", "env:RT_NEW_SO_PIN",
            "--new-pin", "env:RT_NEW_USER_PIN",
            "--rutoken-user-pin-policy", policy,
            "--label", "OpenSC privilege probe", "--rutoken-json")
        if row["exit_code"]:
            raise ScenarioError(f"{name}: formatting failed")
        self.env["RT_ACTIVE_SO_PIN"] = self.env["RT_NEW_SO_PIN"]
        self.env["RT_ACTIVE_USER_PIN"] = self.env["RT_NEW_USER_PIN"]
        self.info(name + ".after")
        for role in ("so", "user"):
            if self.login(name + "." + role + "_login", role)["exit_code"]:
                raise ScenarioError(f"{name}: new {role} PIN does not work")

    def manage(self):
        for policy in ("user", "admin", "both"):
            prefix = "manage." + policy
            self.initialize(prefix + ".init", policy)
            so = ("--login", "--login-type", "so", "--so-pin",
                  "env:RT_ACTIVE_SO_PIN")
            row, _, _ = self.cli(prefix + ".default", *so,
                                  "--rutoken-token-manage", "default-user-pin",
                                  "--new-pin", "env:RT_DEFAULT_USER_PIN",
                                  "--rutoken-json")
            if row["exit_code"]:
                raise ScenarioError(f"{prefix}: cannot set test default PIN")
            self.cli(prefix + ".cli_user", "--login", "--pin",
                     "env:RT_ACTIVE_USER_PIN", "--rutoken-token-manage",
                     "reset-user-pin")
            self.probe(prefix + ".none_rw", "reset-user-pin")
            user_row, _ = self.probe(prefix + ".user_rw", "reset-user-pin",
                                     "user", "rw")
            self.probe(prefix + ".so_ro", "reset-user-pin", "so", "ro")
            so_row, _, _ = self.cli(prefix + ".so_rw", *so,
                                    "--rutoken-token-manage", "reset-user-pin",
                                    "--rutoken-json")
            if user_row["rv"] == "CKR_OK" or so_row["rv"] == "CKR_OK":
                check = self.login(prefix + ".default_login", "user",
                                   self.env["RT_DEFAULT_USER_PIN"])
                if check["exit_code"]:
                    raise ScenarioError(f"{prefix}: reset succeeded but PIN did not change")
                self.env["RT_ACTIVE_USER_PIN"] = self.env["RT_DEFAULT_USER_PIN"]
            self.info(prefix + ".after")

    def license(self):
        free_slot = None
        for number in range(1, 5):
            row, data, _ = self.cli(f"license.slot_{number}",
                                    "--rutoken-license", str(number),
                                    "--rutoken-json")
            if (not row["exit_code"] and isinstance(data, dict) and
                    data.get("license", {}).get("empty")):
                free_slot = number
                break
        if free_slot is None:
            self.report["steps"].append({"name": "license", "rv": "NOT_TESTED",
                                         "reason": "no empty license slot"})
            self.report["incomplete"] = True
            self.save()
            return
        test_file = self.args.output / "license-test.bin"
        test_file.write_bytes(b"P" * 72)
        self.cli("license.cli_no_login", "--rutoken-set-license", str(free_slot),
                 "--input-file", str(test_file))
        self.probe("license.none_rw", "set-license", "none", "rw", free_slot)
        self.probe("license.user_ro", "set-license", "user", "ro", free_slot)
        self.probe("license.so_ro", "set-license", "so", "ro", free_slot)
        row, data, _ = self.cli("license.after", "--rutoken-license",
                                str(free_slot), "--rutoken-json")
        if (row["exit_code"] or not isinstance(data, dict) or
                not data.get("license", {}).get("empty")):
            raise ScenarioError("license: a negative case changed the test slot")

    def name(self):
        baseline = self.info("name.before").get("name", {}).get("label", "")
        if len(baseline.encode("utf-8")) > 255:
            raise ScenarioError("name: original label exceeds 255 bytes; cannot restore it")
        user = ("--login", "--pin", "env:RT_ACTIVE_USER_PIN")
        cases = (("ascii254", "A" * 254), ("ascii255", "A" * 255),
                 ("ascii256", "A" * 256), ("utf8_255", "A" * 253 + "Ж"),
                 ("utf8_256", "A" * 254 + "Ж"))
        try:
            for suffix, value in cases:
                case = "name." + suffix
                row, _, _ = self.cli(case, *user, "--rutoken-set-name", value,
                                      "--rutoken-json")
                if row["exit_code"] == 0:
                    actual = self.info(case + ".read").get("name", {}).get("label")
                    if actual != value:
                        raise ScenarioError(f"{case}: GetTokenName differs")
                    label_row, data = self.probe(case + ".token_label",
                                                  "token-label", "none", "ro")
                    if label_row["rv"] != "CKR_OK" or "label_hex" not in data:
                        raise ScenarioError(f"{case}: C_GetTokenInfo unavailable")
                    label_row["prefix_matches"] = (
                        bytes.fromhex(data["label_hex"]).rstrip(b" \0") ==
                        value.encode("utf-8")[:32].rstrip(b" \0"))
                    self.save()
            self.cli("name.cli_no_login", "--rutoken-set-name", "probe")
            self.probe("name.none_rw", "set-name", "none", "rw", "probe")
            self.probe("name.user_ro", "set-name", "user", "ro", "probe")
            self.cli("name.so_rw", "--login", "--login-type", "so",
                     "--so-pin", "env:RT_ACTIVE_SO_PIN",
                     "--rutoken-set-name", "probe", "--rutoken-json")
        finally:
            row, _, _ = self.cli("name.restore", *user,
                                 "--rutoken-set-name", baseline, "--rutoken-json")
            if row["exit_code"]:
                raise ScenarioError("name: original name could not be restored")
            self.info("name.after")

    def block_so(self, prefix):
        before = self.info(prefix + ".before")["info"]["admin_retries_left"]
        current = self.env["RT_ACTIVE_SO_PIN"]
        wrong = "".join(str(secrets.randbelow(10)) for _ in range(len(current)))
        if wrong == current:
            wrong = ("0" if current[0] != "0" else "1") + wrong[1:]
        self.env["RT_WRONG_SO_PIN"] = wrong
        if not isinstance(before, int) or not 0 <= before <= 15:
            raise ScenarioError(f"{prefix}: invalid SO retry count")
        for attempt in range(before):
            self.cli(f"{prefix}.wrong_{attempt + 1}", "--test-login", "--login",
                     "--login-type", "so", "--so-pin", "env:RT_WRONG_SO_PIN")
            after = self.info(f"{prefix}.retry_{attempt + 1}")["info"]["admin_retries_left"]
            if after >= before - attempt:
                raise ScenarioError(f"{prefix}: wrong PIN did not consume an attempt")
        if self.info(prefix + ".locked")["info"]["admin_retries_left"] != 0:
            raise ScenarioError(f"{prefix}: SO PIN did not lock")

    def repair(self):
        self.probe("repair.before_objects", "object-count", "user", "ro")
        self.block_so("repair.explicit")
        row, _, _ = self.cli(
            "repair.explicit.call", "--rutoken-init-token",
            "--rutoken-repair-mode", "--rutoken-new-so-pin", "env:RT_NEW_SO_PIN",
            "--new-pin", "env:RT_NEW_USER_PIN",
            "--label", "OpenSC privilege probe", "--rutoken-json")
        if row["exit_code"]:
            raise ScenarioError("repair: explicit-PIN repair failed")
        self.env["RT_ACTIVE_SO_PIN"] = self.env["RT_NEW_SO_PIN"]
        self.env["RT_ACTIVE_USER_PIN"] = self.env["RT_NEW_USER_PIN"]
        if self.login("repair.explicit.so_login", "so")["exit_code"]:
            raise ScenarioError("repair: new SO PIN does not work")
        self.probe("repair.explicit.after_objects", "object-count", "user", "ro")
        self.block_so("repair.generated")
        row, _, stderr = self.cli(
            "repair.generated.call", "--rutoken-init-token",
            "--rutoken-repair-mode", "--label", "OpenSC privilege probe",
            "--rutoken-json", capture=True)
        pins = generated_pins(stderr)
        if pins:
            write_private(self.args.output / "generated-pins.json", pins)
        if row["exit_code"] or len(pins) != 2:
            raise ScenarioError("repair: generated-PIN repair failed; inspect private PIN file")
        self.env["RT_ACTIVE_SO_PIN"] = pins["so"]
        self.env["RT_ACTIVE_USER_PIN"] = pins["user"]
        for role in ("so", "user"):
            if self.login("repair.generated." + role + "_login", role)["exit_code"]:
                raise ScenarioError(f"repair: generated {role} PIN does not work")
        self.probe("repair.generated.after_objects", "object-count", "user", "ro")
        self.initialize("repair.restore_known_pins", "both")
        self.probe("repair.restored_objects", "object-count", "user", "ro")
        (self.args.output / "generated-pins.json").unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tool", "module", "helper"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--slot", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--expected-serial", required=True,
                        help="hex serial from --rutoken-info --rutoken-json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=("all", "manage", "license", "name", "repair"),
                        default="all")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.slot < 0 or not re.fullmatch(r"[0-9a-fA-F]+", args.expected_serial):
        parser.error("invalid slot or expected serial")
    for name in ("tool", "module", "helper"):
        path = getattr(args, name).resolve()
        if not path.is_file():
            parser.error(f"{name} does not exist: {path}")
        setattr(args, name, path)
    required = {"RT_SO_PIN", "RT_USER_PIN"}
    if args.case in ("all", "manage", "repair"):
        required |= {"RT_NEW_SO_PIN", "RT_NEW_USER_PIN"}
    if args.case in ("all", "manage"):
        required.add("RT_DEFAULT_USER_PIN")
    missing = sorted(name for name in required if not os.environ.get(name))
    if missing:
        parser.error("missing PIN environment variables: " + ", ".join(missing))
    if args.case in ("all", "manage") and os.environ["RT_DEFAULT_USER_PIN"] == os.environ["RT_NEW_USER_PIN"]:
        parser.error("RT_DEFAULT_USER_PIN must differ from RT_NEW_USER_PIN")
    args.output = args.output.resolve()
    if args.output.exists():
        parser.error("output directory already exists")
    args.output.mkdir(mode=0o700, parents=True)
    runner = Runner(args)
    try:
        runner.info("preflight")
        module, _ = runner.probe("preflight.module", "module-info", "none", "ro")
        if module["rv"] != "CKR_OK" or "module_version" not in module:
            raise ScenarioError("preflight: C_GetInfo unavailable")
        details, data = runner.probe("preflight.details", "token-label", "none", "ro")
        if details["rv"] != "CKR_OK":
            raise ScenarioError("preflight: C_GetTokenInfo unavailable")
        runner.report["device"] = {
            "model": bytes.fromhex(data["model_hex"]).decode("utf-8", "replace").strip(),
            "hardware": data["hardware"], "firmware": data["firmware"]}
        runner.save()
        if args.case != "repair":
            for role in ("so", "user"):
                if runner.login("preflight." + role + "_login", role)["exit_code"]:
                    raise ScenarioError(f"preflight: supplied {role} PIN does not work")
        selected = ("manage", "license", "name", "repair") if args.case == "all" else (args.case,)
        for case in selected:
            getattr(runner, case)()
        runner.report["status"] = "incomplete" if runner.report.get("incomplete") else "complete"
        runner.save()
        return 2 if runner.report.get("incomplete") else 0
    except (ScenarioError, OSError, ValueError) as exc:
        runner.report["status"] = "stopped"
        runner.report["reason"] = str(exc)
        runner.save()
        print(f"STOP: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
