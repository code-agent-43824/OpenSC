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

    def followup(self):
        """Resolve the inconclusive USER reset and standard-label probe cells."""
        baseline = self.info("followup.name.before").get("name", {}).get("label")
        if not isinstance(baseline, str) or len(baseline.encode("utf-8")) > 256:
            raise ScenarioError("followup: original token name cannot be restored")
        self.report["followup"] = {"standard_label": {}, "user_reset": {}}
        self.save()

        def check_standard_label(step, expected):
            row, data = self.probe(step, "token-label", "none", "ro")
            if row["rv"] != "CKR_OK" or not isinstance(data.get("label_hex"), str):
                raise ScenarioError(f"{step}: C_GetTokenInfo unavailable")
            actual = bytes.fromhex(data["label_hex"])
            if len(actual) != 32:
                raise ScenarioError(f"{step}: C_GetTokenInfo label is not 32 bytes")
            row["prefix_matches"] = (actual.rstrip(b" \0") ==
                                     expected.encode("utf-8")[:32].rstrip(b" \0"))
            self.report["followup"]["standard_label"][step.rsplit(".", 1)[-1]] = (
                row["prefix_matches"])
            self.save()

        check_standard_label("followup.name.standard_before", baseline)
        user = ("--login", "--pin", "env:RT_ACTIVE_USER_PIN")
        known_name = "A" * 256
        try:
            row, _, _ = self.cli("followup.name.set_256", *user,
                                 "--rutoken-set-name", known_name, "--rutoken-json")
            if row["exit_code"]:
                raise ScenarioError("followup: cannot set the 256-byte test name")
            actual = self.info("followup.name.read_256").get("name", {}).get("label")
            if actual != known_name:
                raise ScenarioError("followup: GetTokenName differs from the test name")
            check_standard_label("followup.name.standard_256", known_name)
        finally:
            row, _, _ = self.cli("followup.name.restore", *user,
                                 "--rutoken-set-name", baseline, "--rutoken-json")
            if row["exit_code"]:
                raise ScenarioError("followup: original name could not be restored")
            if self.info("followup.name.restored").get("name", {}).get("label") != baseline:
                raise ScenarioError("followup: original name differs after restore")

        formatted = False
        try:
            for policy in ("user", "admin", "both"):
                prefix = "followup.manage." + policy
                formatted = True
                self.initialize(prefix + ".init", policy)
                so = ("--login", "--login-type", "so", "--so-pin",
                      "env:RT_ACTIVE_SO_PIN")
                row, _, _ = self.cli(prefix + ".default", *so,
                                     "--rutoken-token-manage", "default-user-pin",
                                     "--new-pin", "env:RT_DEFAULT_USER_PIN",
                                     "--rutoken-json")
                if row["exit_code"]:
                    raise ScenarioError(f"{prefix}: cannot set the test default PIN")
                self.info(prefix + ".before_reset")
                reset, _ = self.probe(prefix + ".user_rw", "reset-user-pin",
                                      "user", "rw")
                default_login = self.login(prefix + ".default_login", "user",
                                           self.env["RT_DEFAULT_USER_PIN"])
                if default_login["exit_code"] == 0:
                    pin_after = "default"
                    self.env["RT_ACTIVE_USER_PIN"] = self.env["RT_DEFAULT_USER_PIN"]
                elif self.login(prefix + ".new_login", "user",
                                self.env["RT_NEW_USER_PIN"])["exit_code"] == 0:
                    pin_after = "new"
                    self.env["RT_ACTIVE_USER_PIN"] = self.env["RT_NEW_USER_PIN"]
                else:
                    raise ScenarioError(f"{prefix}: neither known USER PIN works")
                reset["pin_after"] = pin_after
                self.report["followup"]["user_reset"][policy] = {
                    "rv": reset["rv"], "code": reset.get("code"),
                    "pin_after": pin_after}
                self.save()
                self.info(prefix + ".after_reset")
        finally:
            if formatted:
                self.initialize("followup.restore.init", "both")
                row, _, _ = self.cli("followup.restore.name", *user,
                                     "--rutoken-set-name", baseline,
                                     "--rutoken-json")
                if row["exit_code"]:
                    raise ScenarioError("followup: original name could not be restored")
                if self.info("followup.restore.after").get("name", {}).get("label") != baseline:
                    raise ScenarioError("followup: original name differs after restore")
                self.report["followup"]["restored_known_pins_and_name"] = True
                self.save()

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

    def closure(self):
        """One physical run for the remaining privilege and repair questions."""
        baseline = self.info("closure.baseline").get("name", {}).get("label")
        if not isinstance(baseline, str) or len(baseline.encode("utf-8")) > 4096:
            raise ScenarioError("closure: original name cannot be restored")
        self.report["closure"] = {"baseline_name_bytes": len(baseline.encode("utf-8")),
                                  "name_boundary": {}, "repair": {}}
        self.save()
        user = ("--login", "--pin", "env:RT_ACTIVE_USER_PIN")
        so = ("--login", "--login-type", "so", "--so-pin",
              "env:RT_ACTIVE_SO_PIN")

        def count(name, role="user", access="ro"):
            row, _ = self.probe(name, "object-count", role, access)
            if row["rv"] != "CKR_OK" or not isinstance(row.get("object_count"), int):
                raise ScenarioError(f"{name}: cannot count USER-visible objects")
            return row["object_count"]

        if count("closure.objects.preflight") != 0:
            raise ScenarioError("closure: token contains USER-visible objects; use an empty disposable token")
        if count("closure.objects.preflight_public", "none", "ro") != 0:
            raise ScenarioError("closure: token contains public objects; use an empty disposable token")
        if count("closure.objects.preflight_so", "so", "rw") != 0:
            raise ScenarioError("closure: token contains SO-visible objects; use an empty disposable token")
        if self.env["RT_DEFAULT_USER_PIN"] in (
                self.env["RT_ACTIVE_USER_PIN"], self.env["RT_NEW_USER_PIN"]):
            raise ScenarioError("closure: RT_DEFAULT_USER_PIN must differ from current and new USER PIN")

        # All negative calls precede formatting. A surprising success stops the run.
        for role, access in (("none", "rw"), ("none", "ro"),
                             ("user", "ro"), ("so", "ro")):
            name = f"closure.mode4.{role}_{access}"
            row, _ = self.probe(name, "reset-user-pin", role, access)
            if row["rv"] == "CKR_OK":
                raise ScenarioError(f"{name}: unexpectedly reset the USER PIN")
        if self.login("closure.mode4.user_still_valid", "user")["exit_code"]:
            raise ScenarioError("closure: negative mode 4 calls changed the USER PIN")

        free_slot = None
        for number in range(1, 5):
            row, data, _ = self.cli(f"closure.license.slot_{number}",
                                    "--rutoken-license", str(number),
                                    "--rutoken-json")
            if (not row["exit_code"] and isinstance(data, dict) and
                    data.get("license", {}).get("empty")):
                free_slot = number
                break
        self.report["closure"]["free_license_slot"] = free_slot
        self.save()
        if free_slot is None:
            self.report["incomplete"] = True
            self.report["closure"]["license_status"] = "no_empty_slot"
            self.save()
        else:
            dummy = self.args.output / "license-test.bin"
            dummy.write_bytes(b"P" * 72)

            def slot_is_empty(name):
                row, data, _ = self.cli(name, "--rutoken-license",
                                        str(free_slot), "--rutoken-json")
                if (row["exit_code"] or not isinstance(data, dict) or
                        not data.get("license", {}).get("empty")):
                    raise ScenarioError(f"{name}: test license slot changed")

            try:
                row, _, _ = self.cli("closure.license.cli_none", "--rutoken-set-license",
                                     str(free_slot), "--input-file", str(dummy),
                                     "--rutoken-json")
                if row["exit_code"] == 0:
                    raise ScenarioError("closure: no-login CLI unexpectedly set a license")
                slot_is_empty("closure.license.after_cli")
                for role, access in (("none", "rw"), ("user", "ro"), ("so", "ro")):
                    name = f"closure.license.{role}_{access}"
                    row, _ = self.probe(name, "set-license", role, access,
                                        free_slot)
                    if row["rv"] == "CKR_OK":
                        raise ScenarioError(f"{name}: unexpectedly set a license")
                    slot_is_empty(name + ".after")
                self.report["closure"]["license_status"] = "negative_cases_complete"
                self.save()
            finally:
                dummy.unlink(missing_ok=True)

        # Find the first rejected length, up to 4096 bytes, and verify that
        # rejected calls leave the previous name untouched.
        current_name = baseline
        accepted = 256
        rejected = None
        def try_name(length):
            nonlocal current_name
            value = "A" * length
            step = f"closure.name.bytes_{length}"
            row, _, _ = self.cli(step, *user, "--rutoken-set-name", value,
                                 "--rutoken-json")
            actual = self.info(step + ".read").get("name", {}).get("label")
            if row["exit_code"] == 0:
                if actual != value:
                    raise ScenarioError(f"{step}: successful write returned a different name")
                current_name = value
                return True
            if actual != current_name:
                raise ScenarioError(f"{step}: rejected CLI write changed the name")
            # Distinguish a CLI limit from the physical module's limit.
            direct, _ = self.probe(step + ".direct", "set-name", "user", "rw",
                                   value)
            if direct["rv"] == "CKR_OK":
                if self.info(step + ".direct_read").get("name", {}).get("label") != value:
                    raise ScenarioError(f"{step}: direct write returned a different name")
                self.report["closure"]["name_boundary"].setdefault(
                    "cli_rejected_module_accepted_bytes", []).append(length)
                self.save()
                current_name = value
                return True
            if self.info(step + ".direct_rejected_read").get(
                    "name", {}).get("label") != current_name:
                raise ScenarioError(f"{step}: rejected write changed the name")
            return False

        try:
            if not try_name(256):
                raise ScenarioError("closure: previously accepted 256-byte name was rejected")
            for length in (257, 512, 1024, 2048, 4096):
                if try_name(length):
                    accepted = length
                else:
                    rejected = length
                    break
            if rejected is not None:
                while rejected - accepted > 1:
                    middle = (accepted + rejected) // 2
                    if try_name(middle):
                        accepted = middle
                    else:
                        rejected = middle
            self.report["closure"]["name_boundary"].update({
                "highest_confirmed_accepted_bytes": accepted,
                "first_confirmed_rejected_bytes": rejected,
                "search_cap_bytes": 4096})
            self.save()
            for role, access in (("none", "rw"), ("user", "ro"), ("so", "rw")):
                step = f"closure.name.{role}_{access}"
                row, _ = self.probe(step, "set-name", role, access, "probe")
                if row["rv"] == "CKR_OK":
                    raise ScenarioError(f"{step}: unexpectedly changed the name")
                if self.info(step + ".read").get("name", {}).get("label") != current_name:
                    raise ScenarioError(f"{step}: negative call changed the name")
        finally:
            row, _, _ = self.cli("closure.name.restore", *user,
                                 "--rutoken-set-name", baseline, "--rutoken-json")
            if row["exit_code"] or self.info("closure.name.restored").get(
                    "name", {}).get("label") != baseline:
                raise ScenarioError("closure: original name could not be restored")

        # Fix the policy at both before checking the corrected CLI. There are
        # no USER-visible objects to destroy at this point.
        self.initialize("closure.policy_both", "both")
        row, _, _ = self.cli("closure.mode4.set_test_default", *so,
                             "--rutoken-token-manage", "default-user-pin",
                             "--new-pin", "env:RT_DEFAULT_USER_PIN", "--rutoken-json")
        if row["exit_code"]:
            raise ScenarioError("closure: cannot set test default USER PIN")
        row, _, _ = self.cli("closure.mode4.cli_user_rw", *user,
                             "--rutoken-token-manage", "reset-user-pin",
                             "--rutoken-json")
        if row["exit_code"]:
            raise ScenarioError("closure: corrected CLI rejected USER/RW reset")
        if self.login("closure.mode4.default_login", "user",
                      self.env["RT_DEFAULT_USER_PIN"])["exit_code"]:
            raise ScenarioError("closure: USER reset succeeded but default PIN does not work")
        self.env["RT_ACTIVE_USER_PIN"] = self.env["RT_DEFAULT_USER_PIN"]
        self.info("closure.mode4.after")

        marker = self.args.output / "repair-marker.bin"
        marker.write_bytes(b"OpenSC disposable repair marker\n")
        try:
            row, _, _ = self.cli("closure.repair.create_object", *user,
                                 "--write-object", str(marker), "--type", "data",
                                 "--id", "eec10a22", "--label", "OpenSC repair marker")
            if row["exit_code"]:
                raise ScenarioError("closure: cannot create repair test object")
            before = count("closure.repair.objects_before")
            if before < 1:
                raise ScenarioError("closure: repair test object is not visible")
            self.report["closure"]["repair"]["objects_before"] = before
            self.save()
            self.block_so("closure.repair.block_so")
            row, _, _ = self.cli("closure.repair.call", "--rutoken-init-token",
                                 "--rutoken-repair-mode",
                                 "--rutoken-new-so-pin", "env:RT_NEW_SO_PIN",
                                 "--new-pin", "env:RT_NEW_USER_PIN",
                                 "--rutoken-user-pin-policy", "both",
                                 "--label", "OpenSC privilege probe", "--rutoken-json")
            if row["exit_code"]:
                raise ScenarioError("closure: explicit-PIN repair failed")
            self.env["RT_ACTIVE_SO_PIN"] = self.env["RT_NEW_SO_PIN"]
            self.env["RT_ACTIVE_USER_PIN"] = self.env["RT_NEW_USER_PIN"]
            # Check both PINs immediately after this repair, before any format.
            for role in ("user", "so"):
                if self.login("closure.repair." + role + "_login", role)["exit_code"]:
                    raise ScenarioError(f"closure: new {role} PIN does not work")
            after = count("closure.repair.objects_after")
            after_so = count("closure.repair.objects_after_so", "so", "rw")
            self.report["closure"]["repair"]["objects_after"] = after
            self.report["closure"]["repair"]["objects_after_so"] = after_so
            self.save()
            if after != 0 or after_so != 0:
                raise ScenarioError("closure: repair did not remove the test object")
            row, _, _ = self.cli("closure.restore.name", *user,
                                 "--rutoken-set-name", baseline, "--rutoken-json")
            if row["exit_code"] or self.info("closure.final").get(
                    "name", {}).get("label") != baseline:
                raise ScenarioError("closure: original name could not be restored after repair")
            self.report["closure"]["repair"]["known_pins_and_name_restored"] = True
            self.save()
        finally:
            marker.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tool", "module", "helper"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--slot", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--expected-serial", required=True,
                        help="hex serial from --rutoken-info --rutoken-json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=("all", "manage", "license", "name", "repair", "followup", "closure"),
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
    if args.case in ("all", "manage", "repair", "followup", "closure"):
        required |= {"RT_NEW_SO_PIN", "RT_NEW_USER_PIN"}
    if args.case in ("all", "manage", "followup", "closure"):
        required.add("RT_DEFAULT_USER_PIN")
    missing = sorted(name for name in required if not os.environ.get(name))
    if missing:
        parser.error("missing PIN environment variables: " + ", ".join(missing))
    if args.case in ("all", "manage", "followup", "closure") and os.environ["RT_DEFAULT_USER_PIN"] == os.environ["RT_NEW_USER_PIN"]:
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
