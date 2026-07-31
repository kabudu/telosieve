#!/usr/bin/env python3
"""Exercise the real OpenTofu plan adapter without external providers."""

import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOFU = shutil.which("tofu")


def run(command: list[str], cwd: pathlib.Path, *, success: bool = True) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(command, cwd=cwd, capture_output=True, check=False)
    if (result.returncode == 0) != success:
        raise SystemExit(
            f"opentofu-e2e: unexpected exit {result.returncode}: {' '.join(command)}\n"
            f"{result.stdout.decode(errors='replace')}{result.stderr.decode(errors='replace')}"
        )
    return result


def config(directory: pathlib.Path, plan: pathlib.Path, stem: str) -> pathlib.Path:
    path = directory / f"{stem}-evaluation.json"
    path.write_text(json.dumps({
        "schema_version": "telosieve.evaluation-config/v3",
        "mode": "opentofu-plan",
        "scenario_path": str((ROOT / "scenarios/benign.json").resolve()),
        "plan_path": str(plan.resolve()),
        "certificate_path": str((directory / f"{stem}-certificate.json").resolve()),
        "ledger_path": str((directory / f"{stem}-ledger.jsonl").resolve()),
    }))
    return path


def main() -> None:
    if TOFU is None:
        raise SystemExit("opentofu-e2e: tofu executable is required")
    binary = ROOT / "target/debug/telosieve"
    if not binary.exists():
        raise SystemExit("opentofu-e2e: build target/debug/telosieve first")
    with tempfile.TemporaryDirectory(prefix="telosieve-opentofu-") as raw:
        directory = pathlib.Path(raw)
        shutil.copy2(ROOT / "examples/opentofu/main.tf", directory / "main.tf")
        run([TOFU, "init", "-backend=false", "-input=false"], directory)
        run([TOFU, "apply", "-auto-approve", "-input=false", "-var=message=old"], directory)
        run([TOFU, "plan", "-input=false", "-var=message=new", "-out=update.tfplan"], directory)
        shown = run([TOFU, "show", "-json", "update.tfplan"], directory).stdout
        plan_path = directory / "update.json"
        plan_path.write_bytes(shown)

        evaluation = run([str(binary), "evaluate", str(config(directory, plan_path, "valid"))], directory)
        report = json.loads(evaluation.stdout)
        certificate = json.loads((directory / "valid-certificate.json").read_bytes())
        record = certificate["opentofu"]
        if report["mode"] != "opentofu-plan" or report["target_mutated"] is not False:
            raise SystemExit("opentofu-e2e: evaluation report is invalid")
        if record["plan_sha256"] != hashlib.sha256(shown).hexdigest() or record["resource_change_count"] != 3:
            raise SystemExit("opentofu-e2e: certificate does not bind the exact three-resource plan")

        destructive = json.loads(shown)
        destructive["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
        destructive_path = directory / "destructive.json"
        destructive_path.write_text(json.dumps(destructive))
        run([str(binary), "evaluate", str(config(directory, destructive_path, "destructive"))], directory, success=False)
        if (directory / "destructive-certificate.json").exists():
            raise SystemExit("opentofu-e2e: destructive plan emitted evidence")

        tampered = json.loads(shown)
        tampered["resource_changes"][0]["change"]["after"]["input"]["values"]["user/message"] = "tampered"
        tampered_path = directory / "tampered.json"
        tampered_path.write_text(json.dumps(tampered))
        run([str(binary), "evaluate", str(config(directory, tampered_path, "tampered"))], directory, success=False)
        if (directory / "tampered-certificate.json").exists():
            raise SystemExit("opentofu-e2e: authority-mismatched plan emitted evidence")

        print(f"opentofu-e2e: passed tofu={record['terraform_version']} plan_sha256={record['plan_sha256']}")


if __name__ == "__main__":
    main()
