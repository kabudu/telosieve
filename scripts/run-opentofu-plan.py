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


def observation_material(directory, binary, plan, stem):
    specifications = (("producer-a", "key-a", "plan-reader-a", "0d" * 32),
                      ("producer-b", "key-b", "plan-reader-b", "0e" * 32))
    keys, sources = [], []
    for producer, key_id, domain, seed in specifications:
        key = directory / f"{stem}-{producer}.key"
        key.write_text(seed); key.chmod(0o600)
        public = run([str(binary), "observation-public-key", str(key)], directory).stdout.decode().strip()
        attestation = directory / f"{stem}-{producer}.attestation.json"
        run([str(binary), "observation-sign", str(plan.resolve()), str(key), "kv/research",
             "opentofu-plan", producer, key_id, domain, "1788000000", "1788000300",
             str(attestation)], directory)
        envelope = directory / f"{stem}-{producer}.envelope.json"
        envelope.write_text(json.dumps({"schema_version": "telosieve.observation-source/v1",
            "input_hex": plan.read_bytes().hex(), "attestation": json.loads(attestation.read_bytes())},
            separators=(",", ":")))
        sources.append({"executable_path": "/bin/cat", "arguments": [str(envelope)]})
        keys.append({"producer": producer, "key_id": key_id, "fault_domain": domain,
                     "public_key": public, "not_before": 1788000000, "not_after": 1800000000})
    trust = directory / f"{stem}-trust.json"
    trust.write_text(json.dumps({"schema_version": "telosieve.observation-trust/v1",
        "evaluation_time": 1788000100, "required_distinct_domains": 2, "keys": keys},
        separators=(",", ":")))
    return trust, sources


def config(directory: pathlib.Path, binary: pathlib.Path, plan: pathlib.Path, stem: str) -> pathlib.Path:
    trust, sources = observation_material(directory, binary, plan, stem)
    path = directory / f"{stem}-evaluation.json"
    path.write_text(json.dumps({
        "schema_version": "telosieve.evaluation-config/v6",
        "mode": "opentofu-plan",
        "scenario_path": str((ROOT / "scenarios/benign.json").resolve()),
        "plan_path": str(plan.resolve()),
        "certificate_path": str((directory / f"{stem}-certificate.json").resolve()),
        "ledger_path": str((directory / f"{stem}-ledger.jsonl").resolve()),
        "observation_trust_path": str(trust.resolve()),
        "observation_sources": sources,
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

        valid_config = config(directory, binary, plan_path, "valid")
        evaluation = run([str(binary), "evaluate", str(valid_config)], directory)
        report = json.loads(evaluation.stdout)
        certificate = json.loads((directory / "valid-certificate.json").read_bytes())
        record = certificate["opentofu"]
        if report["mode"] != "opentofu-plan" or report["target_mutated"] is not False:
            raise SystemExit("opentofu-e2e: evaluation report is invalid")
        if record["plan_sha256"] != hashlib.sha256(shown).hexdigest() or record["resource_change_count"] != 3:
            raise SystemExit("opentofu-e2e: certificate does not bind the exact three-resource plan")
        if not isinstance(record.get("observation_quorum_digest"), str):
            raise SystemExit("opentofu-e2e: certificate lacks observation quorum binding")

        envelope_path = directory / "valid-producer-a.envelope.json"
        original_envelope = envelope_path.read_bytes()
        for fault in ("forged", "disagreement"):
            envelope = json.loads(original_envelope)
            if fault == "forged":
                envelope["attestation"]["signature"] = "00" * 64
            else:
                envelope["input_hex"] = (shown + b" ").hex()
            envelope_path.write_text(json.dumps(envelope, separators=(",", ":")))
            (directory / "valid-certificate.json").unlink(missing_ok=True)
            (directory / "valid-ledger.jsonl").unlink(missing_ok=True)
            run([str(binary), "evaluate", str(valid_config)], directory, success=False)
            if (directory / "valid-certificate.json").exists() or (directory / "valid-ledger.jsonl").exists():
                raise SystemExit(f"opentofu-e2e: {fault} producer emitted evidence")
        envelope_path.write_bytes(original_envelope)

        destructive = json.loads(shown)
        destructive["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
        destructive_path = directory / "destructive.json"
        destructive_path.write_text(json.dumps(destructive))
        run([str(binary), "evaluate", str(config(directory, binary, destructive_path, "destructive"))], directory, success=False)
        if (directory / "destructive-certificate.json").exists():
            raise SystemExit("opentofu-e2e: destructive plan emitted evidence")

        tampered = json.loads(shown)
        tampered["resource_changes"][0]["change"]["after"]["input"]["values"]["user/message"] = "tampered"
        tampered_path = directory / "tampered.json"
        tampered_path.write_text(json.dumps(tampered))
        run([str(binary), "evaluate", str(config(directory, binary, tampered_path, "tampered"))], directory, success=False)
        if (directory / "tampered-certificate.json").exists():
            raise SystemExit("opentofu-e2e: authority-mismatched plan emitted evidence")

        print(f"opentofu-e2e: passed tofu={record['terraform_version']} plan_sha256={record['plan_sha256']}")


if __name__ == "__main__":
    main()
