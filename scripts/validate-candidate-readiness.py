#!/usr/bin/env python3
"""Validate candidate pre-freeze claims against repository evidence and CI."""

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "evaluation/candidate-readiness.json"
CONTRACT = ROOT / "evaluation/contract.json"
RESULT = ROOT / "results/candidate-readiness-validation.json"
MAX_BYTES = 128 * 1024
EXPECTED_RESULT = {
    "schema_version": "telosieve.candidate-prefreeze-readiness-validation/v1",
    "gates": 8, "locally_verified": 7, "pending_freeze": 1,
    "refusals": 7, "status": "passed",
}
EXPECTED_EVIDENCE = {
    "bounded-and-versioned-cli-configuration": (
        ["docs/EVALUATION_CLI.md", "tests/evaluation_cli.rs"],
        ["cargo test --locked --offline --all-targets --all-features"],
    ),
    "fail-closed-live-read-only-integration": (
        ["deploy/kubernetes/evaluation-rbac.yaml", "docs/KUBERNETES_REAL_CLUSTER.md", "scripts/run-kubernetes-real-cluster.py"],
        ["python3 scripts/run-kubernetes-real-cluster.py"],
    ),
    "install-upgrade-rollback-and-uninstall-procedure": (
        ["docs/EVALUATION_LIFECYCLE.md", "scripts/evaluation-lifecycle.py", "scripts/run-evaluation-lifecycle-qualification.py"],
        ["python3 scripts/run-evaluation-lifecycle-qualification.py"],
    ),
    "least-privilege-and-secret-free-defaults": (
        ["deploy/kubernetes/evaluation-rbac.yaml", "docs/PRODUCER_ISOLATION.md", "evaluation/config.live.example.json", "scripts/qualify-linux-producer-isolation.sh"],
        ["./scripts/qualify-linux-producer-isolation.sh", "python3 scripts/run-kubernetes-real-cluster.py"],
    ),
    "operator-diagnostics-and-evidence-export": (
        ["docs/OPERATOR_DIAGNOSTICS.md", "scripts/evaluation-diagnostics.py", "scripts/run-diagnostics-qualification.py"],
        ["python3 scripts/run-diagnostics-qualification.py"],
    ),
    "platform-resource-and-recovery-qualification": (
        ["docs/BUILD_PROVENANCE.md", "docs/SUSTAINED_ADVERSARIAL_LOAD.md", "scripts/run-reproducible-build-qualification.py", "scripts/run-sustained-adversarial-load.py"],
        ["python3 scripts/run-reproducible-build-qualification.py", "python3 scripts/run-sustained-adversarial-load.py"],
    ),
    "signed-checksummed-reproducible-private-bundle": (
        ["docs/CANDIDATE_SIGNING.md", "docs/PRIVATE_BUNDLE.md", "scripts/build-private-bundle.py", "scripts/build-release-candidate.py", "scripts/run-private-bundle-qualification.py", "scripts/run-release-candidate-qualification.py", "scripts/verify-release-candidate.py"],
        ["python3 scripts/run-private-bundle-qualification.py", "python3 scripts/run-release-candidate-qualification.py"],
    ),
    "threat-model-runbook-and-known-limitations": (
        ["docs/OPERATIONS.md", "docs/RISK_REGISTER.md", "docs/THREAT_MODEL.md"],
        ["python3 scripts/validate-project.py"],
    ),
}


def strict_json(path: Path, label: str):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError(f"invalid {label} file")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate {label} field {key}")
            value[key] = item
        return value

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def validate(manifest, contract, *, check_files: bool) -> None:
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "authority_boundary", "repository_visibility",
        "authoritative_ci", "gates",
    }:
        raise ValueError("candidate readiness fields are invalid")
    if (
        manifest["schema_version"] != "telosieve.candidate-prefreeze-readiness/v1"
        or manifest["authority_boundary"] != "read-only-no-target-mutation"
        or manifest["repository_visibility"] != "private"
        or manifest["authoritative_ci"] != "./scripts/ci-local.sh"
    ):
        raise ValueError("candidate readiness policy boundary changed")
    gates = manifest["gates"]
    expected_gates = contract.get("candidate_readiness_gates")
    if not isinstance(gates, list) or not isinstance(expected_gates, list):
        raise ValueError("candidate readiness gates are invalid")
    if [item.get("gate") for item in gates if isinstance(item, dict)] != expected_gates:
        raise ValueError("candidate readiness gates do not exactly match the contract")
    ci = (ROOT / "scripts/ci-local.sh").read_text(encoding="utf-8") if check_files else ""
    for item in gates:
        if not isinstance(item, dict) or set(item) != {
            "gate", "status", "evidence_paths", "validation_commands",
        }:
            raise ValueError("candidate readiness gate shape is invalid")
        expected_status = (
            "pending-freeze" if item["gate"] == "signed-checksummed-reproducible-private-bundle"
            else "locally-verified"
        )
        if item["status"] != expected_status:
            raise ValueError(f"candidate readiness status is invalid for {item['gate']}")
        paths, commands = item["evidence_paths"], item["validation_commands"]
        if (
            not isinstance(paths, list) or not paths or paths != sorted(set(paths))
            or not isinstance(commands, list) or not commands or commands != sorted(set(commands))
            or any(not isinstance(value, str) or not value for value in [*paths, *commands])
        ):
            raise ValueError(f"candidate readiness evidence is invalid for {item['gate']}")
        if (paths, commands) != EXPECTED_EVIDENCE[item["gate"]]:
            raise ValueError(f"candidate readiness evidence changed for {item['gate']}")
        if check_files:
            for relative in paths:
                relative_path = Path(relative)
                if relative_path.is_absolute() or ".." in relative_path.parts:
                    raise ValueError(f"candidate evidence path is unsafe: {relative}")
                path = ROOT / relative
                if path.is_symlink() or not path.is_file():
                    raise ValueError(f"candidate evidence is absent: {relative}")
            if any(command not in ci for command in commands):
                raise ValueError(f"candidate validation is absent from local CI: {item['gate']}")
    if not (ROOT / "docs/PUBLIC_OPENING_DECISION.md").is_file():
        raise ValueError("public-opening authority is missing")


def refusal_count(manifest, contract) -> int:
    cases = []
    missing = copy.deepcopy(manifest); missing["gates"].pop(); cases.append(missing)
    extra = copy.deepcopy(manifest); extra["gates"].append(copy.deepcopy(extra["gates"][-1])); cases.append(extra)
    signed = copy.deepcopy(manifest); signed["gates"][6]["status"] = "locally-verified"; cases.append(signed)
    weakened = copy.deepcopy(manifest); weakened["authority_boundary"] = "read-write"; cases.append(weakened)
    absent = copy.deepcopy(manifest); absent["gates"][0]["evidence_paths"] = []; cases.append(absent)
    reordered = copy.deepcopy(manifest); reordered["gates"][0], reordered["gates"][1] = reordered["gates"][1], reordered["gates"][0]; cases.append(reordered)
    substituted = copy.deepcopy(manifest); substituted["gates"][0]["evidence_paths"] = substituted["gates"][1]["evidence_paths"]; cases.append(substituted)
    for case in cases:
        try:
            validate(case, contract, check_files=False)
        except ValueError:
            continue
        raise ValueError("adversarial candidate-readiness mutation was accepted")
    return len(cases)


def main() -> int:
    try:
        manifest = strict_json(MANIFEST, "candidate readiness")
        contract = strict_json(CONTRACT, "evaluation contract")
        validate(manifest, contract, check_files=True)
        refusals = refusal_count(manifest, contract)
        if strict_json(RESULT, "retained result") != EXPECTED_RESULT:
            raise ValueError("retained candidate-readiness result drifted")
        if refusals != EXPECTED_RESULT["refusals"]:
            raise ValueError("candidate-readiness refusal count drifted")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"candidate-readiness: {error}", file=sys.stderr)
        return 1
    print("candidate-readiness: passed gates=8 locally-verified=7 pending-freeze=1 refusals=7")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
