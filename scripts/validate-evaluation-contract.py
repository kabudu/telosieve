#!/usr/bin/env python3
"""Validate policy against the capability inventory emitted by the built CLI."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "evaluation/contract.json"
RESULT = ROOT / "results/evaluation-contract-validation.json"
CONFIGURATIONS = (
    ROOT / "evaluation/config.example.json",
    ROOT / "evaluation/config.live.example.json",
    ROOT / "evaluation/config.opentofu.example.json",
    ROOT / "evaluation/config.integration.example.json",
)
MAX_CAPABILITY_BYTES = 64 * 1024
MAX_CAPABILITIES = 16
MUTATION_TOKENS = ("actuate", "apply", "create", "delete", "mutate", "patch", "update", "write")
EXPECTED_KEYS = {
    "schema_version", "decision", "decision_date", "contract_revision_date", "repository_visibility",
    "authoritative_ci", "evaluation_authority_boundary",
    "supported_evaluation_modes", "authorized_work",
    "prohibited_without_separate_authorization", "candidate_readiness_gates",
    "production_promotion_gates",
}
EXPECTED_AUTHORIZED = {
    "diagnostics-and-operator-evidence",
    "installation-upgrade-rollback-packaging",
    "private-evaluation-candidate-preparation",
    "read-only-external-observation",
    "stable-cli-and-configuration",
}
EXPECTED_PROHIBITED = {
    "autonomous-production-actuation", "default-on-telemetry",
    "general-safety-or-byzantine-resilience-claims", "hosted-ci-while-private",
    "public-package-or-release", "production-credential-custody",
}
EXPECTED_READINESS = {
    "bounded-and-versioned-cli-configuration", "fail-closed-live-read-only-integration",
    "install-upgrade-rollback-and-uninstall-procedure",
    "least-privilege-and-secret-free-defaults", "operator-diagnostics-and-evidence-export",
    "platform-resource-and-recovery-qualification",
    "signed-checksummed-reproducible-private-bundle",
    "threat-model-runbook-and-known-limitations",
}
EXPECTED_PROMOTION = {
    "explicit-production-promotion-decision",
    "independent-operator-reproduction-of-exact-candidate",
    "independent-security-assessment-of-exact-candidate",
    "material-findings-remediated-and-reassessed",
    "named-production-adapter-concurrency-and-recovery-proof",
    "production-identity-key-clock-and-custody-design",
}
EXPECTED_CAPABILITY_BINDINGS = {
    ("telosieve.evaluation-config/v4", "kubernetes-shadow"): "telosieve.certificate/v9",
    ("telosieve.evaluation-config/v5", "kubernetes-live"): "telosieve.certificate/v9",
    ("telosieve.evaluation-config/v6", "opentofu-plan"): "telosieve.certificate/v10",
    ("telosieve.evaluation-config/v7", "external-read-only"): "telosieve.certificate/v11",
}
EXPECTED_RESULT = {
    "schema_version": "telosieve.evaluation-contract-validation/v3",
    "supported_modes": 4,
    "authorized_work": len(EXPECTED_AUTHORIZED),
    "prohibited_actions": len(EXPECTED_PROHIBITED),
    "candidate_readiness_gates": len(EXPECTED_READINESS),
    "production_promotion_gates": len(EXPECTED_PROMOTION),
    "adversarial_refusals": 8,
    "status": "passed",
}


def fail(message: str) -> None:
    raise ValueError(message)


def strict_json(value: str, label: str) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                fail(f"{label} contains duplicate key {key!r}")
            result[key] = item
        return result

    try:
        return json.loads(value, object_pairs_hook=unique)
    except json.JSONDecodeError as error:
        fail(f"{label} JSON is invalid: {error}")


def exact_string_set(value: object, expected: set[str], label: str) -> None:
    if (
        not isinstance(value, list)
        or value != sorted(value)
        or len(value) != len(set(value))
        or set(value) != expected
    ):
        fail(f"{label} changed or is not sorted and unique")


def configuration_version(value: object) -> int:
    prefix = "telosieve.evaluation-config/v"
    if not isinstance(value, str) or not value.startswith(prefix):
        fail("capability configuration schema is invalid")
    suffix = value[len(prefix):]
    if not suffix.isascii() or not suffix.isdigit() or not 1 <= int(suffix) <= 65535:
        fail("capability configuration version is invalid")
    return int(suffix)


def validate_capabilities(value: object) -> list[dict[str, object]]:
    if not isinstance(value, dict) or set(value) != {"schema_version", "capabilities"}:
        fail("capability inventory fields are invalid")
    if value["schema_version"] != "telosieve.evaluation-capabilities/v2":
        fail("capability inventory schema is unsupported")
    capabilities = value["capabilities"]
    if not isinstance(capabilities, list) or not 1 <= len(capabilities) <= MAX_CAPABILITIES:
        fail("capability inventory count is invalid")
    schemas: set[str] = set()
    modes: set[str] = set()
    for capability in capabilities:
        if not isinstance(capability, dict) or set(capability) != {
            "configuration_schema", "mode", "target_mutated",
            "observation_quorum_required", "certificate_schema",
        }:
            fail("capability fields are invalid")
        schema = capability["configuration_schema"]
        mode = capability["mode"]
        configuration_version(schema)
        if (
            not isinstance(mode, str) or not mode or len(mode) > 128
            or not mode.isascii()
            or capability["target_mutated"] is not False
            or capability["observation_quorum_required"] is not True
            or EXPECTED_CAPABILITY_BINDINGS.get((schema, mode)) != capability["certificate_schema"]
            or any(token in mode.lower() for token in MUTATION_TOKENS)
            or schema in schemas or mode in modes
        ):
            fail("capability violates the read-only unique-mode boundary")
        schemas.add(schema)
        modes.add(mode)
    if capabilities != sorted(capabilities, key=lambda item: configuration_version(item["configuration_schema"])):
        fail("capabilities are not ordered by configuration version")
    return capabilities


def validate(contract: object, emitted: object) -> None:
    if not isinstance(contract, dict) or set(contract) != EXPECTED_KEYS:
        fail("contract fields do not exactly match the v3 schema")
    if contract["schema_version"] != "telosieve.evaluation-product-contract/v3":
        fail("unsupported contract schema")
    if contract["decision"] != "private-evaluation-product-authorized":
        fail("private evaluation product is not explicitly authorized")
    if contract["decision_date"] != "2026-07-30":
        fail("decision date changed")
    if contract["contract_revision_date"] != "2026-08-02":
        fail("contract revision date changed")
    if contract["repository_visibility"] != "private":
        fail("evaluation contract must preserve private repository status")
    if contract["authoritative_ci"] != "./scripts/ci-local.sh":
        fail("evaluation contract must preserve authoritative local CI")
    if contract["evaluation_authority_boundary"] != "read-only-no-target-mutation":
        fail("evaluation authority boundary was weakened")
    capabilities = validate_capabilities(emitted)
    if contract["supported_evaluation_modes"] != capabilities:
        fail("contract and compiled capability inventories disagree")
    exact_string_set(contract["authorized_work"], EXPECTED_AUTHORIZED, "authorized_work")
    exact_string_set(contract["prohibited_without_separate_authorization"], EXPECTED_PROHIBITED, "prohibited_without_separate_authorization")
    exact_string_set(contract["candidate_readiness_gates"], EXPECTED_READINESS, "candidate_readiness_gates")
    exact_string_set(contract["production_promotion_gates"], EXPECTED_PROMOTION, "production_promotion_gates")


def validate_configurations(capabilities: list[dict[str, object]]) -> None:
    configurations = [strict_json(path.read_text(encoding="utf-8"), path.name) for path in CONFIGURATIONS]
    expected = {(item["configuration_schema"], item["mode"]) for item in capabilities}
    actual: set[tuple[object, object]] = set()
    for config in configurations:
        if not isinstance(config, dict):
            fail("evaluation example configuration is not an object")
        actual.add((config.get("schema_version"), config.get("mode")))
        if "observation_trust_path" not in config:
            fail("evaluation example omits mandatory observation trust")
        if config.get("mode") == "kubernetes-shadow":
            if "observation_quorum_path" not in config:
                fail("shadow example omits mandatory observation quorum")
        else:
            sources = config.get("observation_sources")
            if not isinstance(sources, list) or not 2 <= len(sources) <= 8:
                fail("evaluation example omits mandatory corroborated sources")
    if actual != expected:
        fail("evaluation examples do not exactly cover compiled capabilities")


def adversarial_refusals(contract: dict[str, object], emitted: dict[str, object]) -> int:
    cases: list[tuple[dict[str, object], dict[str, object]]] = []
    extra = copy.deepcopy(emitted)
    extra["capabilities"].append({"configuration_schema": "telosieve.evaluation-config/v8", "mode": "future-read", "target_mutated": False, "observation_quorum_required": True, "certificate_schema": "telosieve.certificate/v11"})
    cases.append((copy.deepcopy(contract), extra))
    missing = copy.deepcopy(contract)
    missing["supported_evaluation_modes"] = missing["supported_evaluation_modes"][:-1]
    cases.append((missing, copy.deepcopy(emitted)))
    mutation_flag = copy.deepcopy(emitted)
    mutation_flag["capabilities"][0]["target_mutated"] = True
    cases.append((copy.deepcopy(contract), mutation_flag))
    mutation_name = copy.deepcopy(emitted)
    mutation_name["capabilities"][0]["mode"] = "kubernetes-apply"
    cases.append((copy.deepcopy(contract), mutation_name))
    duplicate = copy.deepcopy(emitted)
    duplicate["capabilities"][1]["configuration_schema"] = duplicate["capabilities"][0]["configuration_schema"]
    cases.append((copy.deepcopy(contract), duplicate))
    weakened = copy.deepcopy(contract)
    weakened["evaluation_authority_boundary"] = "read-write"
    cases.append((weakened, copy.deepcopy(emitted)))
    optional_quorum = copy.deepcopy(emitted)
    optional_quorum["capabilities"][0]["observation_quorum_required"] = False
    cases.append((copy.deepcopy(contract), optional_quorum))
    confused_certificate = copy.deepcopy(emitted)
    confused_certificate["capabilities"][0]["certificate_schema"] = "telosieve.certificate/v10"
    cases.append((copy.deepcopy(contract), confused_certificate))
    for mutated_contract, mutated_emitted in cases:
        try:
            validate(mutated_contract, mutated_emitted)
        except ValueError:
            continue
        fail("adversarial contract mutation was accepted")
    return len(cases)


def main() -> int:
    try:
        contract = strict_json(CONTRACT.read_text(encoding="utf-8"), "contract")
        process = subprocess.run(
            ["cargo", "run", "--quiet", "--locked", "--offline", "--", "evaluation-capabilities"],
            cwd=ROOT, capture_output=True, check=False, timeout=60, text=True,
        )
        if process.returncode != 0 or len(process.stdout.encode()) > MAX_CAPABILITY_BYTES:
            fail(f"compiled capability inventory failed: {process.stderr.strip()}")
        emitted = strict_json(process.stdout, "capability inventory")
        validate(contract, emitted)
        validate_configurations(emitted["capabilities"])
        refusals = adversarial_refusals(contract, emitted)
        decision = (ROOT / "docs/EVALUATION_PRODUCT_DECISION.md").read_text(encoding="utf-8")
        for phrase in (
            "read-only shadow evaluation", "sole authoritative CI gate", "does not authorize",
            "Independent validation follows construction", "new explicit promotion decision",
            "read-only-no-target-mutation",
        ):
            if phrase not in decision:
                fail(f"decision document is missing boundary: {phrase}")
        if (ROOT / ".github/workflows").exists():
            fail("hosted CI is forbidden while the repository is private")
        if strict_json(RESULT.read_text(encoding="utf-8"), "retained result") != EXPECTED_RESULT:
            fail("retained evaluation-contract result does not match the contract")
        if refusals != EXPECTED_RESULT["adversarial_refusals"]:
            fail("adversarial refusal count changed")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"evaluation-contract: {error}", file=sys.stderr)
        return 1
    print(
        "evaluation-contract: passed "
        f"modes={len(contract['supported_evaluation_modes'])} "
        f"authorized={len(EXPECTED_AUTHORIZED)} prohibited={len(EXPECTED_PROHIBITED)} "
        f"readiness={len(EXPECTED_READINESS)} promotion={len(EXPECTED_PROMOTION)} "
        f"adversarial_refusals={refusals}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
