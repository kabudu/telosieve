#!/usr/bin/env python3
"""Validate the binding private evaluation-product decision."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "evaluation/contract.json"
RESULT = ROOT / "results/evaluation-contract-validation.json"
EXPECTED_KEYS = {
    "schema_version",
    "decision",
    "decision_date",
    "repository_visibility",
    "authoritative_ci",
    "supported_evaluation_mode",
    "authorized_work",
    "prohibited_without_separate_authorization",
    "candidate_readiness_gates",
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
    "autonomous-production-actuation",
    "default-on-telemetry",
    "general-safety-or-byzantine-resilience-claims",
    "hosted-ci-while-private",
    "public-package-or-release",
    "production-credential-custody",
}
EXPECTED_READINESS = {
    "bounded-and-versioned-cli-configuration",
    "fail-closed-live-read-only-integration",
    "install-upgrade-rollback-and-uninstall-procedure",
    "least-privilege-and-secret-free-defaults",
    "operator-diagnostics-and-evidence-export",
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
EXPECTED_RESULT = {
    "schema_version": "telosieve.evaluation-contract-validation/v1",
    "authorized_work": len(EXPECTED_AUTHORIZED),
    "prohibited_actions": len(EXPECTED_PROHIBITED),
    "candidate_readiness_gates": len(EXPECTED_READINESS),
    "production_promotion_gates": len(EXPECTED_PROMOTION),
    "status": "passed",
}


def fail(message: str) -> None:
    raise ValueError(message)


def exact_string_set(value: object, expected: set[str], label: str) -> None:
    if (
        not isinstance(value, list)
        or value != sorted(value)
        or len(value) != len(set(value))
        or set(value) != expected
    ):
        fail(f"{label} changed or is not sorted and unique")


def main() -> int:
    try:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        if not isinstance(contract, dict) or set(contract) != EXPECTED_KEYS:
            fail("contract fields do not exactly match the v1 schema")
        if contract["schema_version"] != "telosieve.evaluation-product-contract/v1":
            fail("unsupported contract schema")
        if contract["decision"] != "private-evaluation-product-authorized":
            fail("private evaluation product is not explicitly authorized")
        if contract["decision_date"] != "2026-07-30":
            fail("decision date changed")
        if contract["repository_visibility"] != "private":
            fail("evaluation contract must preserve private repository status")
        if contract["authoritative_ci"] != "./scripts/ci-local.sh":
            fail("evaluation contract must preserve authoritative local CI")
        if contract["supported_evaluation_mode"] != "read-only-shadow":
            fail("first evaluation mode must remain read-only shadow")
        exact_string_set(
            contract["authorized_work"], EXPECTED_AUTHORIZED, "authorized_work"
        )
        exact_string_set(
            contract["prohibited_without_separate_authorization"],
            EXPECTED_PROHIBITED,
            "prohibited_without_separate_authorization",
        )
        exact_string_set(
            contract["candidate_readiness_gates"],
            EXPECTED_READINESS,
            "candidate_readiness_gates",
        )
        exact_string_set(
            contract["production_promotion_gates"],
            EXPECTED_PROMOTION,
            "production_promotion_gates",
        )

        decision = (
            ROOT / "docs/EVALUATION_PRODUCT_DECISION.md"
        ).read_text(encoding="utf-8")
        required_phrases = (
            "read-only shadow evaluation",
            "sole authoritative CI gate",
            "does not authorize",
            "Independent validation follows construction",
            "new explicit promotion decision",
        )
        for phrase in required_phrases:
            if phrase not in decision:
                fail(f"decision document is missing boundary: {phrase}")
        if (ROOT / ".github/workflows").exists():
            fail("hosted CI is forbidden while the repository is private")
        if json.loads(RESULT.read_text(encoding="utf-8")) != EXPECTED_RESULT:
            fail("retained evaluation-contract result does not match the contract")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"evaluation-contract: {error}", file=sys.stderr)
        return 1
    print(
        "evaluation-contract: passed "
        f"authorized={len(EXPECTED_AUTHORIZED)} "
        f"prohibited={len(EXPECTED_PROHIBITED)} "
        f"readiness={len(EXPECTED_READINESS)} "
        f"promotion={len(EXPECTED_PROMOTION)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
