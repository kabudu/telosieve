#!/usr/bin/env python3
"""Adversarial qualification for the witness operator record validator."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

from witness_operator_record import REQUEST, validate_record


def record(
    request_digest: str, attachment_digest: str, signature_digest: str
) -> dict[str, object]:
    return {
        "schema_version": "telosieve.witness-operator-record/v1",
        "request_sha256": request_digest,
        "source_commit": "5219cdc2b860ad760473187b374eaedce5361e4e",
        "operator": {
            "organization": "Independent Example Laboratory",
            "name": "Example Operator",
            "contact": "operator@example.invalid",
            "completed_at": "2026-07-30T12:30:00Z",
        },
        "independence": {
            "not_project_member": True,
            "credentials_not_project_controlled": True,
            "execution_not_project_controlled": True,
            "endpoint_administration_not_project_controlled": True,
            "conflicts": [],
        },
        "execution": {
            "started_at": "2026-07-30T12:00:00Z",
            "ended_at": "2026-07-30T12:20:00Z",
            "host_description": "operator-owned isolated Linux host",
            "network_description": "operator-owned network with controlled faults",
            "clock_source": "operator-administered authenticated time source",
            "credential_custody": "operator-generated and operator-retained",
            "incident_owner": "Independent Example Laboratory",
            "commands": [
                "./scripts/ci-local.sh",
                "./scripts/run-witness-durability.sh",
                "./scripts/run-witness-endpoint-harness.sh",
            ],
            "local_ci_passed": True,
            "hosted_ci_used": False,
        },
        "endpoints": [
            {
                "role": "timestamp",
                "url": "https://timestamp.example.invalid",
                "administrator": "Independent Example Laboratory",
                "credential_owner": "Independent Example Laboratory",
            },
            {
                "role": "revocation",
                "url": "https://revocation.example.invalid",
                "administrator": "Independent Example Laboratory",
                "credential_owner": "Independent Example Laboratory",
            },
        ],
        "outcomes": {
            "accepted": [
                "authenticated-restart",
                "healthy-exact-artifacts",
                "one-sided-partition-fallback",
            ],
            "refused": [
                "delayed-timeout",
                "dropped-connection",
                "equivocal-artifact",
                "oversized-response",
                "stale-revocation",
                "total-outage",
                "unauthorized-request",
            ],
        },
        "attachments": [
            {"path": "run.log", "sha256": attachment_digest},
            {"path": "signature.asc", "sha256": signature_digest},
        ],
        "signature": {
            "path": "signature.asc",
            "format": "openpgp",
            "signer_identity": "Example Operator",
            "key_fingerprint": "synthetic-qualification-key",
        },
        "attestation": {
            "statement": "I ran the frozen request under the described custody boundaries.",
            "limitations": ["Synthetic qualification record; not independent evidence."],
        },
    }


def must_reject(root: Path, candidate: dict[str, object], label: str) -> None:
    path = root / f"{label}.json"
    path.write_text(json.dumps(candidate), encoding="utf-8")
    try:
        validate_record(path)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError):
        return
    raise AssertionError(f"validator accepted {label}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="telosieve-operator-record-") as temporary:
        root = Path(temporary)
        attachment = root / "run.log"
        attachment.write_bytes(b"synthetic qualification only\n")
        attachment_digest = hashlib.sha256(attachment.read_bytes()).hexdigest()
        signature = root / "signature.asc"
        signature.write_bytes(b"synthetic signature fixture\n")
        signature_digest = hashlib.sha256(signature.read_bytes()).hexdigest()
        request_digest = hashlib.sha256(REQUEST.read_bytes()).hexdigest()
        valid = record(request_digest, attachment_digest, signature_digest)
        valid_path = root / "valid.json"
        valid_path.write_text(json.dumps(valid), encoding="utf-8")
        validate_record(valid_path)

        mutations: list[tuple[str, dict[str, object]]] = []
        wrong_request = copy.deepcopy(valid)
        wrong_request["request_sha256"] = "0" * 64
        mutations.append(("wrong-request", wrong_request))
        controlled = copy.deepcopy(valid)
        controlled["independence"]["execution_not_project_controlled"] = False
        mutations.append(("project-controlled", controlled))
        same_origin = copy.deepcopy(valid)
        same_origin["endpoints"][1]["url"] = same_origin["endpoints"][0]["url"]
        mutations.append(("same-origin", same_origin))
        insecure = copy.deepcopy(valid)
        insecure["endpoints"][0]["url"] = "http://timestamp.example.invalid"
        mutations.append(("insecure-origin", insecure))
        missing_fault = copy.deepcopy(valid)
        missing_fault["outcomes"]["refused"].pop()
        mutations.append(("missing-fault", missing_fault))
        hosted_ci = copy.deepcopy(valid)
        hosted_ci["execution"]["hosted_ci_used"] = True
        mutations.append(("hosted-ci", hosted_ci))
        digest_mismatch = copy.deepcopy(valid)
        digest_mismatch["attachments"][0]["sha256"] = "f" * 64
        mutations.append(("digest-mismatch", digest_mismatch))
        traversal = copy.deepcopy(valid)
        traversal["attachments"][0]["path"] = "../run.log"
        mutations.append(("path-traversal", traversal))
        stale_completion = copy.deepcopy(valid)
        stale_completion["operator"]["completed_at"] = "2026-08-08T12:30:00Z"
        mutations.append(("stale-completion", stale_completion))
        unknown_field = copy.deepcopy(valid)
        unknown_field["unreviewed"] = True
        mutations.append(("unknown-field", unknown_field))
        oversized_attachment = root / "oversized.log"
        oversized_attachment.write_bytes(b"x" * (1024 * 1024 + 1))
        oversized = copy.deepcopy(valid)
        oversized["attachments"][0] = {
            "path": "oversized.log",
            "sha256": hashlib.sha256(oversized_attachment.read_bytes()).hexdigest(),
        }
        mutations.append(("oversized-attachment", oversized))
        symbolic_link = root / "linked.log"
        symbolic_link.symlink_to(attachment)
        linked = copy.deepcopy(valid)
        linked["attachments"][0] = {
            "path": "linked.log",
            "sha256": attachment_digest,
        }
        mutations.append(("symbolic-link", linked))
        unbound_signature = copy.deepcopy(valid)
        unbound_signature["signature"]["path"] = "unlisted.asc"
        mutations.append(("unbound-signature", unbound_signature))

        for label, mutation in mutations:
            must_reject(root, mutation, label)

    result = (
        json.dumps(
            {
                "schema_version": "telosieve.witness-operator-record-qualification/v1",
                "accepted": 1,
                "refused": 13,
                "independent_evidence": False,
                "status": "passed",
            },
            separators=(",", ":"),
        )
        + "\n"
    )
    retained = (
        Path(__file__).resolve().parent.parent
        / "results/witness-operator-record-qualification.json"
    ).read_text(encoding="utf-8")
    if result != retained:
        raise AssertionError("retained operator-record qualification result drifted")
    print(result, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
