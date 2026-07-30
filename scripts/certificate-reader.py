#!/usr/bin/env python3
"""Independent bounded reader for supported Telosieve certificates."""

from __future__ import annotations

import hashlib
import json
import sys
from typing import Any


MAX_CERTIFICATE_BYTES = 2 * 1024 * 1024
MAX_U64 = (1 << 64) - 1
SUPPORTED = {
    "telosieve.certificate/v7": (False, False),
    "telosieve.certificate/v8": (True, False),
    "telosieve.certificate/v9": (False, True),
}
REQUIRED_FIELDS = {
    "certificate_version",
    "scenario_id",
    "seed",
    "authority_digests",
    "deletion_authorization_id",
    "phenotype_history_anchor",
    "hypotheses",
    "decision",
    "refusal_reason",
    "transition",
    "rollback",
    "final_state",
    "baselines",
    "metrics",
}
OPTIONAL_FIELDS = {"actuation", "shadow"}
ACTUATION_FIELDS = {"adapter", "operation_digest", "before_digest", "after_digest"}
SHADOW_FIELDS = {
    "adapter",
    "snapshot_digest",
    "target_uid",
    "desired_resource_version",
    "observed_resource_version",
    "captured_at",
}


class ReaderError(ValueError):
    """A fail-closed compatibility refusal."""


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReaderError(f"duplicate field: {key}")
        result[key] = value
    return result


def is_unsigned(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_U64
    )


def exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReaderError(f"{label} fields are invalid")
    return value


def require_strings(value: dict[str, Any], fields: set[str], label: str) -> None:
    if any(not isinstance(value[field], str) for field in fields):
        raise ReaderError(f"{label} string fields are invalid")


def validate_certificate(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReaderError("certificate must be an object")
    fields = set(value)
    if not REQUIRED_FIELDS.issubset(fields) or not fields.issubset(
        REQUIRED_FIELDS | OPTIONAL_FIELDS
    ):
        raise ReaderError("certificate fields are invalid")

    version = value["certificate_version"]
    if not isinstance(version, str) or version not in SUPPORTED:
        raise ReaderError("certificate version is unsupported")
    if not isinstance(value["scenario_id"], str):
        raise ReaderError("scenario_id is invalid")
    if not is_unsigned(value["seed"]):
        raise ReaderError("seed is invalid")
    if not isinstance(value["authority_digests"], dict) or any(
        not isinstance(key, str) or not isinstance(digest, str)
        for key, digest in value["authority_digests"].items()
    ):
        raise ReaderError("authority_digests is invalid")
    if value["deletion_authorization_id"] is not None and not isinstance(
        value["deletion_authorization_id"], str
    ):
        raise ReaderError("deletion_authorization_id is invalid")
    if not isinstance(value["phenotype_history_anchor"], dict):
        raise ReaderError("phenotype_history_anchor is invalid")
    if not isinstance(value["hypotheses"], list):
        raise ReaderError("hypotheses is invalid")
    if not isinstance(value["decision"], str) or value["decision"] not in {
        "applied",
        "refused",
    }:
        raise ReaderError("decision is invalid")
    if value["refusal_reason"] is not None and not isinstance(
        value["refusal_reason"], str
    ):
        raise ReaderError("refusal_reason is invalid")
    for field in ("transition", "rollback"):
        if value[field] is not None and not isinstance(value[field], dict):
            raise ReaderError(f"{field} is invalid")
    if not isinstance(value["final_state"], dict):
        raise ReaderError("final_state is invalid")
    if not isinstance(value["baselines"], list):
        raise ReaderError("baselines is invalid")
    if not isinstance(value["metrics"], dict):
        raise ReaderError("metrics is invalid")

    requires_actuation, requires_shadow = SUPPORTED[version]
    actuation = value.get("actuation")
    shadow = value.get("shadow")
    if (actuation is not None) != requires_actuation or (
        shadow is not None
    ) != requires_shadow:
        raise ReaderError("certificate extensions do not match its version")
    if requires_actuation:
        record = exact_object(actuation, ACTUATION_FIELDS, "actuation")
        require_strings(record, ACTUATION_FIELDS, "actuation")
    if requires_shadow:
        record = exact_object(shadow, SHADOW_FIELDS, "shadow")
        require_strings(record, SHADOW_FIELDS - {"captured_at"}, "shadow")
        if not is_unsigned(record["captured_at"]):
            raise ReaderError("shadow captured_at is invalid")
    return value


def read_certificate(stream: Any) -> tuple[dict[str, Any], bytes]:
    raw = stream.read(MAX_CERTIFICATE_BYTES + 1)
    if len(raw) > MAX_CERTIFICATE_BYTES:
        raise ReaderError("certificate exceeds the input bound")
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReaderError("certificate JSON is malformed") from error
    return validate_certificate(value), raw


def main() -> int:
    try:
        certificate, raw = read_certificate(sys.stdin.buffer)
    except ReaderError as error:
        print(f"certificate-reader: refused: {error}", file=sys.stderr)
        return 2
    json.dump(
        {
            "implementation": "telosieve-python-certificate-reader/v1",
            "certificate_version": certificate["certificate_version"],
            "scenario_id": certificate["scenario_id"],
            "input_sha256": hashlib.sha256(raw).hexdigest(),
            "status": "accepted",
        },
        sys.stdout,
        sort_keys=True,
        separators=(",", ":"),
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
