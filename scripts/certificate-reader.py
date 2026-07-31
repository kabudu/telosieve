#!/usr/bin/env python3
"""Independent bounded reader for supported Telosieve certificates."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any


MAX_CERTIFICATE_BYTES = 2 * 1024 * 1024
MAX_ATTESTATION_BYTES = 64 * 1024
MAX_ATTESTATION_KEYS = 8
MAX_ATTESTATION_LIFETIME_SECONDS = 30 * 24 * 60 * 60
MAX_WITNESS_RECORDS = 64
MAX_REVOCATIONS = 64
MAX_U64 = (1 << 64) - 1
ATTESTATION_SCHEMA = "telosieve.certificate-attestation/v1"
TIMESTAMP_SCHEMA = "telosieve.attestation-timestamp/v1"
REVOCATION_SCHEMA = "telosieve.signer-revocations/v1"
SUPPORTED = {
    "telosieve.certificate/v7": (False, False, False),
    "telosieve.certificate/v8": (True, False, False),
    "telosieve.certificate/v9": (False, True, False),
    "telosieve.certificate/v10": (False, False, True),
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
OPTIONAL_FIELDS = {"actuation", "shadow", "opentofu"}
ACTUATION_FIELDS = {"adapter", "operation_digest", "before_digest", "after_digest"}
SHADOW_FIELDS = {
    "adapter",
    "snapshot_digest",
    "target_uid",
    "desired_resource_version",
    "observed_resource_version",
    "captured_at",
}
SHADOW_OPTIONAL_FIELDS = {"observation_quorum_digest"}
OPENTOFU_FIELDS = {
    "adapter", "plan_sha256", "format_version", "terraform_version",
    "resource_change_count",
}
ATTESTATION_FIELDS = {
    "schema_version",
    "context",
    "certificate_sha256",
    "signer",
    "key_id",
    "issued_at",
    "expires_at",
    "signature",
}
TRUST_FIELDS = {"context", "evaluation_time", "keys"}
TRUST_KEY_FIELDS = {"signer", "key_id", "public_key", "not_before", "not_after"}
TIMESTAMP_FIELDS = {
    "schema_version", "context", "sequence", "previous_digest",
    "attestation_sha256", "observed_at", "authority", "key_id", "signature",
}
REVOCATION_FIELDS = {
    "schema_version", "context", "sequence", "issued_at", "expires_at",
    "entries", "authority", "key_id", "signature",
}
REVOCATION_ENTRY_FIELDS = {"signer", "key_id", "revoked_at"}
WITNESS_TRUST_FIELDS = {
    "context", "evaluation_time", "timestamp_authority", "timestamp_key_id",
    "timestamp_public_key", "trusted_tip_sequence", "trusted_tip_digest",
    "revocation_authority", "revocation_key_id", "revocation_public_key",
    "trusted_revocation_sequence", "trusted_revocation_digest",
}

FIELD = 2**255 - 19
ORDER = 2**252 + 27742317777372353535851937790883648493
CURVE_D = (-121665 * pow(121666, FIELD - 2, FIELD)) % FIELD
SQRT_M1 = pow(2, (FIELD - 1) // 4, FIELD)
IDENTITY = (0, 1, 1, 0)


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


def valid_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 128
        and all(
            character.isascii()
            and (character.isalnum() or character in "._:/-")
            for character in value
        )
    )


def canonical_hex(value: Any, size: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == size * 2
        and all(character in "0123456789abcdef" for character in value)
    )


def recover_x(y: int) -> int:
    xx = ((y * y - 1) * pow(CURVE_D * y * y + 1, FIELD - 2, FIELD)) % FIELD
    x = pow(xx, (FIELD + 3) // 8, FIELD)
    if (x * x - xx) % FIELD:
        x = (x * SQRT_M1) % FIELD
    if (x * x - xx) % FIELD:
        raise ReaderError("Ed25519 point is invalid")
    if x & 1:
        x = FIELD - x
    return x


def point_add(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = ((y1 - x1) * (y2 - x2)) % FIELD
    b = ((y1 + x1) * (y2 + x2)) % FIELD
    c = (2 * CURVE_D * t1 * t2) % FIELD
    d = (2 * z1 * z2) % FIELD
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % FIELD, g * h % FIELD, f * g % FIELD, e * h % FIELD)


def scalar_multiply(
    point: tuple[int, int, int, int], scalar: int
) -> tuple[int, int, int, int]:
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def is_identity(point: tuple[int, int, int, int]) -> bool:
    x, y, z, _ = point
    return x % FIELD == 0 and (y - z) % FIELD == 0


def decode_point(encoded: bytes) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        raise ReaderError("Ed25519 point length is invalid")
    integer = int.from_bytes(encoded, "little")
    sign = integer >> 255
    y = integer & ((1 << 255) - 1)
    if y >= FIELD:
        raise ReaderError("Ed25519 point is non-canonical")
    x = recover_x(y)
    if (x & 1) != sign:
        x = FIELD - x
    if x == 0 and sign:
        raise ReaderError("Ed25519 point sign is invalid")
    point = (x, y, 1, x * y % FIELD)
    if not is_identity(scalar_multiply(point, ORDER)) or is_identity(point):
        raise ReaderError("Ed25519 point is not prime-order")
    return point


BASE_Y = 4 * pow(5, FIELD - 2, FIELD) % FIELD
BASE_X = recover_x(BASE_Y)
BASE_POINT = (BASE_X, BASE_Y, 1, BASE_X * BASE_Y % FIELD)


def encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    inverse = pow(z, FIELD - 2, FIELD)
    affine_x = x * inverse % FIELD
    affine_y = y * inverse % FIELD
    return (affine_y | ((affine_x & 1) << 255)).to_bytes(32, "little")


def verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> None:
    if len(signature) != 64:
        raise ReaderError("Ed25519 signature length is invalid")
    encoded_r = signature[:32]
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= ORDER:
        raise ReaderError("Ed25519 signature scalar is invalid")
    public_point = decode_point(public_key)
    r_point = decode_point(encoded_r)
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % ORDER
    expected = point_add(r_point, scalar_multiply(public_point, challenge))
    if encode_point(scalar_multiply(BASE_POINT, scalar)) != encode_point(expected):
        raise ReaderError("Ed25519 signature is invalid")


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

    requires_actuation, requires_shadow, requires_opentofu = SUPPORTED[version]
    actuation = value.get("actuation")
    shadow = value.get("shadow")
    opentofu = value.get("opentofu")
    if (actuation is not None) != requires_actuation or (
        shadow is not None
    ) != requires_shadow or (opentofu is not None) != requires_opentofu:
        raise ReaderError("certificate extensions do not match its version")
    if requires_actuation:
        record = exact_object(actuation, ACTUATION_FIELDS, "actuation")
        require_strings(record, ACTUATION_FIELDS, "actuation")
    if requires_shadow:
        if not isinstance(shadow, dict) or not SHADOW_FIELDS.issubset(shadow) or not set(shadow).issubset(SHADOW_FIELDS | SHADOW_OPTIONAL_FIELDS):
            raise ReaderError("shadow fields are invalid")
        record = shadow
        require_strings(record, SHADOW_FIELDS - {"captured_at"}, "shadow")
        if not is_unsigned(record["captured_at"]):
            raise ReaderError("shadow captured_at is invalid")
        if "observation_quorum_digest" in record and not canonical_hex(record["observation_quorum_digest"], 32):
            raise ReaderError("shadow observation quorum digest is invalid")
    if requires_opentofu:
        record = exact_object(opentofu, OPENTOFU_FIELDS, "opentofu")
        require_strings(record, OPENTOFU_FIELDS - {"resource_change_count"}, "opentofu")
        if not canonical_hex(record["plan_sha256"], 32):
            raise ReaderError("opentofu plan digest is invalid")
        if record["adapter"] != "telosieve.opentofu-plan/v1" or record["format_version"] != "1.2":
            raise ReaderError("opentofu schema metadata is invalid")
        if not valid_text(record["terraform_version"]):
            raise ReaderError("opentofu version is invalid")
        if not is_unsigned(record["resource_change_count"]) or not 1 <= record["resource_change_count"] <= 64:
            raise ReaderError("opentofu resource count is invalid")
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


def load_bounded_json(path: str, maximum: int, label: str) -> tuple[Any, bytes]:
    with open(path, "rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ReaderError(f"{label} exceeds the input bound")
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReaderError(f"{label} JSON is malformed") from error
    return value, raw


def verify_attestation(
    certificate_raw: bytes, attestation: dict[str, Any], trust: dict[str, Any]
) -> dict[str, Any]:
    exact_object(attestation, ATTESTATION_FIELDS, "attestation")
    exact_object(trust, TRUST_FIELDS, "attestation trust")
    if (
        attestation["schema_version"] != ATTESTATION_SCHEMA
        or not valid_text(attestation["context"])
        or not valid_text(attestation["signer"])
        or not valid_text(attestation["key_id"])
        or not canonical_hex(attestation["certificate_sha256"], 32)
        or not canonical_hex(attestation["signature"], 64)
        or not is_unsigned(attestation["issued_at"])
        or not is_unsigned(attestation["expires_at"])
        or attestation["issued_at"] >= attestation["expires_at"]
        or attestation["expires_at"] - attestation["issued_at"]
        > MAX_ATTESTATION_LIFETIME_SECONDS
    ):
        raise ReaderError("attestation envelope is invalid")
    if (
        not valid_text(trust["context"])
        or not is_unsigned(trust["evaluation_time"])
        or not isinstance(trust["keys"], list)
        or not 1 <= len(trust["keys"]) <= MAX_ATTESTATION_KEYS
        or trust["context"] != attestation["context"]
    ):
        raise ReaderError("attestation trust is invalid")
    if hashlib.sha256(certificate_raw).hexdigest() != attestation["certificate_sha256"]:
        raise ReaderError("attestation certificate digest does not match")

    identities: set[tuple[str, str]] = set()
    matching = []
    for candidate in trust["keys"]:
        exact_object(candidate, TRUST_KEY_FIELDS, "attestation key")
        identity = (candidate["signer"], candidate["key_id"])
        if (
            not valid_text(candidate["signer"])
            or not valid_text(candidate["key_id"])
            or not canonical_hex(candidate["public_key"], 32)
            or not is_unsigned(candidate["not_before"])
            or not is_unsigned(candidate["not_after"])
            or candidate["not_before"] >= candidate["not_after"]
            or identity in identities
        ):
            raise ReaderError("attestation trust key is invalid")
        identities.add(identity)
        if identity == (attestation["signer"], attestation["key_id"]):
            matching.append(candidate)
    if len(matching) != 1:
        raise ReaderError("attestation signer is unknown or ambiguous")
    key = matching[0]
    if (
        attestation["issued_at"] < key["not_before"]
        or attestation["issued_at"] >= key["not_after"]
        or trust["evaluation_time"] < attestation["issued_at"]
        or trust["evaluation_time"] >= attestation["expires_at"]
    ):
        raise ReaderError("attestation time is invalid")

    unsigned = {
        "schema_version": attestation["schema_version"],
        "context": attestation["context"],
        "certificate_sha256": attestation["certificate_sha256"],
        "signer": attestation["signer"],
        "key_id": attestation["key_id"],
        "issued_at": attestation["issued_at"],
        "expires_at": attestation["expires_at"],
    }
    message = (
        ATTESTATION_SCHEMA.encode()
        + b"\0"
        + json.dumps(
            unsigned, ensure_ascii=False, separators=(",", ":")
        ).encode()
    )
    verify_ed25519(
        bytes.fromhex(key["public_key"]),
        bytes.fromhex(attestation["signature"]),
        message,
    )
    return attestation


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def signed_message(domain: str, value: dict[str, Any]) -> bytes:
    return domain.encode() + b"\0" + canonical_json(value)


def verify_witnesses(
    attestation: dict[str, Any],
    attestation_raw: bytes,
    timestamps: Any,
    revocations: dict[str, Any],
    revocations_raw: bytes,
    trust: dict[str, Any],
) -> dict[str, Any]:
    exact_object(trust, WITNESS_TRUST_FIELDS, "witness trust")
    text_fields = {
        "context", "timestamp_authority", "timestamp_key_id",
        "revocation_authority", "revocation_key_id",
    }
    if (
        any(not valid_text(trust[field]) for field in text_fields)
        or not canonical_hex(trust["timestamp_public_key"], 32)
        or not canonical_hex(trust["revocation_public_key"], 32)
        or not canonical_hex(trust["trusted_tip_digest"], 32)
        or not canonical_hex(trust["trusted_revocation_digest"], 32)
        or not is_unsigned(trust["evaluation_time"])
        or not is_unsigned(trust["trusted_tip_sequence"])
        or trust["trusted_tip_sequence"] == 0
        or not is_unsigned(trust["trusted_revocation_sequence"])
        or trust["trusted_revocation_sequence"] == 0
    ):
        raise ReaderError("witness trust is invalid")
    if not isinstance(timestamps, list) or not 1 <= len(timestamps) <= MAX_WITNESS_RECORDS:
        raise ReaderError("timestamp chain exceeds its bound")

    predecessor = None
    previous_observed_at = None
    match = None
    attestation_digest = hashlib.sha256(attestation_raw).hexdigest()
    for index, record_value in enumerate(timestamps, 1):
        record = exact_object(record_value, TIMESTAMP_FIELDS, "timestamp")
        if (
            record["schema_version"] != TIMESTAMP_SCHEMA
            or record["context"] != trust["context"]
            or record["sequence"] != index
            or record["previous_digest"] != predecessor
            or record["authority"] != trust["timestamp_authority"]
            or record["key_id"] != trust["timestamp_key_id"]
            or not canonical_hex(record["attestation_sha256"], 32)
            or not canonical_hex(record["signature"], 64)
            or not is_unsigned(record["observed_at"])
            or (
                previous_observed_at is not None
                and record["observed_at"] < previous_observed_at
            )
        ):
            raise ReaderError("timestamp chain is invalid")
        unsigned = {
            "schema_version": record["schema_version"],
            "context": record["context"],
            "sequence": record["sequence"],
            "previous_digest": record["previous_digest"],
            "attestation_sha256": record["attestation_sha256"],
            "observed_at": record["observed_at"],
            "authority": record["authority"],
            "key_id": record["key_id"],
        }
        verify_ed25519(
            bytes.fromhex(trust["timestamp_public_key"]),
            bytes.fromhex(record["signature"]),
            signed_message(TIMESTAMP_SCHEMA, unsigned),
        )
        if record["attestation_sha256"] == attestation_digest:
            if match is not None:
                raise ReaderError("attestation has ambiguous timestamp records")
            match = record
        predecessor = hashlib.sha256(canonical_json({
            **unsigned, "signature": record["signature"]
        })).hexdigest()
        previous_observed_at = record["observed_at"]
    if (
        timestamps[-1]["sequence"] != trust["trusted_tip_sequence"]
        or predecessor != trust["trusted_tip_digest"]
        or match is None
    ):
        raise ReaderError("timestamp trusted tip is incomplete or rolled back")
    if not (attestation["issued_at"] <= match["observed_at"] < attestation["expires_at"]):
        raise ReaderError("attestation timestamp is outside its validity interval")

    exact_object(revocations, REVOCATION_FIELDS, "revocation snapshot")
    if (
        revocations["schema_version"] != REVOCATION_SCHEMA
        or hashlib.sha256(revocations_raw).hexdigest()
        != trust["trusted_revocation_digest"]
        or revocations["context"] != trust["context"]
        or revocations["sequence"] != trust["trusted_revocation_sequence"]
        or revocations["authority"] != trust["revocation_authority"]
        or revocations["key_id"] != trust["revocation_key_id"]
        or not canonical_hex(revocations["signature"], 64)
        or not is_unsigned(revocations["issued_at"])
        or not is_unsigned(revocations["expires_at"])
        or revocations["issued_at"] >= revocations["expires_at"]
        or revocations["expires_at"] - revocations["issued_at"]
        > MAX_ATTESTATION_LIFETIME_SECONDS
        or not revocations["issued_at"] <= trust["evaluation_time"] < revocations["expires_at"]
        or not isinstance(revocations["entries"], list)
        or len(revocations["entries"]) > MAX_REVOCATIONS
    ):
        raise ReaderError("revocation snapshot is invalid")
    identities = set()
    for entry in revocations["entries"]:
        exact_object(entry, REVOCATION_ENTRY_FIELDS, "revocation entry")
        identity = (entry["signer"], entry["key_id"])
        if (
            not valid_text(entry["signer"])
            or not valid_text(entry["key_id"])
            or not is_unsigned(entry["revoked_at"])
            or identity in identities
        ):
            raise ReaderError("revocation entry is invalid")
        identities.add(identity)
    unsigned_revocations = {
        "schema_version": revocations["schema_version"],
        "context": revocations["context"],
        "sequence": revocations["sequence"],
        "issued_at": revocations["issued_at"],
        "expires_at": revocations["expires_at"],
        "entries": [
            {
                "signer": entry["signer"],
                "key_id": entry["key_id"],
                "revoked_at": entry["revoked_at"],
            }
            for entry in revocations["entries"]
        ],
        "authority": revocations["authority"],
        "key_id": revocations["key_id"],
    }
    verify_ed25519(
        bytes.fromhex(trust["revocation_public_key"]),
        bytes.fromhex(revocations["signature"]),
        signed_message(REVOCATION_SCHEMA, unsigned_revocations),
    )
    if any(
        entry["signer"] == attestation["signer"]
        and entry["key_id"] == attestation["key_id"]
        and match["observed_at"] >= entry["revoked_at"]
        for entry in revocations["entries"]
    ):
        raise ReaderError("attestation signer was revoked before observation")
    return match


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attestation")
    parser.add_argument("--trust")
    parser.add_argument("--timestamps")
    parser.add_argument("--revocations")
    parser.add_argument("--witness-trust")
    arguments = parser.parse_args()
    try:
        certificate, raw = read_certificate(sys.stdin.buffer)
        if bool(arguments.attestation) != bool(arguments.trust):
            raise ReaderError("attestation and trust must be supplied together")
        attestation = None
        timestamp = None
        if arguments.attestation:
            attestation_value, attestation_raw = load_bounded_json(
                arguments.attestation, MAX_ATTESTATION_BYTES, "attestation"
            )
            trust_value, _ = load_bounded_json(
                arguments.trust, MAX_ATTESTATION_BYTES, "attestation trust"
            )
            attestation = verify_attestation(raw, attestation_value, trust_value)
        witness_arguments = (
            arguments.timestamps, arguments.revocations, arguments.witness_trust
        )
        if any(witness_arguments) and not all(witness_arguments):
            raise ReaderError("timestamps, revocations, and witness trust must be supplied together")
        if all(witness_arguments):
            if attestation is None:
                raise ReaderError("witness verification requires attestation verification")
            timestamp_value, _ = load_bounded_json(
                arguments.timestamps, MAX_ATTESTATION_BYTES, "timestamps"
            )
            revocation_value, revocation_raw = load_bounded_json(
                arguments.revocations, MAX_ATTESTATION_BYTES, "revocations"
            )
            witness_trust_value, _ = load_bounded_json(
                arguments.witness_trust, MAX_ATTESTATION_BYTES, "witness trust"
            )
            timestamp = verify_witnesses(
                attestation, attestation_raw, timestamp_value,
                revocation_value, revocation_raw, witness_trust_value
            )
    except ReaderError as error:
        print(f"certificate-reader: refused: {error}", file=sys.stderr)
        return 2
    summary = {
        "implementation": "telosieve-python-certificate-reader/v3",
        "certificate_version": certificate["certificate_version"],
        "scenario_id": certificate["scenario_id"],
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "status": "accepted",
    }
    if attestation is not None:
        summary["attestation"] = {
            "schema_version": attestation["schema_version"],
            "signer": attestation["signer"],
            "key_id": attestation["key_id"],
            "status": "verified",
        }
    if timestamp is not None:
        summary["timestamp"] = {
            "schema_version": timestamp["schema_version"],
            "sequence": timestamp["sequence"],
            "observed_at": timestamp["observed_at"],
            "status": "verified",
        }
    json.dump(
        summary,
        sys.stdout,
        sort_keys=True,
        separators=(",", ":"),
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
