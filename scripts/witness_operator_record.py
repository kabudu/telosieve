#!/usr/bin/env python3
"""Fail-closed validation for independently returned witness evidence."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent.parent
REQUEST = ROOT / "assessment/witness-operator-request.json"
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
MAX_TEXT = 512
RECORD_KEYS = {
    "schema_version",
    "request_sha256",
    "source_commit",
    "operator",
    "independence",
    "execution",
    "endpoints",
    "outcomes",
    "attachments",
    "signature",
    "attestation",
}
REQUEST_KEYS = {
    "schema_version",
    "source_commit",
    "repository_visibility",
    "authoritative_ci",
    "required_commands",
    "source_artifacts",
    "required_success_cases",
    "required_refusal_cases",
    "maximum_record_bytes",
    "maximum_attachment_bytes",
    "maximum_attachments",
}


def fail(message: str) -> None:
    raise ValueError(message)


def exact_object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} fields do not exactly match the v1 schema")
    return value


def text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > MAX_TEXT
        or any(ord(character) < 32 for character in value)
    ):
        fail(f"{label} must be a normalized bounded string")
    return value


def timestamp(value: object, label: str) -> datetime:
    raw = text(value, label)
    if not raw.endswith("Z"):
        fail(f"{label} must use UTC Z notation")
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as error:
        fail(f"{label} is not RFC 3339: {error}")
    if parsed.tzinfo != timezone.utc:
        fail(f"{label} must use UTC")
    return parsed


def string_set(value: object, label: str) -> set[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 32
        or any(not isinstance(item, str) for item in value)
    ):
        fail(f"{label} must be a bounded non-empty string array")
    normalized = [text(item, label) for item in value]
    if len(set(normalized)) != len(normalized):
        fail(f"{label} must not contain duplicates")
    return set(normalized)


def git(*arguments: str) -> bytes:
    return subprocess.run(
        ("git", *arguments),
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def validate_request(request: object) -> dict[str, object]:
    request = exact_object(request, REQUEST_KEYS, "request")
    if request["schema_version"] != "telosieve.witness-operator-request/v1":
        fail("unsupported request schema")
    if request["repository_visibility"] != "private":
        fail("request must preserve private repository status")
    if request["authoritative_ci"] != "./scripts/ci-local.sh":
        fail("request must use authoritative local CI")
    expected_commands = [
        "./scripts/ci-local.sh",
        "./scripts/run-witness-durability.sh",
        "./scripts/run-witness-endpoint-harness.sh",
    ]
    if request["required_commands"] != expected_commands:
        fail("request command set or order changed")
    source_commit = request["source_commit"]
    if not isinstance(source_commit, str) or COMMIT.fullmatch(source_commit) is None:
        fail("request source commit must be a full lowercase Git object ID")
    git("cat-file", "-e", f"{source_commit}^{{commit}}")
    git("merge-base", "--is-ancestor", source_commit, "HEAD")
    tracked = git("ls-tree", "-r", "--name-only", source_commit).splitlines()
    if any(path.startswith(b".github/workflows/") for path in tracked):
        fail("requested source contains forbidden hosted CI")

    artifacts = request["source_artifacts"]
    if not isinstance(artifacts, list) or not artifacts or len(artifacts) > 32:
        fail("request source artifacts violate count bounds")
    paths: list[str] = []
    for artifact in artifacts:
        artifact = exact_object(artifact, {"path", "sha256"}, "source artifact")
        path = text(artifact["path"], "source artifact.path")
        relative = Path(path)
        expected = artifact["sha256"]
        if relative.is_absolute() or ".." in relative.parts:
            fail("source artifact path must be repository-relative")
        if not isinstance(expected, str) or SHA256.fullmatch(expected) is None:
            fail("source artifact.sha256 must be lowercase SHA-256")
        actual = hashlib.sha256(git("show", f"{source_commit}:{path}")).hexdigest()
        if actual != expected:
            fail(f"source artifact digest mismatch: {path}")
        paths.append(path)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        fail("source artifact paths must be sorted and unique")

    string_set(request["required_success_cases"], "required_success_cases")
    string_set(request["required_refusal_cases"], "required_refusal_cases")
    for field, minimum, maximum in (
        ("maximum_record_bytes", 4096, 1024 * 1024),
        ("maximum_attachment_bytes", 1024, 16 * 1024 * 1024),
        ("maximum_attachments", 1, 64),
    ):
        value = request[field]
        if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
            fail(f"request {field} is outside its safety bound")
    return request


def validate_record(record_path: Path, request_path: Path = REQUEST) -> dict[str, object]:
    request_bytes = request_path.read_bytes()
    request = validate_request(json.loads(request_bytes))
    maximum_record = request["maximum_record_bytes"]
    record_bytes = record_path.read_bytes()
    if len(record_bytes) > maximum_record:
        fail("record exceeds request byte bound")
    record = exact_object(json.loads(record_bytes), RECORD_KEYS, "record")
    if record["schema_version"] != "telosieve.witness-operator-record/v1":
        fail("unsupported record schema")
    expected_request_digest = hashlib.sha256(request_bytes).hexdigest()
    if record["request_sha256"] != expected_request_digest:
        fail("record does not bind the exact operator request")
    if (
        not isinstance(record["source_commit"], str)
        or COMMIT.fullmatch(record["source_commit"]) is None
        or record["source_commit"] != request["source_commit"]
    ):
        fail("record source commit does not match the request")

    operator = exact_object(
        record["operator"],
        {"organization", "name", "contact", "completed_at"},
        "operator",
    )
    for field in ("organization", "name", "contact"):
        text(operator[field], f"operator.{field}")
    completed_at = timestamp(operator["completed_at"], "operator.completed_at")

    independence = exact_object(
        record["independence"],
        {
            "not_project_member",
            "credentials_not_project_controlled",
            "execution_not_project_controlled",
            "endpoint_administration_not_project_controlled",
            "conflicts",
        },
        "independence",
    )
    for field in (
        "not_project_member",
        "credentials_not_project_controlled",
        "execution_not_project_controlled",
        "endpoint_administration_not_project_controlled",
    ):
        if independence[field] is not True:
            fail(f"independence.{field} must be explicitly true")
    conflicts = independence["conflicts"]
    if not isinstance(conflicts, list) or len(conflicts) > 8:
        fail("independence.conflicts must be a bounded array")
    for conflict in conflicts:
        text(conflict, "independence.conflicts")

    execution = exact_object(
        record["execution"],
        {
            "started_at",
            "ended_at",
            "host_description",
            "network_description",
            "clock_source",
            "credential_custody",
            "incident_owner",
            "commands",
            "local_ci_passed",
            "hosted_ci_used",
        },
        "execution",
    )
    started_at = timestamp(execution["started_at"], "execution.started_at")
    ended_at = timestamp(execution["ended_at"], "execution.ended_at")
    if ended_at < started_at or ended_at - started_at > timedelta(hours=24):
        fail("execution interval must be ordered and no longer than 24 hours")
    if completed_at < ended_at or completed_at - ended_at > timedelta(days=7):
        fail("completion must follow execution within seven days")
    for field in (
        "host_description",
        "network_description",
        "clock_source",
        "credential_custody",
        "incident_owner",
    ):
        text(execution[field], f"execution.{field}")
    if execution["commands"] != request["required_commands"]:
        fail("execution commands do not exactly match the request")
    if execution["local_ci_passed"] is not True:
        fail("authoritative local CI was not reported as passed")
    if execution["hosted_ci_used"] is not False:
        fail("hosted CI must not be used for this private repository")

    endpoints = record["endpoints"]
    if not isinstance(endpoints, list) or len(endpoints) != 2:
        fail("exactly two endpoint authorities are required")
    roles: set[str] = set()
    origins: set[tuple[str, str, int | None]] = set()
    for endpoint in endpoints:
        endpoint = exact_object(
            endpoint,
            {"role", "url", "administrator", "credential_owner"},
            "endpoint",
        )
        role = text(endpoint["role"], "endpoint.role")
        roles.add(role)
        parsed = urlsplit(text(endpoint["url"], "endpoint.url"))
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            fail("endpoint.url must be an authenticated HTTPS origin")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            fail("endpoint.url must contain only an HTTPS origin")
        origins.add((parsed.scheme, parsed.hostname.lower(), parsed.port))
        text(endpoint["administrator"], "endpoint.administrator")
        text(endpoint["credential_owner"], "endpoint.credential_owner")
    if roles != {"revocation", "timestamp"} or len(origins) != 2:
        fail("timestamp and revocation must use distinct HTTPS origins")

    outcomes = exact_object(record["outcomes"], {"accepted", "refused"}, "outcomes")
    if string_set(outcomes["accepted"], "outcomes.accepted") != set(
        request["required_success_cases"]
    ):
        fail("accepted outcomes do not exactly match the request")
    if string_set(outcomes["refused"], "outcomes.refused") != set(
        request["required_refusal_cases"]
    ):
        fail("refused outcomes do not exactly match the request")

    attachments = record["attachments"]
    if (
        not isinstance(attachments, list)
        or not attachments
        or len(attachments) > request["maximum_attachments"]
    ):
        fail("attachments violate count bounds")
    attachment_root = record_path.resolve().parent
    paths: list[str] = []
    for attachment in attachments:
        attachment = exact_object(attachment, {"path", "sha256"}, "attachment")
        relative = text(attachment["path"], "attachment.path")
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            fail("attachment path must stay below the record directory")
        expected = attachment["sha256"]
        if not isinstance(expected, str) or SHA256.fullmatch(expected) is None:
            fail("attachment.sha256 must be lowercase SHA-256")
        candidate = attachment_root / relative_path
        resolved = candidate.resolve()
        if attachment_root not in resolved.parents or not resolved.is_file():
            fail("attachment is absent or escapes the record directory")
        if candidate.is_symlink():
            fail("attachment must not be a symbolic link")
        with resolved.open("rb") as stream:
            content = stream.read(request["maximum_attachment_bytes"] + 1)
        if len(content) > request["maximum_attachment_bytes"]:
            fail("attachment exceeds byte bound")
        if hashlib.sha256(content).hexdigest() != expected:
            fail("attachment digest mismatch")
        paths.append(relative)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        fail("attachment paths must be sorted and unique")

    signature = exact_object(
        record["signature"],
        {"path", "format", "signer_identity", "key_fingerprint"},
        "signature",
    )
    signature_path = text(signature["path"], "signature.path")
    if signature_path not in paths:
        fail("detached signature must be a digest-bound attachment")
    if signature["format"] not in {"minisign", "openpgp", "ssh-signature", "x509-cms"}:
        fail("unsupported detached signature format")
    text(signature["signer_identity"], "signature.signer_identity")
    text(signature["key_fingerprint"], "signature.key_fingerprint")

    attestation = exact_object(
        record["attestation"], {"statement", "limitations"}, "attestation"
    )
    text(attestation["statement"], "attestation.statement")
    string_set(attestation["limitations"], "attestation.limitations")
    return record


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: witness_operator_record.py RECORD.json", file=sys.stderr)
        return 2
    try:
        record = validate_record(Path(sys.argv[1]))
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"witness-operator-record: {error}", file=sys.stderr)
        return 1
    print(
        "witness-operator-record: structurally valid "
        f"source={record['source_commit']} attachments={len(record['attachments'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
