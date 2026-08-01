#!/usr/bin/env python3
"""Publish bounded fail-closed Prometheus metrics from PKI monitor status."""
from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
import time
from pathlib import Path

from http_json_integration_common import HTTPJSONIntegrationError, strict_json

MAX_STATUS_BYTES = 16 * 1024
MAX_AGE_SECONDS = 24 * 60 * 60
MAX_FUTURE_SKEW_SECONDS = 60
STATUS_FIELDS = {
    "schema_version", "checked_at", "identities", "ready", "not_ready",
    "renew_before_seconds", "secrets_disclosed", "status",
}


def safe_read(path_value: str) -> bytes:
    path = Path(path_value)
    if not path.is_absolute():
        raise HTTPJSONIntegrationError("status path must be absolute")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise HTTPJSONIntegrationError("status cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_size > MAX_STATUS_BYTES or metadata.st_mode & 0o077):
            raise HTTPJSONIntegrationError("status boundary is unsafe")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(MAX_STATUS_BYTES + 1)
        if len(data) > MAX_STATUS_BYTES:
            raise HTTPJSONIntegrationError("status is oversized")
        return data
    finally:
        os.close(descriptor)


def validate(raw: bytes, now: int, maximum_age: int) -> tuple[dict, int, bool]:
    value = strict_json(raw, "PKI monitor status")
    if not isinstance(value, dict) or set(value) != STATUS_FIELDS:
        raise HTTPJSONIntegrationError("status shape is invalid")
    integers = ("checked_at", "identities", "ready", "not_ready", "renew_before_seconds")
    if any(not isinstance(value[field], int) or isinstance(value[field], bool) for field in integers):
        raise HTTPJSONIntegrationError("status integer field is invalid")
    if value["schema_version"] != "telosieve.http-json-pki-monitor-status/v1":
        raise HTTPJSONIntegrationError("status schema is unsupported")
    if value["checked_at"] < 0:
        raise HTTPJSONIntegrationError("status timestamp is invalid")
    if not 1 <= value["identities"] <= 4:
        raise HTTPJSONIntegrationError("status identity count is invalid")
    if not 0 <= value["ready"] <= value["identities"] or not 0 <= value["not_ready"] <= value["identities"]:
        raise HTTPJSONIntegrationError("status readiness count is invalid")
    if value["ready"] + value["not_ready"] != value["identities"]:
        raise HTTPJSONIntegrationError("status readiness counts are inconsistent")
    if not 0 <= value["renew_before_seconds"] <= 30 * 24 * 60 * 60:
        raise HTTPJSONIntegrationError("status renewal horizon is invalid")
    expected = "ready" if value["not_ready"] == 0 else "not-ready"
    if value["status"] != expected or value["secrets_disclosed"] is not False:
        raise HTTPJSONIntegrationError("status assertion is inconsistent")
    age = now - value["checked_at"]
    fresh = -MAX_FUTURE_SKEW_SECONDS <= age <= maximum_age
    return value, max(age, 0), fresh


def metrics(source_valid: bool, fresh: bool, ready: bool, checked_at: int, identities: int, not_ready: int) -> bytes:
    values = (
        ("telosieve_http_json_pki_source_valid", int(source_valid), "Whether the PKI status schema and boundary are valid."),
        ("telosieve_http_json_pki_fresh", int(fresh), "Whether the PKI status is within its configured age bound."),
        ("telosieve_http_json_pki_ready", int(ready), "Whether every configured PKI identity is ready."),
        ("telosieve_http_json_pki_status_checked_unixtime_seconds", checked_at, "Unix time of the last valid PKI status check."),
        ("telosieve_http_json_pki_identities", identities, "Number of identities in the last valid PKI status."),
        ("telosieve_http_json_pki_not_ready", not_ready, "Number of identities not ready in the last valid PKI status."),
    )
    lines = []
    for name, value, help_text in values:
        lines.extend((f"# HELP {name} {help_text}", f"# TYPE {name} gauge", f"{name} {value}"))
    return ("\n".join(lines) + "\n").encode()


def publish(path_value: str, payload: bytes) -> None:
    path = Path(path_value)
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        raise HTTPJSONIntegrationError("metrics output path is invalid")
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & 0o022:
            raise HTTPJSONIntegrationError("existing metrics boundary is unsafe")
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(raw)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--status", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--maximum-age-seconds", required=True, type=int)
    args = parser.parse_args()
    if not 60 <= args.maximum_age_seconds <= MAX_AGE_SECONDS:
        raise HTTPJSONIntegrationError("maximum age is outside its bound")
    source_valid = fresh = ready = False
    checked_at = identities = not_ready = 0
    try:
        value, _age, fresh = validate(safe_read(args.status), int(time.time()), args.maximum_age_seconds)
        source_valid = True
        checked_at = value["checked_at"]
        identities = value["identities"]
        not_ready = value["not_ready"]
        ready = fresh and value["status"] == "ready"
    except HTTPJSONIntegrationError:
        pass
    publish(args.output, metrics(source_valid, fresh, ready, checked_at, identities, not_ready))
    return 0 if source_valid and fresh and ready else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HTTPJSONIntegrationError, OSError) as error:
        raise SystemExit(f"http-json-pki-prometheus: {error}") from error
