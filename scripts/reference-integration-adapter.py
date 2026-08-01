#!/usr/bin/env python3
"""Conformance-only adapter that returns one operator-supplied response."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(f"reference-integration-adapter: {message}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--response", required=True)
    arguments = parser.parse_args()
    response_path = Path(arguments.response)
    if not response_path.is_absolute() or response_path.is_symlink() or not response_path.is_file():
        fail("response must be an absolute regular file")
    metadata = response_path.stat()
    if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o022:
        fail("response must be single-link and not group/other writable")
    request_bytes = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(request_bytes) > MAX_REQUEST_BYTES:
        fail("request exceeds bound")
    try:
        request = json.loads(request_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("request is invalid JSON")
    required = {
        "schema_version", "contract", "operation", "integration_id",
        "resource_kind", "target_id", "subject", "evaluation_time",
    }
    if (
        not isinstance(request, dict)
        or set(request) != required
        or request["schema_version"] != "telosieve.integration-request/v1"
        or request["contract"] != "telosieve.integration-contract/v1"
        or request["operation"] != "observe"
    ):
        fail("request contract is invalid")
    with response_path.open("rb") as stream:
        response = stream.read(MAX_RESPONSE_BYTES + 1)
    if len(response) > MAX_RESPONSE_BYTES:
        fail("response exceeds bound")
    try:
        decoded = json.loads(response)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("response is invalid JSON")
    for response_key, request_key in (
        ("integration_id", "integration_id"),
        ("resource_kind", "resource_kind"),
        ("subject", "subject"),
        ("captured_at", "evaluation_time"),
    ):
        if decoded.get(response_key) != request[request_key]:
            fail(f"response {response_key} does not match request")
    if decoded.get("target", {}).get("id") != request["target_id"]:
        fail("response target does not match request")
    canonical = json.dumps(decoded, separators=(",", ":"), ensure_ascii=False).encode()
    os.write(sys.stdout.fileno(), canonical)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
