#!/usr/bin/env python3
"""Independently collect and sign one Redis integration response."""

import argparse
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path

from redis_integration_common import CONTRACT, REQUEST_SCHEMA, RedisIntegrationError, collect


MAX_ATTESTATION_BYTES = 64 * 1024


def regular_file(value: str, maximum: int, label: str, executable: bool = False) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise RedisIntegrationError(f"invalid {label}")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > maximum:
        raise RedisIntegrationError(f"invalid {label}")
    if executable and (metadata.st_mode & 0o111 == 0 or metadata.st_mode & 0o022):
        raise RedisIntegrationError(f"unsafe {label}")
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    for field in ("host", "port", "credentials", "prefix", "integration-id", "resource-kind", "target-id", "subject", "evaluation-time", "telosieve", "key", "producer", "key-id", "domain", "issued", "expires"):
        parser.add_argument(f"--{field}", required=True)
    args = parser.parse_args()
    telosieve = regular_file(args.telosieve, 128 * 1024 * 1024, "Telosieve executable", True)
    key = regular_file(args.key, 4096, "signing key")
    request = {
        "schema_version": REQUEST_SCHEMA,
        "contract": CONTRACT,
        "operation": "observe",
        "integration_id": args.integration_id,
        "resource_kind": args.resource_kind,
        "target_id": args.target_id,
        "subject": args.subject,
        "evaluation_time": int(args.evaluation_time),
    }
    response = collect(request, args.host, int(args.port), args.credentials, args.prefix)
    descriptor, raw_path = tempfile.mkstemp(prefix="telosieve-redis-observation-")
    os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(response)
    response_path = Path(raw_path)
    attestation_path = response_path.with_suffix(".attestation")
    try:
        with tempfile.TemporaryFile() as error:
            result = subprocess.run(
                [str(telosieve), "observation-sign", str(response_path), str(key), args.subject,
                 "external-read-only", args.producer, args.key_id, args.domain, args.issued,
                 args.expires, str(attestation_path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=error,
                check=False, timeout=3,
            )
            if result.returncode or error.tell() > 16 * 1024:
                raise RedisIntegrationError("bounded observation signing failed")
        if attestation_path.is_symlink() or not attestation_path.is_file() or attestation_path.stat().st_size > MAX_ATTESTATION_BYTES:
            raise RedisIntegrationError("attestation output is invalid")
        attestation = json.loads(attestation_path.read_bytes())
        envelope = {"schema_version": "telosieve.observation-source/v1", "input_hex": response.hex(), "attestation": attestation}
        print(json.dumps(envelope, separators=(",", ":")))
    finally:
        response_path.unlink(missing_ok=True)
        attestation_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RedisIntegrationError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"redis-observation-producer: {error}") from error
