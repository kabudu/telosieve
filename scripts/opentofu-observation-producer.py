#!/usr/bin/env python3
"""Render and sign one saved OpenTofu plan observation for Telosieve."""

import argparse
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path


MAX_PLAN_FILE_BYTES = 128 * 1024 * 1024
MAX_RENDERED_BYTES = 2 * 1024 * 1024
MAX_ATTESTATION_BYTES = 64 * 1024
MAX_STDERR_BYTES = 16 * 1024
COMMAND_TIMEOUT_SECONDS = 3


def regular_file(value: str, maximum: int, label: str, executable: bool = False) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise SystemExit(f"opentofu-observation-producer: invalid {label}")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > maximum:
        raise SystemExit(f"opentofu-observation-producer: invalid {label}")
    if executable and (metadata.st_mode & 0o111 == 0 or metadata.st_mode & 0o022):
        raise SystemExit(f"opentofu-observation-producer: unsafe executable {label}")
    return path


def run(arguments: list[str], maximum: int) -> bytes:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            result = subprocess.run(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                check=False,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as error:
            raise SystemExit("opentofu-observation-producer: bounded command timed out") from error
        if result.returncode or stdout.tell() > maximum or stderr.tell() > MAX_STDERR_BYTES:
            raise SystemExit("opentofu-observation-producer: bounded command failed")
        stdout.seek(0)
        return stdout.read(maximum + 1)


def bounded_file(path: Path, maximum: int, label: str) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise SystemExit(f"opentofu-observation-producer: invalid {label}")
    value = path.read_bytes()
    if len(value) > maximum:
        raise SystemExit(f"opentofu-observation-producer: oversized {label}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    for field in (
        "tofu", "plan", "telosieve", "key", "subject", "producer", "key-id",
        "domain", "issued", "expires",
    ):
        parser.add_argument(f"--{field}", required=True)
    args = parser.parse_args()

    tofu = regular_file(args.tofu, 128 * 1024 * 1024, "tofu executable", True)
    plan = regular_file(args.plan, MAX_PLAN_FILE_BYTES, "saved plan")
    telosieve = regular_file(args.telosieve, 128 * 1024 * 1024, "telosieve executable", True)
    key = regular_file(args.key, 4096, "signing key")
    rendered = run([str(tofu), "show", "-json", str(plan)], MAX_RENDERED_BYTES)
    try:
        parsed = json.loads(rendered)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit("opentofu-observation-producer: rendered plan JSON is invalid") from error
    if not isinstance(parsed, dict):
        raise SystemExit("opentofu-observation-producer: rendered plan must be an object")

    descriptor, raw_path = tempfile.mkstemp(prefix="telosieve-opentofu-observation-")
    os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(rendered)
    rendered_path = Path(raw_path)
    attestation_path = rendered_path.with_suffix(".attestation")
    try:
        run(
            [
                str(telosieve), "observation-sign", str(rendered_path), str(key),
                args.subject, "opentofu-plan", args.producer, args.key_id,
                args.domain, args.issued, args.expires, str(attestation_path),
            ],
            MAX_ATTESTATION_BYTES,
        )
        attestation = json.loads(
            bounded_file(attestation_path, MAX_ATTESTATION_BYTES, "attestation")
        )
        envelope = {
            "schema_version": "telosieve.observation-source/v1",
            "input_hex": rendered.hex(),
            "attestation": attestation,
        }
        print(json.dumps(envelope, separators=(",", ":")))
    finally:
        rendered_path.unlink(missing_ok=True)
        attestation_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
