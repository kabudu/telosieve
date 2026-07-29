#!/usr/bin/env python3
"""Validate retained dependency inventory and advisory evidence."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LOCKFILE = ROOT / "Cargo.lock"
COMMIT = re.compile(r"[0-9a-f]{40}")
MAX_AUDIT_AGE = datetime.timedelta(days=30)
EXPECTED_AUDIT_VERSION = "cargo-audit-audit 0.22.1"


def fail(message: str) -> None:
    raise ValueError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--inventory",
        type=Path,
        default=ROOT / "results/dependency-inventory.json",
    )
    parser.add_argument(
        "--audit",
        type=Path,
        default=ROOT / "results/advisory-audit.json",
    )
    arguments = parser.parse_args()
    try:
        subprocess.run(
            (
                "python3",
                "scripts/dependency-inventory.py",
                "--check",
                str(arguments.inventory),
            ),
            cwd=ROOT,
            check=True,
        )
        audit = json.loads(arguments.audit.read_text(encoding="utf-8"))
        expected_keys = {
            "schema_version",
            "generated_at",
            "command",
            "tool_version",
            "lockfile_sha256",
            "database",
            "vulnerabilities",
            "warnings",
            "accepted_findings",
            "status",
        }
        if not isinstance(audit, dict) or set(audit) != expected_keys:
            fail("advisory result fields do not exactly match the v1 schema")
        if audit["schema_version"] != "telosieve.advisory-audit/v1":
            fail("unsupported advisory result schema")
        generated_at = datetime.datetime.fromisoformat(audit["generated_at"])
        now = datetime.datetime.now(datetime.UTC)
        if generated_at.tzinfo is None:
            fail("advisory audit timestamp must include a timezone")
        if generated_at > now + datetime.timedelta(minutes=5):
            fail("advisory audit timestamp is in the future")
        if now - generated_at > MAX_AUDIT_AGE:
            fail("advisory audit is older than 30 days; refresh it")
        if audit["command"] != "cargo audit --json":
            fail("advisory audit command changed")
        if audit["tool_version"] != EXPECTED_AUDIT_VERSION:
            fail("advisory audit tool version changed")
        actual_lock = hashlib.sha256(LOCKFILE.read_bytes()).hexdigest()
        if audit["lockfile_sha256"] != actual_lock:
            fail("advisory result does not match Cargo.lock")
        database = audit["database"]
        if (
            not isinstance(database, dict)
            or COMMIT.fullmatch(database.get("last-commit", "")) is None
            or not database.get("last-updated")
            or not isinstance(database.get("advisory-count"), int)
            or database["advisory-count"] <= 0
        ):
            fail("advisory database provenance is incomplete")
        database_updated = datetime.datetime.fromisoformat(database["last-updated"])
        if database_updated.tzinfo is None or database_updated > generated_at:
            fail("advisory database timestamp is inconsistent")
        vulnerabilities = audit["vulnerabilities"]
        warnings = audit["warnings"]
        accepted = audit["accepted_findings"]
        if (
            vulnerabilities != {"found": False, "count": 0, "list": []}
            or warnings
            or accepted
            or audit["status"] != "passed"
        ):
            fail("advisory findings require explicit documented resolution")
    except (
        OSError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"supply-chain-validation: {error}", file=sys.stderr)
        return 1
    print("supply-chain-validation: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
