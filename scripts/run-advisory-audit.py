#!/usr/bin/env python3
"""Run cargo-audit against the locally refreshed RustSec database."""

from __future__ import annotations

import datetime
import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LOCKFILE = ROOT / "Cargo.lock"
COMMAND = ("cargo", "audit", "--json")


def main() -> int:
    audit = subprocess.run(
        COMMAND,
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        report = json.loads(audit.stdout)
    except json.JSONDecodeError as error:
        print(f"advisory-audit: cargo-audit JSON failed: {error}", file=sys.stderr)
        if audit.stderr:
            print(audit.stderr.rstrip(), file=sys.stderr)
        return 2
    version = subprocess.run(
        ("cargo", "audit", "--version"),
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    vulnerabilities = report["vulnerabilities"]
    warnings = report["warnings"]
    status = (
        "passed"
        if audit.returncode == 0
        and vulnerabilities["count"] == 0
        and not warnings
        else "findings"
    )
    output = {
        "schema_version": "telosieve.advisory-audit/v1",
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "command": " ".join(COMMAND),
        "tool_version": version,
        "lockfile_sha256": hashlib.sha256(LOCKFILE.read_bytes()).hexdigest(),
        "database": report["database"],
        "vulnerabilities": vulnerabilities,
        "warnings": warnings,
        "accepted_findings": [],
        "status": status,
    }
    json.dump(output, sys.stdout, indent=2)
    sys.stdout.write("\n")
    if audit.stderr:
        print(audit.stderr.rstrip(), file=sys.stderr)
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
