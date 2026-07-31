#!/usr/bin/env python3
"""Qualify bounded diagnostics and its privacy allowlist."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LIFECYCLE = ROOT / "scripts/evaluation-lifecycle.py"
DIAGNOSTICS = ROOT / "scripts/evaluation-diagnostics.py"
BINARY = (ROOT / "target/debug/telosieve").resolve()
SECRET = "TOP-SECRET-APPLICATION-VALUE"


def run(tool: Path, arguments: list[str], success: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["python3", str(tool), *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if (result.returncode == 0) != success:
        raise AssertionError(f"unexpected result: {arguments} {result.stdout!r} {result.stderr!r}")
    return result


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="telosieve-diagnostics-") as temporary:
        workspace = Path(temporary)
        install = workspace / "install"
        config = workspace / "config.json"
        output = workspace / "diagnostics.json"
        config.write_text(
            json.dumps(
                {
                    "schema_version": "telosieve.evaluation-config/v1",
                    "mode": "kubernetes-shadow",
                    "scenario_path": str((ROOT / "scenarios/benign.json").resolve()),
                    "snapshot_path": str(
                        (ROOT / "snapshots/kubernetes-shadow-benign.json").resolve()
                    ),
                    "certificate_path": str(install.resolve() / "evidence/certificate.json"),
                    "ledger_path": str(install.resolve() / "evidence/ledger.jsonl"),
                }
            ),
            encoding="utf-8",
        )
        os.chmod(config, 0o600)
        run(
            LIFECYCLE,
            [
                "install", "--root", str(install), "--binary", str(BINARY),
                "--config", str(config),
            ],
        )
        secret_path = install / "evidence/customer-name-and-secret.json"
        secret_path.write_text(json.dumps({"value": SECRET}), encoding="utf-8")
        os.chmod(secret_path, 0o600)
        run(DIAGNOSTICS, ["--root", str(install), "--output", str(output)])
        exported = json.loads(output.read_bytes())
        assert set(exported) == {
            "schema_version", "status", "privacy", "installation", "evidence", "checks"
        }
        assert set(exported["installation"]) == {
            "release_id", "binary_sha256", "configuration_sha256"
        }
        assert set(exported["evidence"]) == {"file_count", "total_bytes", "files"}
        assert all(set(record) == {"id", "sha256", "size"} for record in exported["evidence"]["files"])
        encoded = output.read_text(encoding="utf-8")
        assert SECRET not in encoded
        assert secret_path.name not in encoded
        assert str(install) not in encoded
        assert exported["privacy"] == {
            "content_included": False,
            "environment_included": False,
            "paths_included": False,
        }

        run(DIAGNOSTICS, ["--root", str(install), "--output", str(output)], success=False)
        link = install / "evidence/link"
        link.symlink_to(secret_path)
        refused = workspace / "refused.json"
        run(DIAGNOSTICS, ["--root", str(install), "--output", str(refused)], success=False)
        assert not refused.exists()
        link.unlink()
        os.chmod(secret_path, 0o644)
        run(DIAGNOSTICS, ["--root", str(install), "--output", str(refused)], success=False)
        assert not refused.exists()
        os.chmod(secret_path, 0o600)
        run(
            DIAGNOSTICS,
            ["--root", str(install), "--output", str(install / "inside.json")],
            success=False,
        )

    print(
        json.dumps(
            {
                "schema_version": "telosieve.diagnostics-qualification/v1",
                "exported": 1,
                "refused": 4,
                "secret_disclosures": 0,
                "status": "passed",
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
