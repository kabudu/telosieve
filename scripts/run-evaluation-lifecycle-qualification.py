#!/usr/bin/env python3
"""Exercise the complete private evaluation installation lifecycle."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "scripts/evaluation-lifecycle.py"
BINARY = (ROOT / "target/debug/telosieve").resolve()


def run(arguments: list[str], success: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["python3", str(TOOL), *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if (result.returncode == 0) != success:
        raise AssertionError(
            f"unexpected lifecycle result for {arguments}: "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    return result


def configuration(path: Path, installation: Path, certificate: str) -> None:
    value = {
        "schema_version": "telosieve.evaluation-config/v4",
        "mode": "kubernetes-shadow",
        "scenario_path": str((ROOT / "scenarios/benign.json").resolve()),
        "snapshot_path": str(
            (ROOT / "snapshots/kubernetes-shadow-benign.json").resolve()
        ),
        "observation_trust_path": str((ROOT / "evaluation/observation-trust.example.json").resolve()),
        "observation_quorum_path": str((ROOT / "evaluation/observation-quorum.example.json").resolve()),
        "certificate_path": str(installation / "evidence" / certificate),
        "ledger_path": str(installation / "evidence/ledger.jsonl"),
    }
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    os.chmod(path, 0o600)


def main() -> int:
    if not BINARY.is_file() or BINARY.stat().st_mode & 0o111 == 0:
        raise SystemExit("lifecycle-qualification: target/debug/telosieve is unavailable")
    with tempfile.TemporaryDirectory(prefix="telosieve-lifecycle-") as temporary:
        workspace = Path(temporary)
        root = workspace / "installation"
        config_v1 = workspace / "config-v1.json"
        config_v2 = workspace / "config-v2.json"
        backup = workspace / "backup-v1"
        tampered = workspace / "backup-tampered"
        configuration(config_v1, root.resolve(), "certificate-v1.json")
        configuration(config_v2, root.resolve(), "certificate-v2.json")

        run(
            [
                "install", "--root", str(root), "--binary", str(BINARY),
                "--config", str(config_v1),
            ]
        )
        version = subprocess.run(
            [str(root / "current/telosieve"), "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        ).stdout
        assert version.startswith("telosieve ")
        assert (root / "current/evaluation.json").read_bytes() == config_v1.read_bytes()
        evaluation = subprocess.run(
            [
                str(root / "current/telosieve"),
                "evaluate",
                str(root / "current/evaluation.json"),
            ],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        report = json.loads(evaluation.stdout)
        assert report["target_mutated"] is False
        assert (root / "evidence/certificate-v1.json").is_file()
        assert (root / "evidence/ledger.jsonl").is_file()
        run(
            [
                "install", "--root", str(root), "--binary", str(BINARY),
                "--config", str(config_v1),
            ],
            success=False,
        )

        evidence = root / "evidence/operator-record.json"
        evidence.write_text('{"retained":true}\n', encoding="utf-8")
        run(["backup", "--root", str(root), "--output", str(backup)])
        backup_manifest = json.loads((backup / "backup.json").read_bytes())
        assert backup_manifest["schema_version"] == "telosieve.evaluation-backup/v1"
        assert any(
            record["path"] == "evidence/operator-record.json"
            for record in backup_manifest["files"]
        )

        run(
            [
                "upgrade", "--root", str(root), "--binary", str(BINARY),
                "--config", str(config_v2),
            ]
        )
        assert (root / "current/evaluation.json").read_bytes() == config_v2.read_bytes()
        assert evidence.read_text(encoding="utf-8") == '{"retained":true}\n'
        invalid_config = workspace / "invalid-config.json"
        invalid_config.write_text(
            '{"schema_version":"telosieve.evaluation-config/v4",'
            '"schema_version":"telosieve.evaluation-config/v4"}',
            encoding="utf-8",
        )
        run(
            [
                "upgrade", "--root", str(root), "--binary", str(BINARY),
                "--config", str(invalid_config),
            ],
            success=False,
        )
        assert (root / "current/evaluation.json").read_bytes() == config_v2.read_bytes()

        (root / ".lifecycle.lock").mkdir()
        run(["backup", "--root", str(root), "--output", str(workspace / "locked")], success=False)
        (root / ".lifecycle.lock").rmdir()
        evidence_link = root / "evidence/link"
        evidence_link.symlink_to(config_v1)
        run(
            ["backup", "--root", str(root), "--output", str(workspace / "linked")],
            success=False,
        )
        evidence_link.unlink()
        evidence_directory = root / "evidence"
        evidence_real = root / "evidence-real"
        evidence_directory.rename(evidence_real)
        evidence_directory.symlink_to(evidence_real, target_is_directory=True)
        run(
            [
                "backup", "--root", str(root),
                "--output", str(workspace / "linked-directory"),
            ],
            success=False,
        )
        evidence_directory.unlink()
        evidence_real.rename(evidence_directory)
        run(
            ["backup", "--root", str(root), "--output", str(root / "inside-backup")],
            success=False,
        )

        shutil.copytree(backup, tampered)
        tampered_config = next((tampered / "release").glob("*/evaluation.json"))
        os.chmod(tampered_config, 0o600)
        tampered_config.write_text("{}\n", encoding="utf-8")
        run(
            ["rollback", "--root", str(root), "--backup", str(tampered)],
            success=False,
        )
        assert (root / "current/evaluation.json").read_bytes() == config_v2.read_bytes()

        run(["rollback", "--root", str(root), "--backup", str(backup)])
        assert (root / "current/evaluation.json").read_bytes() == config_v1.read_bytes()
        assert evidence.read_text(encoding="utf-8") == '{"retained":true}\n'

        run(
            ["uninstall", "--root", str(root), "--confirm-root", str(workspace)],
            success=False,
        )
        binary_link = workspace / "binary-link"
        binary_link.symlink_to(BINARY)
        run(
            [
                "install", "--root", str(workspace / "linked-install"),
                "--binary", str(binary_link), "--config", str(config_v1),
            ],
            success=False,
        )
        assert (root / "current").is_symlink()
        run(
            ["uninstall", "--root", str(root), "--confirm-root", str(root.resolve())]
        )
        assert not (root / "current").exists()
        assert not (root / "releases").exists()
        assert evidence.read_text(encoding="utf-8") == '{"retained":true}\n'

        run(
            [
                "install", "--root", "relative-root", "--binary", str(BINARY),
                "--config", str(config_v1),
            ],
            success=False,
        )

    print(
        json.dumps(
            {
                "schema_version": "telosieve.evaluation-lifecycle-qualification/v1",
                "phases": ["install", "backup", "upgrade", "rollback", "uninstall"],
                "refusals": [
                    "existing-install",
                    "duplicate-configuration-key",
                    "concurrent-lifecycle-lock",
                    "symlinked-evidence",
                    "symlinked-evidence-directory",
                    "in-root-backup",
                    "tampered-backup",
                    "wrong-uninstall-confirmation",
                    "relative-root",
                    "symlinked-binary",
                ],
                "evidence_preserved": True,
                "status": "passed",
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
