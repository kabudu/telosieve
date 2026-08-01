#!/usr/bin/env python3
"""Qualify fail-closed Prometheus publication from PKI monitor status."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = (ROOT / "scripts/http-json-pki-prometheus.py").resolve()


def run(status: Path, output: Path, success: bool) -> bytes:
    result = subprocess.run(
        [sys.executable, str(PUBLISHER), "--status", str(status), "--output", str(output),
         "--maximum-age-seconds", "300"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=5, env={"LC_ALL": "C"},
    )
    if (result.returncode == 0) != success:
        raise SystemExit("pki-prometheus-qualification: publisher exit status is invalid")
    if result.stdout or len(result.stderr) > 1024:
        raise SystemExit("pki-prometheus-qualification: publisher diagnostics are invalid")
    return output.read_bytes()


def status(now: int, *, ready: int = 3, not_ready: int = 0, state: str = "ready") -> dict:
    return {"schema_version": "telosieve.http-json-pki-monitor-status/v1", "checked_at": now,
            "identities": 3, "ready": ready, "not_ready": not_ready,
            "renew_before_seconds": 3600, "secrets_disclosed": False, "status": state}


def write(path: Path, value) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")))
    path.chmod(0o600)


def main() -> None:
    now = int(time.time())
    refusals = 0
    with tempfile.TemporaryDirectory(prefix="telosieve-pki-prometheus-") as raw:
        work = Path(raw)
        source = work / "status.json"
        output = work / "telosieve.prom"
        write(source, status(now))
        output.write_text("stale output\n"); output.chmod(0o644)
        previous_inode = output.stat().st_ino
        ready_metrics = run(source, output, True)
        if (b"telosieve_http_json_pki_ready 1\n" not in ready_metrics
                or b"telosieve_http_json_pki_source_valid 1\n" not in ready_metrics
                or f"telosieve_http_json_pki_status_checked_unixtime_seconds {now}\n".encode() not in ready_metrics
                or output.stat().st_ino == previous_inode
                or stat.S_IMODE(output.stat().st_mode) != 0o644):
            raise SystemExit("pki-prometheus-qualification: ready publication is invalid")

        cases = [
            status(now, ready=2, not_ready=1, state="not-ready"),
            status(now - 301),
            status(now + 120),
            status(-1),
            {"malformed": True},
            status(now, ready=3, not_ready=1),
        ]
        for value in cases:
            write(source, value)
            published = run(source, output, False); refusals += 1
            if b"telosieve_http_json_pki_ready 0\n" not in published:
                raise SystemExit("pki-prometheus-qualification: refusal published ready state")

        write(source, status(now)); source.chmod(0o644)
        published = run(source, output, False); refusals += 1
        if b"telosieve_http_json_pki_source_valid 0\n" not in published:
            raise SystemExit("pki-prometheus-qualification: unsafe source was not invalidated")
        source.unlink()
        published = run(source, output, False); refusals += 1
        if b"telosieve_http_json_pki_source_valid 0\n" not in published:
            raise SystemExit("pki-prometheus-qualification: missing source was not invalidated")
        if str(source).encode() in published or str(output).encode() in published:
            raise SystemExit("pki-prometheus-qualification: path disclosed in metrics")

        print(json.dumps({"schema_version": "telosieve.http-json-pki-prometheus-qualification/v1",
                          "ready_publications": 1, "refusals": refusals,
                          "atomic_publication": True, "fixed_cardinality_metrics": 6,
                          "path_disclosures": 0, "independent_evidence": False,
                          "status": "passed"}, separators=(",", ":")))


if __name__ == "__main__":
    main()
