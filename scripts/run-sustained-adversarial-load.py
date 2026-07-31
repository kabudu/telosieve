#!/usr/bin/env python3
"""Run bounded repeated resource attacks against every evaluation mode."""

from __future__ import annotations

import concurrent.futures
import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BINARY = (ROOT / "target/debug/telosieve").resolve()
FAKE_KUBECTL = (ROOT / "tests/fixtures/fake-kubectl").resolve()
RETAINED = ROOT / "results/sustained-adversarial-load.json"
CASES_PER_MODE = 16
MAX_CONCURRENCY = 4
CASE_TIMEOUT_SECONDS = 10
MAX_ELAPSED_SECONDS = 30
MAX_PEAK_RSS_BYTES = 512 * 1024 * 1024
SHADOW_ATTACK_BYTES = 1024 * 1024 + 1
OPENTOFU_ATTACK_BYTES = 2 * 1024 * 1024 + 1
LIVE_RESPONSE_ATTACK_BYTES = 1024 * 1024 + 1
MODES = ("kubernetes-shadow", "kubernetes-live", "opentofu-plan")


def config(case: Path, mode: str, hostile_input: Path, index: int) -> Path:
    common = {
        "scenario_path": str((ROOT / "scenarios/benign.json").resolve()),
        "certificate_path": str((case / f"certificate-{index}.json").resolve()),
        "ledger_path": str((case / f"ledger-{index}.jsonl").resolve()),
    }
    if mode == "kubernetes-shadow":
        value = {
            "schema_version": "telosieve.evaluation-config/v4",
            "mode": mode,
            "snapshot_path": str(hostile_input.resolve()),
            "observation_trust_path": str((ROOT / "evaluation/observation-trust.example.json").resolve()),
            "observation_quorum_path": str((ROOT / "evaluation/observation-quorum.example.json").resolve()),
            **common,
        }
    elif mode == "opentofu-plan":
        value = {
            "schema_version": "telosieve.evaluation-config/v6",
            "mode": mode,
            "plan_path": str(hostile_input.resolve()),
            "observation_trust_path": str((ROOT / "evaluation/observation-trust.example.json").resolve()),
            "observation_sources": [
                {"executable_path": "/bin/cat", "arguments": [str((ROOT / "evaluation/observation-quorum.example.json").resolve())]},
                {"executable_path": "/bin/cat", "arguments": [str((ROOT / "evaluation/observation-quorum.example.json").resolve())]},
            ],
            **common,
        }
    else:
        kubectl = case / "kubectl"
        shutil.copy2(FAKE_KUBECTL, kubectl)
        kubectl.chmod(0o700)
        kubeconfig = case / "kubeconfig"
        kubeconfig.write_text("bounded synthetic credential\n", encoding="utf-8")
        kubeconfig.chmod(0o600)
        value = {
            "schema_version": "telosieve.evaluation-config/v5",
            "mode": mode,
            **common,
            "observation_trust_path": str((ROOT / "evaluation/observation-trust.example.json").resolve()),
            "observation_sources": [
                {"executable_path": "/bin/cat", "arguments": [str((ROOT / "evaluation/observation-quorum.example.json").resolve())]},
                {"executable_path": "/bin/cat", "arguments": [str((ROOT / "evaluation/observation-quorum.example.json").resolve())]},
            ],
            "kubernetes": {
                "kubectl_path": str(kubectl.resolve()),
                "kubeconfig_path": str(kubeconfig.resolve()),
                "context": "evaluation",
                "namespace": "telosieve-research",
                "desired_config_map": "repair-goal",
                "observed_stateful_set": "research-kv",
            },
        }
    path = case / "evaluation.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def run_case(case: Path, mode: str, hostile_input: Path, index: int) -> None:
    config_path = config(case, mode, hostile_input, index)
    environment = os.environ.copy()
    if mode == "kubernetes-live":
        environment.update({
            "TELOSIEVE_KUBECTL_CASE": "oversized",
            "TELOSIEVE_KUBECTL_LOG": str(case / "calls.jsonl"),
            "TELOSIEVE_KUBECTL_COUNTER": str(case / "counter"),
        })
    process = subprocess.run(
        [str(BINARY), "evaluate", str(config_path)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        timeout=CASE_TIMEOUT_SECONDS,
    )
    certificate = case / f"certificate-{index}.json"
    temporary_certificate = certificate.with_suffix(".json.tmp")
    ledger = case / f"ledger-{index}.jsonl"
    if (
        process.returncode == 0
        or certificate.exists()
        or temporary_certificate.exists()
        or ledger.exists()
    ):
        raise RuntimeError(f"{mode} load case {index} did not fail closed")
    if len(process.stdout) + len(process.stderr) > 64 * 1024:
        raise RuntimeError(f"{mode} load case {index} emitted excessive diagnostics")


def run_mode(work: Path, mode: str, hostile_input: Path) -> None:
    cases = []
    for index in range(CASES_PER_MODE):
        case = work / mode / str(index)
        case.mkdir(parents=True)
        cases.append((case, mode, hostile_input, index))
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENCY) as pool:
        futures = [pool.submit(run_case, *arguments) for arguments in cases]
        for future in futures:
            future.result(timeout=CASE_TIMEOUT_SECONDS * 2)


def main() -> int:
    if not BINARY.is_file() or not os.access(BINARY, os.X_OK):
        raise SystemExit("sustained-load: build target/debug/telosieve first")
    retained = json.loads(RETAINED.read_bytes())
    expected = {
        "schema_version": "telosieve.sustained-adversarial-load/v1",
        "modes": list(MODES),
        "cases_per_mode": CASES_PER_MODE,
        "maximum_concurrency": MAX_CONCURRENCY,
        "case_timeout_seconds": CASE_TIMEOUT_SECONDS,
        "maximum_elapsed_seconds": MAX_ELAPSED_SECONDS,
        "maximum_peak_child_rss_bytes": MAX_PEAK_RSS_BYTES,
        "attack_bytes": {
            "kubernetes-shadow": SHADOW_ATTACK_BYTES,
            "kubernetes-live-response": LIVE_RESPONSE_ATTACK_BYTES,
            "opentofu-plan": OPENTOFU_ATTACK_BYTES,
        },
        "expected_refusals": CASES_PER_MODE * len(MODES),
        "target_mutated": False,
        "independent_evidence": False,
        "status": "passed",
    }
    if retained != expected:
        raise SystemExit("sustained-load: retained qualification contract drifted")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="telosieve-sustained-load-") as raw:
        work = Path(raw)
        shadow = work / "oversized-shadow.json"
        shadow.write_bytes(b" " * SHADOW_ATTACK_BYTES)
        plan = work / "oversized-plan.json"
        plan.write_bytes(b" " * OPENTOFU_ATTACK_BYTES)
        run_mode(work, "kubernetes-shadow", shadow)
        run_mode(work, "kubernetes-live", shadow)
        run_mode(work, "opentofu-plan", plan)
    elapsed = round(time.monotonic() - started, 3)
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    peak_bytes = peak if sys.platform == "darwin" else peak * 1024
    if elapsed > MAX_ELAPSED_SECONDS:
        raise SystemExit("sustained-load: elapsed time exceeds bound")
    if peak_bytes > MAX_PEAK_RSS_BYTES:
        raise SystemExit("sustained-load: peak child RSS exceeds bound")
    print(json.dumps({
        **expected,
        "elapsed_seconds": elapsed,
        "peak_child_rss_bytes": peak_bytes,
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
