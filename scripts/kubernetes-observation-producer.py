#!/usr/bin/env python3
"""Collect and sign one read-only Kubernetes observation for Telosieve."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def run(arguments: list[str], maximum: int = 1024 * 1024) -> bytes:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        result = subprocess.run(arguments, stdout=stdout, stderr=stderr,
                                check=False, timeout=3)
        if result.returncode or stdout.tell() > maximum or stderr.tell() > 16 * 1024:
            raise SystemExit("kubernetes-observation-producer: bounded command failed")
        stdout.seek(0)
        return stdout.read(maximum + 1)


def bounded_file(path: Path, maximum: int, label: str) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise SystemExit(f"kubernetes-observation-producer: invalid {label}")
    value = path.read_bytes()
    if len(value) > maximum:
        raise SystemExit(f"kubernetes-observation-producer: oversized {label}")
    return value


def identity(value: dict) -> dict:
    metadata = value["metadata"]
    return {
        "api_version": value["apiVersion"], "kind": value["kind"],
        "namespace": metadata["namespace"], "name": metadata["name"],
        "uid": metadata["uid"], "resource_version": metadata["resourceVersion"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    for field in ("kubectl", "kubeconfig", "context", "namespace", "configmap",
                  "statefulset", "scenario", "telosieve", "key", "producer",
                  "key-id", "domain", "issued", "expires"):
        parser.add_argument(f"--{field}", required=True)
    args = parser.parse_args()
    common = [args.kubectl, f"--kubeconfig={args.kubeconfig}",
              f"--context={args.context}", f"--namespace={args.namespace}"]
    get = lambda *items: json.loads(run([*common, "get", *items, "-o", "json"]))
    desired = get("configmap", args.configmap)
    before = get("statefulset", args.statefulset)
    labels = before["spec"]["selector"].get("matchLabels", {})
    selector = ",".join(f"{key}={labels[key]}" for key in sorted(labels))
    pods = get("pods", f"--selector={selector}")
    after = get("statefulset", args.statefulset)
    if before != after:
        raise SystemExit("kubernetes-observation-producer: controller drifted")
    scenario = json.loads(bounded_file(Path(args.scenario), 2 * 1024 * 1024, "scenario"))
    desired_values = json.loads(desired["metadata"].get("annotations", {}).get(
        "telosieve.io/values", json.dumps(desired.get("data", {}))))
    replicas = {}
    for pod in sorted(pods["items"], key=lambda item: item["metadata"]["name"]):
        replicas[pod["metadata"]["name"]] = dict(sorted(json.loads(
            pod["metadata"]["annotations"]["telosieve.io/values"]).items()))
    snapshot = {
        "schema_version": "telosieve.kubernetes-shadow/v1",
        "subject": scenario["subject"], "captured_at": scenario["evaluation_time"],
        "desired": {"metadata": identity(desired), "target": identity(before),
                    "data": dict(sorted(desired_values.items()))},
        "observed": {"metadata": identity(before),
                     "generation": before["metadata"].get("generation", 0),
                     "observed_generation": before["status"]["observedGeneration"],
                     "complete": True, "replicas": replicas},
    }
    snapshot_bytes = json.dumps(snapshot, separators=(",", ":")).encode()
    descriptor, raw_path = tempfile.mkstemp(prefix="telosieve-observation-")
    os.close(descriptor)
    snapshot_path = Path(raw_path)
    attestation_path = snapshot_path.with_suffix(".attestation")
    try:
        snapshot_path.write_bytes(snapshot_bytes)
        command = [args.telosieve, "observation-sign", str(snapshot_path), args.key,
                   scenario["subject"], "kubernetes-live", args.producer,
                   args.key_id, args.domain, args.issued, args.expires,
                   str(attestation_path)]
        run(command, 64 * 1024)
        envelope = {"schema_version": "telosieve.observation-source/v1",
                    "snapshot": snapshot,
                    "attestation": json.loads(bounded_file(attestation_path, 64 * 1024,
                                                           "attestation"))}
        print(json.dumps(envelope, separators=(",", ":")))
    finally:
        snapshot_path.unlink(missing_ok=True)
        attestation_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
