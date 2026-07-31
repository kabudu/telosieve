#!/usr/bin/env python3
"""Run Telosieve end to end against a disposable real Kubernetes API server."""
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
KIND_IMAGE = "kindest/node@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NAMESPACE = "telosieve-research"
MAX_SECONDS = 120
MAX_PEAK_RSS_BYTES = 512 * 1024 * 1024


def run(arguments, *, input_bytes=None, timeout=30, check=True, env=None):
    result = subprocess.run(
        arguments, cwd=ROOT, input=input_bytes, capture_output=True, check=False,
        timeout=timeout, env=env,
    )
    if check and result.returncode != 0:
        detail = result.stderr.decode(errors="replace")[-4096:]
        raise RuntimeError(f"command failed ({arguments[0]}): {detail}")
    return result


def kubectl(admin_config, *arguments, input_object=None, check=True, timeout=30):
    payload = None if input_object is None else json.dumps(input_object).encode()
    return run(
        ["kubectl", f"--kubeconfig={admin_config}", *arguments],
        input_bytes=payload, check=check, timeout=timeout,
    )


def resources():
    values = json.dumps({"cluster/epoch": "7", "user/message": "old"}, separators=(",", ":"))
    return {
        "apiVersion": "v1", "kind": "List", "items": [
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}},
            {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "telosieve-evaluation", "namespace": NAMESPACE}},
            {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "repair-goal", "namespace": NAMESPACE, "annotations": {"telosieve.io/values": json.dumps({"cluster/epoch": "7", "user/message": "new"}, separators=(",", ":"))}}},
            {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "must-not-read", "namespace": NAMESPACE}, "stringData": {"value": "not-for-telosieve"}},
            {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "research-kv", "namespace": NAMESPACE}, "spec": {"clusterIP": "None", "selector": {"app": "research-kv"}}},
            {"apiVersion": "apps/v1", "kind": "StatefulSet", "metadata": {"name": "research-kv", "namespace": NAMESPACE}, "spec": {
                "serviceName": "research-kv", "replicas": 3,
                "selector": {"matchLabels": {"app": "research-kv"}},
                "template": {"metadata": {"labels": {"app": "research-kv"}, "annotations": {"telosieve.io/values": values}}, "spec": {"containers": [{"name": "pause", "image": "registry.k8s.io/pause:3.10", "imagePullPolicy": "IfNotPresent"}]}}
            }},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "telosieve-evaluation-reader", "namespace": NAMESPACE}, "rules": [
                {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["repair-goal"], "verbs": ["get"]},
                {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
                {"apiGroups": ["apps"], "resources": ["statefulsets"], "resourceNames": ["research-kv"], "verbs": ["get"]}
            ]},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "telosieve-evaluation-reader", "namespace": NAMESPACE}, "subjects": [{"kind": "ServiceAccount", "name": "telosieve-evaluation", "namespace": NAMESPACE}], "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "telosieve-evaluation-reader"}}
        ]
    }


def restricted_config(admin_config, output):
    config = json.loads(
        kubectl(admin_config, "config", "view", "--raw", "-o", "json").stdout
    )
    cluster = config["clusters"][0]["cluster"]
    token = kubectl(
        admin_config, "create", "token", "telosieve-evaluation",
        f"--namespace={NAMESPACE}", "--duration=10m",
    ).stdout.decode().strip()
    value = {
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "evaluation", "cluster": cluster}],
        "users": [{"name": "evaluation", "user": {"token": token}}],
        "contexts": [{"name": "evaluation", "context": {"cluster": "evaluation", "user": "evaluation", "namespace": NAMESPACE}}],
        "current-context": "evaluation",
    }
    output.write_text(json.dumps(value), encoding="utf-8")
    output.chmod(0o600)


def main():
    for executable in ("docker", "kind", "kubectl"):
        if shutil.which(executable) is None:
            raise SystemExit(f"kubernetes-e2e: required executable is missing: {executable}")
    if run(["docker", "image", "inspect", KIND_IMAGE], check=False).returncode != 0:
        raise SystemExit("kubernetes-e2e: pinned kind node image is not cached")
    started = time.monotonic()
    cluster_name = f"telosieve-e2e-{os.getpid()}"
    created = True
    cleanup_ok = True
    try:
        run(["kind", "create", "cluster", "--name", cluster_name, "--image", KIND_IMAGE, "--wait", "60s"], timeout=90)
        with tempfile.TemporaryDirectory(prefix="telosieve-kubernetes-e2e-") as temporary:
            work = Path(temporary)
            admin_config = work / "admin-kubeconfig"
            admin_config.write_bytes(run(["kind", "get", "kubeconfig", "--name", cluster_name]).stdout)
            admin_config.chmod(0o600)
            kubectl(admin_config, "apply", "-f", "-", input_object=resources(), timeout=30)
            kubectl(admin_config, "rollout", "status", "statefulset/research-kv", f"--namespace={NAMESPACE}", "--timeout=60s", timeout=70)
            restricted = work / "evaluation-kubeconfig"
            restricted_config(admin_config, restricted)
            access = lambda *args: run(["kubectl", f"--kubeconfig={restricted}", "--context=evaluation", *args], check=False).stdout.decode().strip()
            if access("auth", "can-i", "get", "configmap/repair-goal", f"--namespace={NAMESPACE}") != "yes":
                raise SystemExit("kubernetes-e2e: required ConfigMap read denied")
            for request in (("patch", "configmap/repair-goal"), ("get", "secret/must-not-read"), ("delete", "statefulset/research-kv")):
                if access("auth", "can-i", *request, f"--namespace={NAMESPACE}") != "no":
                    raise SystemExit(f"kubernetes-e2e: unsafe permission granted: {request}")
            config_path = work / "evaluation.json"
            config_path.write_text(json.dumps({
                "schema_version": "telosieve.evaluation-config/v2", "mode": "kubernetes-live",
                "scenario_path": str((ROOT / "scenarios/kubernetes-real-cluster.json").resolve()),
                "certificate_path": str(work / "certificate.json"), "ledger_path": str(work / "ledger.jsonl"),
                "kubernetes": {"kubectl_path": str(Path("/usr/local/bin/kubectl").resolve()), "kubeconfig_path": str(restricted.resolve()), "context": "evaluation", "namespace": NAMESPACE, "desired_config_map": "repair-goal", "observed_stateful_set": "research-kv"}
            }), encoding="utf-8")
            before = json.loads(kubectl(admin_config, "get", "statefulset/research-kv", f"--namespace={NAMESPACE}", "-o", "json").stdout)
            evaluation = run([str((ROOT / "target/debug/telosieve").resolve()), "evaluate", str(config_path)], timeout=30)
            report = json.loads(evaluation.stdout)
            if report["target_mutated"] or report["mode"] != "kubernetes-live":
                raise SystemExit("kubernetes-e2e: invalid success report")
            after = json.loads(kubectl(admin_config, "get", "statefulset/research-kv", f"--namespace={NAMESPACE}", "-o", "json").stdout)
            for field in ("uid", "resourceVersion", "generation"):
                if before["metadata"].get(field) != after["metadata"].get(field):
                    raise SystemExit(f"kubernetes-e2e: target changed during evaluation: {field}")
            altered = json.dumps({"metadata": {"annotations": {"telosieve.io/values": json.dumps({"cluster/epoch": "7", "user/message": "untrusted"}, separators=(",", ":"))}}})
            kubectl(admin_config, "patch", "configmap/repair-goal", f"--namespace={NAMESPACE}", "--type=merge", "-p", altered)
            (work / "certificate.json").unlink()
            (work / "ledger.jsonl").unlink()
            refusal = run([str((ROOT / "target/debug/telosieve").resolve()), "evaluate", str(config_path)], timeout=30, check=False)
            if refusal.returncode == 0 or (work / "certificate.json").exists() or (work / "ledger.jsonl").exists():
                raise SystemExit("kubernetes-e2e: authority mismatch did not fail closed")
            paused = False
            try:
                run(["docker", "pause", f"{cluster_name}-control-plane"])
                paused = True
                outage = run([str((ROOT / "target/debug/telosieve").resolve()), "evaluate", str(config_path)], timeout=30, check=False)
            finally:
                if paused:
                    run(["docker", "unpause", f"{cluster_name}-control-plane"])
            if outage.returncode == 0 or (work / "certificate.json").exists() or (work / "ledger.jsonl").exists():
                raise SystemExit("kubernetes-e2e: API outage did not fail closed")
            server = json.loads(kubectl(admin_config, "version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
    finally:
        if created:
            cleanup = run(["kind", "delete", "cluster", "--name", cluster_name], timeout=60, check=False)
            cleanup_ok = cleanup.returncode == 0
    if not cleanup_ok:
        raise SystemExit("kubernetes-e2e: disposable cluster cleanup failed")
    elapsed = round(time.monotonic() - started, 3)
    if elapsed > MAX_SECONDS:
        raise SystemExit("kubernetes-e2e: elapsed time exceeds bound")
    peak_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    peak_rss_bytes = peak_rss if sys.platform == "darwin" else peak_rss * 1024
    if peak_rss_bytes > MAX_PEAK_RSS_BYTES:
        raise SystemExit("kubernetes-e2e: peak child RSS exceeds bound")
    result = {"schema_version": "telosieve.kubernetes-real-cluster-qualification/v1", "server_version": server, "cluster_kind": "kind", "read_only_rbac": True, "real_api_server": True, "successful_evaluations": 1, "fail_closed_evaluations": 2, "target_mutated": False, "elapsed_seconds": elapsed, "peak_child_rss_bytes": peak_rss_bytes, "independent_evidence": False, "status": "passed"}
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
