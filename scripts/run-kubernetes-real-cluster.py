#!/usr/bin/env python3
"""Run Telosieve end to end against a disposable real Kubernetes API server."""
import json
import os
import resource
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIND_IMAGE = "kindest/node@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NAMESPACE = "telosieve-research"
MAX_SECONDS = 120
MAX_PEAK_RSS_BYTES = 512 * 1024 * 1024
LOAD_EVALUATIONS = 8
LOAD_CONCURRENCY = 4
MAX_LOAD_SECONDS = 30
LOAD_CASE_TIMEOUT_SECONDS = 5
PRODUCER = (ROOT / "scripts/kubernetes-observation-producer.py").resolve()
RELAY = (ROOT / "scripts/observation-source-relay.py").resolve()
RELAY_CLIENT = (ROOT / "scripts/observation-source-client.py").resolve()


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


def observation_material(binary, work, restricted, scenario):
    specifications = (("producer-a", "key-a", "api-reader-a", "0b" * 32),
                      ("producer-b", "key-b", "api-reader-b", "0c" * 32))
    keys, sources = [], []
    for producer, key_id, domain, seed in specifications:
        key = work / f"{producer}.key"
        key.write_text(seed, encoding="ascii")
        key.chmod(0o600)
        public = run([str(binary), "observation-public-key", str(key)]).stdout.decode().strip()
        keys.append({"producer": producer, "key_id": key_id, "fault_domain": domain,
                     "public_key": public, "not_before": 1750000000,
                     "not_after": 1750001000})
        arguments = ["--kubectl", str(Path("/usr/local/bin/kubectl").resolve()),
                     "--kubeconfig", str(restricted.resolve()), "--context", "evaluation",
                     "--namespace", NAMESPACE, "--configmap", "repair-goal",
                     "--statefulset", "research-kv", "--scenario", str(scenario),
                     "--telosieve", str(binary), "--key", str(key), "--producer", producer,
                     "--key-id", key_id, "--domain", domain, "--issued", "1750000000",
                     "--expires", "1750000300"]
        sources.append({"executable_path": str(PRODUCER), "arguments": arguments})
    trust = work / "observation-trust.json"
    trust.write_text(json.dumps({"schema_version": "telosieve.observation-trust/v1",
                                 "evaluation_time": 1750000100,
                                 "required_distinct_domains": 2, "keys": keys},
                                separators=(",", ":")), encoding="utf-8")
    return trust, sources


def relay_sources(work, sources):
    relayed, processes = [], []
    for index, source in enumerate(sources):
        token = work / f"relay-{index}.token"
        token.write_bytes(bytes([65 + index]) * 32)
        token.chmod(0o440)
        socket_path = work / f"relay-{index}.sock"
        relay_config = work / f"relay-{index}.json"
        relay_config.write_text(json.dumps({
            "schema_version": "telosieve.observation-relay/v1",
            "socket_path": str(socket_path),
            "token_path": str(token),
            "producer": source,
        }, separators=(",", ":")), encoding="utf-8")
        process = subprocess.Popen(
            [str(RELAY), "--config", str(relay_config)], cwd=ROOT,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        processes.append(process)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if socket_path.exists():
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    probe.settimeout(0.05)
                    probe.connect(str(socket_path))
                    break
                except (ConnectionRefusedError, FileNotFoundError):
                    pass
                finally:
                    probe.close()
            if process.poll() is not None:
                _, error = process.communicate()
                stop_relays(processes)
                raise SystemExit(
                    "kubernetes-e2e: observation relay failed: "
                    + error.decode(errors="replace")[-1024:]
                )
            time.sleep(0.01)
        else:
            stop_relays(processes)
            raise SystemExit("kubernetes-e2e: observation relay readiness timed out")
        try:
            health = run([
                str(RELAY_CLIENT), "--socket", str(socket_path),
                "--token", str(token), "--check",
            ], timeout=3)
            health_ready = json.loads(health.stdout).get("status") == "ready"
        except BaseException:
            stop_relays(processes)
            raise
        if not health_ready:
            stop_relays(processes)
            raise SystemExit("kubernetes-e2e: observation relay health failed")
        relayed.append({
            "executable_path": str(RELAY_CLIENT),
            "arguments": ["--socket", str(socket_path), "--token", str(token)],
        })
    return relayed, processes


def stop_relays(processes):
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def evaluate_load(binary, work, restricted, trust, sources):
    def one(index):
        case = work / f"load-{index}"
        case.mkdir()
        config_path = case / "evaluation.json"
        config_path.write_text(json.dumps({
            "schema_version": "telosieve.evaluation-config/v5", "mode": "kubernetes-live",
            "scenario_path": str((ROOT / "scenarios/kubernetes-real-cluster.json").resolve()),
            "certificate_path": str(case / "certificate.json"), "ledger_path": str(case / "ledger.jsonl"),
            "observation_trust_path": str(trust), "observation_sources": sources,
            "kubernetes": {"kubectl_path": str(Path("/usr/local/bin/kubectl").resolve()), "kubeconfig_path": str(restricted.resolve()), "context": "evaluation", "namespace": NAMESPACE, "desired_config_map": "repair-goal", "observed_stateful_set": "research-kv"}
        }), encoding="utf-8")
        evaluation = run(
            [str(binary), "evaluate", str(config_path)],
            timeout=LOAD_CASE_TIMEOUT_SECONDS,
        )
        report = json.loads(evaluation.stdout)
        if report["target_mutated"] or report["mode"] != "kubernetes-live":
            raise RuntimeError(f"kubernetes load evaluation {index} returned an invalid report")
        if not (case / "certificate.json").is_file() or len((case / "ledger.jsonl").read_text().splitlines()) != 1:
            raise RuntimeError(f"kubernetes load evaluation {index} did not persist exact evidence")

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=LOAD_CONCURRENCY) as pool:
        futures = [pool.submit(one, index) for index in range(LOAD_EVALUATIONS)]
        for future in futures:
            future.result(timeout=MAX_LOAD_SECONDS)
    elapsed = time.monotonic() - started
    if elapsed > MAX_LOAD_SECONDS:
        raise SystemExit("kubernetes-e2e: sustained load exceeded its time bound")
    return round(elapsed, 3)


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
            binary = (ROOT / "target/debug/telosieve").resolve()
            scenario = (ROOT / "scenarios/kubernetes-real-cluster.json").resolve()
            trust, direct_sources = observation_material(binary, work, restricted, scenario)
            access = lambda *args: run(["kubectl", f"--kubeconfig={restricted}", "--context=evaluation", *args], check=False).stdout.decode().strip()
            if access("auth", "can-i", "get", "configmap/repair-goal", f"--namespace={NAMESPACE}") != "yes":
                raise SystemExit("kubernetes-e2e: required ConfigMap read denied")
            for request in (("patch", "configmap/repair-goal"), ("get", "secret/must-not-read"), ("delete", "statefulset/research-kv")):
                if access("auth", "can-i", *request, f"--namespace={NAMESPACE}") != "no":
                    raise SystemExit(f"kubernetes-e2e: unsafe permission granted: {request}")
            sources, relay_processes = relay_sources(work, direct_sources)
            try:
                config_path = work / "evaluation.json"
                config_path.write_text(json.dumps({
                    "schema_version": "telosieve.evaluation-config/v5", "mode": "kubernetes-live",
                    "scenario_path": str(scenario),
                    "certificate_path": str(work / "certificate.json"), "ledger_path": str(work / "ledger.jsonl"),
                    "observation_trust_path": str(trust), "observation_sources": sources,
                    "kubernetes": {"kubectl_path": str(Path("/usr/local/bin/kubectl").resolve()), "kubeconfig_path": str(restricted.resolve()), "context": "evaluation", "namespace": NAMESPACE, "desired_config_map": "repair-goal", "observed_stateful_set": "research-kv"}
                }), encoding="utf-8")
                before = json.loads(kubectl(admin_config, "get", "statefulset/research-kv", f"--namespace={NAMESPACE}", "-o", "json").stdout)
                evaluation = run([str(binary), "evaluate", str(config_path)], timeout=30)
                report = json.loads(evaluation.stdout)
                if report["target_mutated"] or report["mode"] != "kubernetes-live":
                    raise SystemExit("kubernetes-e2e: invalid success report")
                load_elapsed = evaluate_load(binary, work, restricted, trust, sources)
                after = json.loads(kubectl(admin_config, "get", "statefulset/research-kv", f"--namespace={NAMESPACE}", "-o", "json").stdout)
                for field in ("uid", "resourceVersion", "generation"):
                    if before["metadata"].get(field) != after["metadata"].get(field):
                        raise SystemExit(f"kubernetes-e2e: target changed during evaluation: {field}")
                altered = json.dumps({"metadata": {"annotations": {"telosieve.io/values": json.dumps({"cluster/epoch": "7", "user/message": "untrusted"}, separators=(",", ":"))}}})
                kubectl(admin_config, "patch", "configmap/repair-goal", f"--namespace={NAMESPACE}", "--type=merge", "-p", altered)
                (work / "certificate.json").unlink()
                (work / "ledger.jsonl").unlink()
                refusal = run([str(binary), "evaluate", str(config_path)], timeout=30, check=False)
                if refusal.returncode == 0 or (work / "certificate.json").exists() or (work / "ledger.jsonl").exists():
                    raise SystemExit("kubernetes-e2e: authority mismatch did not fail closed")
                paused = False
                try:
                    run(["docker", "pause", f"{cluster_name}-control-plane"])
                    paused = True
                    outage = run([str(binary), "evaluate", str(config_path)], timeout=30, check=False)
                finally:
                    if paused:
                        run(["docker", "unpause", f"{cluster_name}-control-plane"])
                if outage.returncode == 0 or (work / "certificate.json").exists() or (work / "ledger.jsonl").exists():
                    raise SystemExit("kubernetes-e2e: API outage did not fail closed")
                relay_processes[0].terminate()
                relay_processes[0].wait(timeout=2)
                relay_outage = run(
                    [str(binary), "evaluate", str(config_path)],
                    timeout=30, check=False,
                )
                if relay_outage.returncode == 0 or (work / "certificate.json").exists() or (work / "ledger.jsonl").exists():
                    raise SystemExit("kubernetes-e2e: relay outage did not fail closed")
                server = json.loads(kubectl(admin_config, "version", "-o", "json").stdout)["serverVersion"]["gitVersion"]
            finally:
                stop_relays(relay_processes)
                if any(work.glob("relay-*.sock")):
                    raise SystemExit("kubernetes-e2e: observation relay socket cleanup failed")
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
    result = {"schema_version": "telosieve.kubernetes-real-cluster-qualification/v1", "server_version": server, "cluster_kind": "kind", "read_only_rbac": True, "real_api_server": True, "observation_source_processes": 2, "observation_transport": "authenticated-unix-relay", "observation_relays": 2, "configured_fault_domains": 2, "successful_evaluations": 1 + LOAD_EVALUATIONS, "load_evaluations": LOAD_EVALUATIONS, "load_concurrency": LOAD_CONCURRENCY, "load_case_timeout_seconds": LOAD_CASE_TIMEOUT_SECONDS, "load_elapsed_seconds": load_elapsed, "fail_closed_evaluations": 3, "relay_outage_refused": True, "target_mutated": False, "elapsed_seconds": elapsed, "peak_child_rss_bytes": peak_rss_bytes, "independent_evidence": False, "status": "passed"}
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
