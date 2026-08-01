#!/usr/bin/env python3
"""Qualify Telosieve against a disposable real Redis server with read-only ACLs."""

from __future__ import annotations

import json
import os
import pathlib
import resource
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

from redis_integration_common import RedisConnection, RedisIntegrationError


ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGE = "redis@sha256:9d317178eceac8454a2284a9e6df2466b93c745529947f0cd42a0fa9609d7005"
PREFIX = "telosieve:qualification"
INTEGRATION_ID = "redis"
RESOURCE_KIND = "replicated-key-value"
TARGET_ID = "redis/qualification"
MAX_SECONDS = 90
LOAD_EVALUATIONS = 8
LOAD_CONCURRENCY = 4
LOAD_TIMEOUT_SECONDS = 10
ADAPTER = (ROOT / "scripts/redis-integration-adapter.py").resolve()
PRODUCER = (ROOT / "scripts/redis-observation-producer.py").resolve()


def run(arguments: list[str], *, success: bool = True, timeout: int = 30) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(arguments, cwd=ROOT, stdin=subprocess.DEVNULL,
                            capture_output=True, check=False, timeout=timeout)
    if (result.returncode == 0) != success:
        raise RuntimeError(
            f"redis-e2e: unexpected exit {result.returncode}: {arguments[0]}\n"
            + result.stderr.decode(errors="replace")[-4096:]
        )
    return result


def credential(path: pathlib.Path, username: str, password: str) -> None:
    path.write_text(json.dumps({
        "schema_version": "telosieve.redis-credentials/v1",
        "username": username, "password": password,
    }, separators=(",", ":")))
    path.chmod(0o600)


def redis_command(port: int, username: str, password: str, *parts: str):
    with RedisConnection("127.0.0.1", port) as redis:
        if redis.command("AUTH", username, password) != "OK":
            raise RuntimeError("redis-e2e: authentication failed")
        return redis.command(*parts)


def seed(port: int, prefix: str, admin_password: str, *, revision: str = "revision-73", replicas: int = 3) -> None:
    command = lambda *parts: redis_command(port, "admin", admin_password, *parts)
    command("SET", f"{prefix}:revision", revision)
    command("HSET", f"{prefix}:desired", "cluster/epoch", "7", "user/message", "new")
    names = ["replica-a", "replica-b", "replica-c"] if replicas == 3 else [
        f"replica-{index + 1}" for index in range(replicas)
    ]
    for name in names:
        command("SADD", f"{prefix}:replicas", name)
        command("HSET", f"{prefix}:replica:{name}", "cluster/epoch", "7", "user/message", "old")


def observation_material(work: pathlib.Path, binary: pathlib.Path, port: int, credentials: list[pathlib.Path]):
    specifications = (
        ("producer-a", "key-a", "redis-reader-a", "21" * 32),
        ("producer-b", "key-b", "redis-reader-b", "22" * 32),
    )
    keys, sources = [], []
    for index, (producer, key_id, domain, seed_value) in enumerate(specifications):
        key = work / f"{producer}.key"
        key.write_text(seed_value); key.chmod(0o600)
        public = run([str(binary), "observation-public-key", str(key)]).stdout.decode().strip()
        keys.append({"producer": producer, "key_id": key_id, "fault_domain": domain,
                     "public_key": public, "not_before": 1750000000, "not_after": 1750001000})
        sources.append({"executable_path": str(PRODUCER), "arguments": [
            "--host", "127.0.0.1", "--port", str(port), "--credentials", str(credentials[index]),
            "--prefix", PREFIX, "--integration-id", INTEGRATION_ID,
            "--resource-kind", RESOURCE_KIND, "--target-id", TARGET_ID,
            "--subject", "kv/research", "--evaluation-time", "1750000000",
            "--telosieve", str(binary), "--key", str(key), "--producer", producer,
            "--key-id", key_id, "--domain", domain, "--issued", "1750000000",
            "--expires", "1750000300",
        ]})
    trust = work / "trust.json"
    trust.write_text(json.dumps({"schema_version": "telosieve.observation-trust/v1",
        "evaluation_time": 1750000100, "required_distinct_domains": 2, "keys": keys},
        separators=(",", ":")))
    return trust, sources


def configuration(work: pathlib.Path, binary: pathlib.Path, port: int,
                  adapter_credential: pathlib.Path, producer_credentials: list[pathlib.Path], stem: str):
    trust, sources = observation_material(work, binary, port, producer_credentials)
    value = {
        "schema_version": "telosieve.evaluation-config/v7", "mode": "external-read-only",
        "scenario_path": str((ROOT / "scenarios/benign.json").resolve()),
        "certificate_path": str((work / f"{stem}-certificate.json").resolve()),
        "ledger_path": str((work / f"{stem}-ledger.jsonl").resolve()),
        "observation_trust_path": str(trust.resolve()), "observation_sources": sources,
        "adapter": {"executable_path": str(ADAPTER), "arguments": [
            "--host", "127.0.0.1", "--port", str(port), "--credentials", str(adapter_credential),
            "--prefix", PREFIX], "integration_id": INTEGRATION_ID,
            "resource_kind": RESOURCE_KIND, "target_id": TARGET_ID},
    }
    path = work / f"{stem}-evaluation.json"
    path.write_text(json.dumps(value, separators=(",", ":")))
    return path, value


def assert_no_evidence(work: pathlib.Path, binary: pathlib.Path, config: pathlib.Path, stem: str) -> None:
    run([str(binary), "evaluate", str(config)], success=False, timeout=LOAD_TIMEOUT_SECONDS)
    if (work / f"{stem}-certificate.json").exists() or (work / f"{stem}-ledger.jsonl").exists():
        raise RuntimeError(f"redis-e2e: {stem} emitted evidence")


def main() -> None:
    started = time.monotonic()
    for executable in ("docker",):
        if shutil.which(executable) is None:
            raise SystemExit(f"redis-e2e: missing executable: {executable}")
    binary = (ROOT / "target/debug/telosieve").resolve()
    if not binary.is_file():
        raise SystemExit("redis-e2e: build target/debug/telosieve first")
    run(["docker", "image", "inspect", IMAGE])
    container = f"telosieve-redis-{os.getpid()}"
    created = False
    try:
        with tempfile.TemporaryDirectory(prefix="telosieve-redis-e2e-") as raw:
            work = pathlib.Path(raw)
            passwords = {"admin": "A" * 32, "adapter": "B" * 32,
                         "producer-a": "C" * 32, "producer-b": "D" * 32}
            acl = work / "users.acl"
            lines = ["user default off", f"user admin on >{passwords['admin']} ~* +@all"]
            for user in ("adapter", "producer-a", "producer-b"):
                lines.append(
                    f"user {user} on >{passwords[user]} ~{PREFIX}:* "
                    "+get +hgetall +smembers +ping +multi +exec"
                )
            acl.write_text("\n".join(lines) + "\n"); acl.chmod(0o444)
            run(["docker", "run", "--detach", "--rm", "--name", container,
                 "--read-only", "--tmpfs", "/data:rw,noexec,nosuid,size=32m",
                 "--cap-drop=ALL", "--security-opt", "no-new-privileges",
                 "--memory", "128m", "--pids-limit", "64", "--cpus", "1",
                 "--publish", "127.0.0.1::6379", "--volume", f"{acl}:/run/redis/users.acl:ro",
                 IMAGE, "redis-server", "--save", "", "--appendonly", "no",
                 "--aclfile", "/run/redis/users.acl"])
            created = True
            port_value = run(["docker", "port", container, "6379/tcp"]).stdout.decode().strip()
            port = int(port_value.rsplit(":", 1)[1])
            deadline = time.monotonic() + 5
            while True:
                try:
                    if redis_command(port, "admin", passwords["admin"], "PING") == "PONG":
                        break
                except RedisIntegrationError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
            seed(port, PREFIX, passwords["admin"])
            credential_paths = []
            for user in ("adapter", "producer-a", "producer-b"):
                path = work / f"{user}.credentials.json"
                credential(path, user, passwords[user]); credential_paths.append(path)
                try:
                    redis_command(port, user, passwords[user], "SET", f"{PREFIX}:forbidden", "mutation")
                    raise RuntimeError(f"redis-e2e: {user} unexpectedly has mutation authority")
                except RedisIntegrationError as error:
                    if "NOPERM" not in str(error):
                        raise
            config_path, base = configuration(
                work, binary, port, credential_paths[0], credential_paths[1:], "valid")
            evaluation = run([str(binary), "evaluate", str(config_path)], timeout=LOAD_TIMEOUT_SECONDS)
            report = json.loads(evaluation.stdout)
            certificate = json.loads((work / "valid-certificate.json").read_bytes())
            record = certificate["integration"]
            if report["target_mutated"] or record["integration_id"] != INTEGRATION_ID or record["target_revision"] != "revision-73":
                raise RuntimeError("redis-e2e: success evidence is invalid")

            def load(index: int) -> None:
                case = work / f"load-{index}"; case.mkdir()
                value = json.loads(json.dumps(base))
                value["certificate_path"] = str(case / "certificate.json")
                value["ledger_path"] = str(case / "ledger.jsonl")
                path = case / "evaluation.json"; path.write_text(json.dumps(value))
                result = run([str(binary), "evaluate", str(path)], timeout=LOAD_TIMEOUT_SECONDS)
                if json.loads(result.stdout)["target_mutated"] or not (case / "certificate.json").is_file():
                    raise RuntimeError("redis-e2e: load evaluation failed")

            load_started = time.monotonic()
            with ThreadPoolExecutor(max_workers=LOAD_CONCURRENCY) as pool:
                for future in [pool.submit(load, index) for index in range(LOAD_EVALUATIONS)]:
                    future.result(timeout=30)
            load_elapsed = time.monotonic() - load_started
            if load_elapsed > 30:
                raise RuntimeError("redis-e2e: load exceeded bound")

            unsafe_credential = json.loads(json.dumps(base))
            unsafe_credential["certificate_path"] = str(work / "unsafe-credential-certificate.json")
            unsafe_credential["ledger_path"] = str(work / "unsafe-credential-ledger.jsonl")
            unsafe_credential_path = work / "unsafe-credential-evaluation.json"
            unsafe_credential_path.write_text(json.dumps(unsafe_credential))
            credential_paths[0].chmod(0o644)
            try:
                assert_no_evidence(work, binary, unsafe_credential_path, "unsafe-credential")
            finally:
                credential_paths[0].chmod(0o600)

            seed(port, f"{PREFIX}-oversized", passwords["admin"], replicas=65)
            oversized = json.loads(json.dumps(base)); oversized["adapter"]["arguments"][-1] = f"{PREFIX}-oversized"
            oversized["certificate_path"] = str(work / "oversized-certificate.json")
            oversized["ledger_path"] = str(work / "oversized-ledger.jsonl")
            oversized_path = work / "oversized-evaluation.json"; oversized_path.write_text(json.dumps(oversized))
            assert_no_evidence(work, binary, oversized_path, "oversized")

            bad_prefix = f"{PREFIX}-disagreement"; seed(port, bad_prefix, passwords["admin"], revision="revision-74")
            disagreement = json.loads(json.dumps(base)); disagreement["observation_sources"][0]["arguments"][7] = bad_prefix
            disagreement["certificate_path"] = str(work / "disagreement-certificate.json")
            disagreement["ledger_path"] = str(work / "disagreement-ledger.jsonl")
            disagreement_path = work / "disagreement-evaluation.json"; disagreement_path.write_text(json.dumps(disagreement))
            assert_no_evidence(work, binary, disagreement_path, "disagreement")

            stale = json.loads(json.dumps(base))
            stale_arguments = stale["observation_sources"][0]["arguments"]
            stale_arguments[stale_arguments.index("--issued") + 1] = "1749999900"
            stale["certificate_path"] = str(work / "stale-certificate.json")
            stale["ledger_path"] = str(work / "stale-ledger.jsonl")
            stale_path = work / "stale-evaluation.json"; stale_path.write_text(json.dumps(stale))
            assert_no_evidence(work, binary, stale_path, "stale")

            run(["docker", "stop", "--time", "1", container]); created = False
            outage = json.loads(json.dumps(base)); outage["certificate_path"] = str(work / "outage-certificate.json")
            outage["ledger_path"] = str(work / "outage-ledger.jsonl")
            outage_path = work / "outage-evaluation.json"; outage_path.write_text(json.dumps(outage))
            assert_no_evidence(work, binary, outage_path, "outage")
            elapsed = time.monotonic() - started
            if elapsed > MAX_SECONDS:
                raise RuntimeError("redis-e2e: qualification exceeded wall-time bound")
            peak_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
            if os.uname().sysname == "Linux":
                peak_rss *= 1024
            result = {
                "schema_version": "telosieve.redis-integration-qualification/v1",
                "redis_version": "8.8.0", "image": IMAGE,
                "real_server": True, "loopback_only": True,
                "read_only_acl_users": 3, "mutation_attempts_refused": 3,
                "observation_producers": 2, "separate_control_planes": False,
                "successful_evaluations": 1, "load_evaluations": LOAD_EVALUATIONS,
                "load_concurrency": LOAD_CONCURRENCY, "load_elapsed_seconds": round(load_elapsed, 3),
                "fail_closed_evaluations": 5, "target_mutated": False,
                "elapsed_seconds": round(elapsed, 3),
                "peak_child_rss_bytes": peak_rss,
                "independent_evidence": False, "status": "passed",
            }
            print(json.dumps(result, separators=(",", ":")))
    finally:
        if created:
            subprocess.run(["docker", "stop", "--time", "1", container], cwd=ROOT,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False, timeout=5)


if __name__ == "__main__":
    main()
