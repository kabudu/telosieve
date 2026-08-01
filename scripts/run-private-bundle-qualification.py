#!/usr/bin/env python3
"""Qualify deterministic four-mode private evaluation bundle assembly."""

import hashlib
import json
import os
import resource
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BINARY = (ROOT / "target/debug/telosieve").resolve()
BUILDER = ROOT / "scripts/build-private-bundle.py"
SOURCE_COMMIT = "a" * 40
MAX_BUNDLE_BYTES = 160 * 1024 * 1024
MAX_BUILD_SECONDS = 15
EXPECTED_CONFIGURATIONS = (
    "evaluation/config.example.json",
    "evaluation/config.live.example.json",
    "evaluation/config.opentofu.example.json",
    "evaluation/config.integration.example.json",
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def command(binary: Path, output: Path, commit: str = SOURCE_COMMIT) -> list[str]:
    return [
        "python3", str(BUILDER), "--binary", str(binary),
        "--source-commit", commit, "--output", str(output),
    ]


def build(binary: Path, output: Path, commit: str = SOURCE_COMMIT) -> None:
    subprocess.run(
        command(binary, output, commit), cwd=ROOT, check=True,
        capture_output=True, timeout=MAX_BUILD_SECONDS,
    )


def assert_bundle(path: Path) -> int:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise SystemExit("private-bundle-qualification: duplicate archive entry")
        manifest = json.loads(archive.read("bundle-manifest.json"))
        if manifest["schema_version"] != "telosieve.private-bundle/v3":
            raise SystemExit("private-bundle-qualification: bundle schema mismatch")
        if manifest["source_commit"] != SOURCE_COMMIT:
            raise SystemExit("private-bundle-qualification: source commit mismatch")
        recorded = [record["path"] for record in manifest["entries"]]
        if recorded != names[:-1] or names[-1] != "bundle-manifest.json":
            raise SystemExit("private-bundle-qualification: unsigned or unrecorded archive entry")
        for record in manifest["entries"]:
            data = archive.read(record["path"])
            if len(data) != record["size"] or sha256_bytes(data) != record["sha256"]:
                raise SystemExit("private-bundle-qualification: entry digest mismatch")

        capabilities_bytes = archive.read("evaluation/capabilities.json")
        capabilities = json.loads(capabilities_bytes)
        contract_bytes = archive.read("evaluation/contract.json")
        contract = json.loads(contract_bytes)
        if capabilities["capabilities"] != contract["supported_evaluation_modes"]:
            raise SystemExit("private-bundle-qualification: capability/contract mismatch")
        if any(item["target_mutated"] for item in capabilities["capabilities"]):
            raise SystemExit("private-bundle-qualification: mutation capability included")

        profile = json.loads(archive.read("evaluation/candidate-profile.json"))
        coverage_bytes = archive.read("evaluation/adversarial-coverage.json")
        if (
            profile["schema_version"] != "telosieve.evaluation-candidate-profile/v1"
            or profile["source_commit"] != SOURCE_COMMIT
            or profile["status"] != "unsigned-private-evaluation-candidate-input"
            or profile["capabilities_sha256"] != sha256_bytes(capabilities_bytes)
            or profile["contract_sha256"] != sha256_bytes(contract_bytes)
            or profile["coverage_contract_sha256"] != sha256_bytes(coverage_bytes)
            or profile["signing_required"] is not True
            or profile["independent_assessment_required"] is not True
        ):
            raise SystemExit("private-bundle-qualification: candidate profile is invalid")

        test_plan = json.loads(archive.read("evaluation/candidate-test-plan.json"))
        planned = [
            {
                "configuration_schema": item["configuration_schema"],
                "mode": item["mode"],
                "expected_target_mutated": item["expected_target_mutated"],
            }
            for item in test_plan["tests"]
        ]
        expected = [
            {
                "configuration_schema": item["configuration_schema"],
                "mode": item["mode"],
                "expected_target_mutated": False,
            }
            for item in capabilities["capabilities"]
        ]
        if planned != expected:
            raise SystemExit("private-bundle-qualification: test plan does not cover capabilities")

        redis_result = json.loads(
            archive.read("results/redis-integration-qualification.json")
        )
        if (
            set(redis_result) != {
                "schema_version", "redis_version", "image", "real_server",
                "loopback_only", "read_only_acl_users",
                "mutation_attempts_refused", "observation_producers",
                "separate_control_planes", "successful_evaluations",
                "load_evaluations", "load_concurrency", "load_elapsed_seconds",
                "fail_closed_evaluations", "target_mutated", "elapsed_seconds",
                "peak_child_rss_bytes", "independent_evidence", "status",
            }
            or redis_result["schema_version"]
            != "telosieve.redis-integration-qualification/v1"
            or redis_result["image"]
            != "redis@sha256:9d317178eceac8454a2284a9e6df2466b93c745529947f0cd42a0fa9609d7005"
            or redis_result["real_server"] is not True
            or redis_result["loopback_only"] is not True
            or redis_result["read_only_acl_users"] != 3
            or redis_result["mutation_attempts_refused"] != 3
            or redis_result["observation_producers"] != 2
            or redis_result["separate_control_planes"] is not False
            or redis_result["successful_evaluations"] != 1
            or redis_result["load_evaluations"] != 8
            or redis_result["load_concurrency"] != 4
            or not isinstance(redis_result["load_elapsed_seconds"], (int, float))
            or isinstance(redis_result["load_elapsed_seconds"], bool)
            or not 0 <= redis_result["load_elapsed_seconds"] <= 30
            or redis_result["fail_closed_evaluations"] != 5
            or redis_result["target_mutated"] is not False
            or not isinstance(redis_result["elapsed_seconds"], (int, float))
            or isinstance(redis_result["elapsed_seconds"], bool)
            or not 0 <= redis_result["elapsed_seconds"] <= 90
            or not isinstance(redis_result["peak_child_rss_bytes"], int)
            or isinstance(redis_result["peak_child_rss_bytes"], bool)
            or not 0 < redis_result["peak_child_rss_bytes"] <= 512 * 1024 * 1024
            or redis_result["independent_evidence"] is not False
            or redis_result["status"] != "passed"
        ):
            raise SystemExit("private-bundle-qualification: Redis result is invalid")

        postgresql_result = json.loads(
            archive.read("results/postgresql-integration-qualification.json")
        )
        if (
            set(postgresql_result) != {
                "schema_version", "postgresql_version", "libpq_version", "image",
                "real_database", "loopback_only", "read_only_roles",
                "forbidden_operations_refused", "observation_producers",
                "separate_control_planes", "successful_evaluations",
                "load_evaluations", "load_concurrency", "load_elapsed_seconds",
                "race_evaluations", "race_refusals", "fail_closed_evaluations",
                "target_mutated", "elapsed_seconds", "peak_child_rss_bytes",
                "independent_evidence", "status",
            }
            or postgresql_result["schema_version"]
            != "telosieve.postgresql-integration-qualification/v1"
            or postgresql_result["postgresql_version"] != "18.4"
            or postgresql_result["libpq_version"] != "18.1"
            or postgresql_result["image"]
            != "postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
            or postgresql_result["real_database"] is not True
            or postgresql_result["loopback_only"] is not True
            or postgresql_result["read_only_roles"] != 3
            or postgresql_result["forbidden_operations_refused"] != 6
            or postgresql_result["observation_producers"] != 2
            or postgresql_result["separate_control_planes"] is not False
            or postgresql_result["successful_evaluations"] != 1
            or postgresql_result["load_evaluations"] != 8
            or postgresql_result["load_concurrency"] != 4
            or not isinstance(postgresql_result["load_elapsed_seconds"], (int, float))
            or isinstance(postgresql_result["load_elapsed_seconds"], bool)
            or not 0 <= postgresql_result["load_elapsed_seconds"] <= 30
            or postgresql_result["race_evaluations"] != 4
            or not 0 <= postgresql_result["race_refusals"] <= 4
            or postgresql_result["fail_closed_evaluations"] != 7
            or postgresql_result["target_mutated"] is not False
            or not isinstance(postgresql_result["elapsed_seconds"], (int, float))
            or isinstance(postgresql_result["elapsed_seconds"], bool)
            or not 0 <= postgresql_result["elapsed_seconds"] <= 90
            or not isinstance(postgresql_result["peak_child_rss_bytes"], int)
            or isinstance(postgresql_result["peak_child_rss_bytes"], bool)
            or not 0 < postgresql_result["peak_child_rss_bytes"] <= 512 * 1024 * 1024
            or postgresql_result["independent_evidence"] is not False
            or postgresql_result["status"] != "passed"
        ):
            raise SystemExit("private-bundle-qualification: PostgreSQL result is invalid")

        http_result = json.loads(archive.read("results/http-json-integration-qualification.json"))
        if (
            set(http_result) != {"schema_version", "transport", "orchestrated_endpoints", "external_endpoints",
                "loopback_only", "bearer_identities", "mutation_methods_refused", "observation_producers",
                "separate_control_planes", "successful_evaluations", "load_evaluations", "load_concurrency",
                "load_elapsed_seconds", "fail_closed_evaluations", "target_mutated", "elapsed_seconds",
                "peak_child_rss_bytes", "independent_evidence", "status"}
            or http_result["schema_version"] != "telosieve.http-json-integration-qualification/v1"
            or http_result["transport"] != "http/1.1"
            or http_result["orchestrated_endpoints"] is not True
            or http_result["external_endpoints"] is not False
            or http_result["loopback_only"] is not True
            or http_result["bearer_identities"] != 3
            or http_result["mutation_methods_refused"] != 4
            or http_result["observation_producers"] != 2
            or http_result["separate_control_planes"] is not False
            or http_result["successful_evaluations"] != 1
            or http_result["load_evaluations"] != 8 or http_result["load_concurrency"] != 4
            or not isinstance(http_result["load_elapsed_seconds"], (int, float))
            or isinstance(http_result["load_elapsed_seconds"], bool)
            or not 0 <= http_result["load_elapsed_seconds"] <= 20
            or http_result["fail_closed_evaluations"] != 8
            or http_result["target_mutated"] is not False
            or not isinstance(http_result["elapsed_seconds"], (int, float))
            or isinstance(http_result["elapsed_seconds"], bool)
            or not 0 <= http_result["elapsed_seconds"] <= 60
            or not isinstance(http_result["peak_child_rss_bytes"], int)
            or isinstance(http_result["peak_child_rss_bytes"], bool)
            or not 0 < http_result["peak_child_rss_bytes"] <= 512 * 1024 * 1024
            or http_result["independent_evidence"] is not False or http_result["status"] != "passed"
        ):
            raise SystemExit("private-bundle-qualification: HTTP/JSON result is invalid")

        packaged_modes = [
            {
                "configuration_schema": (config := json.loads(archive.read(path)))["schema_version"],
                "mode": config["mode"],
                "target_mutated": False,
            }
            for path in EXPECTED_CONFIGURATIONS
        ]
        if packaged_modes != capabilities["capabilities"]:
            raise SystemExit("private-bundle-qualification: packaged configs do not cover capabilities")
        required = {
            "docs/KUBERNETES_SHADOW.md", "docs/OPENTOFU_PLAN.md",
            "examples/opentofu/main.tf", "scripts/ci-local.sh",
            "scripts/run-kubernetes-real-cluster.py", "scripts/run-opentofu-plan.py",
            "evaluation/config.opentofu.example.json", "evaluation/candidate-test-plan.json",
            "evaluation/config.integration.example.json",
            "evaluation/observation-trust.integration.example.json",
            "evaluation/integration-response.example.json",
            "docs/INTEGRATION_CONTRACT.md", "scripts/reference-integration-adapter.py",
            "docs/REDIS_INTEGRATION.md", "scripts/redis_integration_common.py",
            "scripts/redis-integration-adapter.py", "scripts/redis-observation-producer.py",
            "scripts/test-redis-integration.py", "scripts/run-redis-integration.py",
            "results/redis-integration-qualification.json",
            "docs/POSTGRESQL_INTEGRATION.md", "scripts/postgresql_integration_common.py",
            "scripts/postgresql-integration-adapter.py",
            "scripts/postgresql-observation-producer.py",
            "scripts/test-postgresql-integration.py", "scripts/run-postgresql-integration.py",
            "results/postgresql-integration-qualification.json",
            "docs/HTTP_JSON_INTEGRATION.md", "scripts/http_json_integration_common.py",
            "scripts/http-json-integration-adapter.py", "scripts/http-json-observation-producer.py",
            "scripts/test-http-json-integration.py", "scripts/run-http-json-integration.py",
            "results/http-json-integration-qualification.json",
            "evaluation/candidate-readiness.json",
            "evaluation/observation-trust.example.json", "evaluation/observation-quorum.example.json",
            "evaluation/observation-trust.live.example.json",
            "evaluation/observation-trust.opentofu.example.json",
            "scripts/kubernetes-observation-producer.py",
            "scripts/opentofu-observation-producer.py",
            "scripts/observation-source-relay.py", "scripts/observation-source-client.py",
            "scripts/run-producer-isolation-qualification.py",
            "scripts/qualify-linux-producer-isolation.sh",
            "scripts/run-linux-producer-isolation.py",
            "deploy/systemd/telosieve-observation@.service",
            "deploy/systemd/observation-kubernetes-a.example.json",
            "deploy/systemd/observation-opentofu-a.example.json",
            "docs/PRODUCER_ISOLATION.md",
            "evaluation/adversarial-coverage.json", "docs/ADVERSARIAL_COVERAGE.md",
            "scripts/validate-adversarial-coverage.py", "results/adversarial-coverage-validation.json",
            "scripts/run-sustained-adversarial-load.py", "results/sustained-adversarial-load.json",
            "scripts/validate-candidate-readiness.py",
            "results/candidate-readiness-validation.json",
            "docs/CANDIDATE_READINESS.md",
            "RELEASE_NOTES_v0.2.0-rc.1.md",
            "scripts/build-release-candidate.py", "scripts/verify-release-candidate.py",
            "docs/SUSTAINED_ADVERSARIAL_LOAD.md", "docs/OBSERVATION_QUORUM.md",
            "evaluation/candidate-profile.json", "evaluation/capabilities.json",
        }
        if not required.issubset(names):
            raise SystemExit("private-bundle-qualification: required assessor content is absent")
        for producer in (
            "scripts/kubernetes-observation-producer.py",
            "scripts/opentofu-observation-producer.py",
            "scripts/observation-source-relay.py",
            "scripts/observation-source-client.py",
            "scripts/qualify-linux-producer-isolation.sh",
            "scripts/run-linux-producer-isolation.py",
            "scripts/verify-release-candidate.py",
            "scripts/reference-integration-adapter.py",
            "scripts/redis-integration-adapter.py",
            "scripts/redis-observation-producer.py",
            "scripts/test-redis-integration.py",
            "scripts/run-redis-integration.py",
            "scripts/postgresql-integration-adapter.py",
            "scripts/postgresql-observation-producer.py",
            "scripts/test-postgresql-integration.py",
            "scripts/run-postgresql-integration.py",
            "scripts/http-json-integration-adapter.py",
            "scripts/http-json-observation-producer.py",
            "scripts/test-http-json-integration.py",
            "scripts/run-http-json-integration.py",
        ):
            mode = archive.getinfo(producer).external_attr >> 16
            if mode & 0o777 != 0o555:
                raise SystemExit("private-bundle-qualification: producer mode is unsafe")
        return len(capabilities["capabilities"])


def write_executable(path: Path, body: str) -> None:
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o700)


def assert_capability_refusals(work: Path) -> int:
    fixtures = {
        "mismatch": "printf '%s\\n' '{\"schema_version\":\"telosieve.evaluation-capabilities/v1\",\"capabilities\":[]}'",
        "malformed": "printf 'not-json\\n'",
        "oversized": "dd if=/dev/zero bs=1024 count=65 2>/dev/null",
        "timeout": "sleep 6",
    }
    for name, body in fixtures.items():
        binary = work / f"fake-{name}"
        output = work / f"refused-{name}.zip"
        write_executable(binary, body)
        result = subprocess.run(
            command(binary, output), cwd=ROOT, capture_output=True,
            check=False, timeout=MAX_BUILD_SECONDS,
        )
        if result.returncode == 0 or output.exists():
            raise SystemExit(f"private-bundle-qualification: {name} capability fault accepted")
    return len(fixtures)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="telosieve-bundle-") as temporary:
        work = Path(temporary)
        first = work / "one.zip"
        second = work / "two.zip"
        interrupted = work / "interrupted.zip"
        other = work / "other.zip"
        started = time.monotonic()
        build(BINARY, first)
        wall_ms = round((time.monotonic() - started) * 1000, 3)
        build(BINARY, second)
        if first.read_bytes() != second.read_bytes():
            raise SystemExit("private-bundle-qualification: repeated bundles differ")
        modes = assert_bundle(first)

        process = subprocess.Popen(
            command(BINARY, interrupted), cwd=ROOT,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        process.kill()
        process.wait(timeout=5)
        if interrupted.exists():
            raise SystemExit("private-bundle-qualification: interrupted output was published")
        build(BINARY, interrupted)
        if sha256_file(interrupted) != sha256_file(first):
            raise SystemExit("private-bundle-qualification: interruption recovery diverged")

        build(BINARY, other, "b" * 40)
        if sha256_file(other) == sha256_file(first):
            raise SystemExit("private-bundle-qualification: source substitution was not bound")
        malformed = subprocess.run(
            command(BINARY, work / "invalid.zip", "HEAD"), cwd=ROOT,
            capture_output=True, check=False, timeout=MAX_BUILD_SECONDS,
        )
        if malformed.returncode == 0 or (work / "invalid.zip").exists():
            raise SystemExit("private-bundle-qualification: malformed source identity accepted")
        capability_refusals = assert_capability_refusals(work)

        peak_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        if first.stat().st_size > MAX_BUNDLE_BYTES or wall_ms >= MAX_BUILD_SECONDS * 1000:
            raise SystemExit("private-bundle-qualification: resource bound exceeded")
        bundle_digest = sha256_file(first)

    print(json.dumps({
        "schema_version": "telosieve.private-bundle-qualification/v3",
        "platform": os.uname().sysname,
        "bundle_sha256": bundle_digest,
        "wall_ms": wall_ms,
        "peak_child_rss": peak_rss,
        "supported_modes": modes,
        "capability_refusals": capability_refusals,
        "reproducible": True,
        "interruption_recovered": True,
        "source_commit_bound": True,
        "unsigned_candidate_input": True,
        "status": "passed",
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
