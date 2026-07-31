#!/usr/bin/env python3
"""Build a deterministic, checksummed private evaluation ZIP."""
import argparse, hashlib, json, os, stat, subprocess, tempfile, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "telosieve.private-bundle/v3"
CAPABILITY_SCHEMA = "telosieve.evaluation-capabilities/v1"
PROFILE_SCHEMA = "telosieve.evaluation-candidate-profile/v1"
FILES = [
    "AGENTS.md", "README.md", "Cargo.lock", "docs/EVALUATION_CLI.md",
    "docs/EVALUATION_LIFECYCLE.md", "docs/OPERATOR_DIAGNOSTICS.md",
    "docs/OPERATIONS.md", "docs/PRIVATE_BUNDLE.md", "docs/RELEASE.md",
    "docs/BUILD_PROVENANCE.md", "docs/CANDIDATE_SIGNING.md",
    "docs/KUBERNETES_REAL_CLUSTER.md", "docs/KUBERNETES_SHADOW.md",
    "docs/OPENTOFU_PLAN.md", "docs/EVALUATION_PRODUCT_DECISION.md",
    "docs/THREAT_MODEL.md", "docs/ADVERSARIAL_COVERAGE.md",
    "docs/SUSTAINED_ADVERSARIAL_LOAD.md", "docs/OBSERVATION_QUORUM.md",
    "deploy/kubernetes/evaluation-rbac.yaml", "evaluation/config.example.json",
    "evaluation/config.live.example.json", "evaluation/config.opentofu.example.json",
    "evaluation/observation-trust.example.json", "evaluation/observation-quorum.example.json",
    "evaluation/contract.json", "evaluation/candidate-test-plan.json",
    "evaluation/adversarial-coverage.json",
    "examples/opentofu/main.tf",
    "scenarios/benign.json", "scenarios/kubernetes-real-cluster.json",
    "snapshots/kubernetes-shadow-benign.json",
    "scripts/evaluation-lifecycle.py", "scripts/evaluation-diagnostics.py",
    "scripts/ci-local.sh", "scripts/run-kubernetes-real-cluster.py",
    "scripts/run-opentofu-plan.py", "scripts/validate-adversarial-coverage.py",
    "scripts/run-sustained-adversarial-load.py",
    "results/adversarial-coverage-validation.json",
    "results/sustained-adversarial-load.json",
]
MAX_BINARY = 128 * 1024 * 1024
MAX_CAPABILITIES = 64 * 1024
CAPABILITY_TIMEOUT_SECONDS = 5
MAX_SOURCE_FILE = 16 * 1024 * 1024
MAX_SOURCE_TOTAL = 32 * 1024 * 1024
MUTATION_TOKENS = ("actuate", "apply", "create", "delete", "mutate", "patch", "update", "write")
FIXED_TIME = (2026, 1, 1, 0, 0, 0)

def digest(data): return hashlib.sha256(data).hexdigest()

def bounded_read(path, maximum, label):
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise SystemExit(f"private-bundle: cannot open {label}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise SystemExit(f"private-bundle: invalid or oversized {label}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise SystemExit(f"private-bundle: {label} exceeded its bound while reading")
        return data, metadata.st_mode
    finally:
        os.close(descriptor)

def strict_json(data, label):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise SystemExit(f"private-bundle: {label} contains duplicate key {key!r}")
            value[key] = item
        return value
    try:
        return json.loads(data, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"private-bundle: {label} JSON is invalid: {error}") from error

def read_sources():
    sources = {}
    source_total = 0
    for relative in FILES:
        path = ROOT / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_FILE:
            raise SystemExit(f"private-bundle: invalid source {relative}")
        data, _ = bounded_read(path, MAX_SOURCE_FILE, relative)
        source_total += len(data)
        if source_total > MAX_SOURCE_TOTAL:
            raise SystemExit("private-bundle: source inputs exceed total bound")
        sources[relative] = data
    return sources

def collect_capabilities(binary, contract_bytes):
    with tempfile.TemporaryFile() as stdout:
        try:
            result = subprocess.run(
                [str(binary), "evaluation-capabilities"], stdout=stdout,
                stderr=subprocess.DEVNULL, timeout=CAPABILITY_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise SystemExit("private-bundle: capability collection timed out") from error
        size = stdout.tell()
        if result.returncode != 0 or size > MAX_CAPABILITIES:
            raise SystemExit("private-bundle: capability collection failed or exceeded its bound")
        stdout.seek(0)
        data = stdout.read()
    value = strict_json(data, "capability inventory")
    if not isinstance(value, dict) or value.get("schema_version") != CAPABILITY_SCHEMA:
        raise SystemExit("private-bundle: capability inventory schema is invalid")
    contract = strict_json(contract_bytes, "contract")
    if value.get("capabilities") != contract.get("supported_evaluation_modes"):
        raise SystemExit("private-bundle: binary capabilities do not match the product contract")
    capabilities = value.get("capabilities")
    if (
        contract.get("schema_version") != "telosieve.evaluation-product-contract/v2"
        or contract.get("evaluation_authority_boundary") != "read-only-no-target-mutation"
        or not isinstance(capabilities, list)
        or not 1 <= len(capabilities) <= 16
        or any(
            not isinstance(item, dict)
            or set(item) != {"configuration_schema", "mode", "target_mutated"}
            or item["target_mutated"] is not False
            or not isinstance(item["mode"], str)
            or any(token in item["mode"].lower() for token in MUTATION_TOKENS)
            for item in capabilities
        )
    ):
        raise SystemExit("private-bundle: capability inventory violates the read-only contract")
    return data, value, contract

def validate_test_inputs(capability_document, contract, sources):
    capabilities = capability_document["capabilities"]
    configurations = [
        strict_json(sources[path], path)
        for path in (
            "evaluation/config.live.example.json", "evaluation/config.opentofu.example.json",
            "evaluation/config.example.json",
        )
    ]
    packaged = [
        {"configuration_schema": item.get("schema_version"), "mode": item.get("mode"), "target_mutated": False}
        for item in configurations
    ]
    plan = strict_json(sources["evaluation/candidate-test-plan.json"], "candidate test plan")
    coverage = strict_json(sources["evaluation/adversarial-coverage.json"], "adversarial coverage")
    if not isinstance(plan, dict):
        raise SystemExit("private-bundle: candidate test plan must be an object")
    tests = plan.get("tests")
    planned = [
        {
            "configuration_schema": item.get("configuration_schema"),
            "mode": item.get("mode"),
            "target_mutated": item.get("expected_target_mutated"),
        }
        for item in tests
    ] if isinstance(tests, list) and all(isinstance(item, dict) for item in tests) else None
    if (
        packaged != capabilities
        or planned != capabilities
        or plan.get("schema_version") != "telosieve.evaluation-candidate-test-plan/v1"
        or plan.get("execution_context") != "source-checkout-at-bundle-source-commit"
        or plan.get("coverage_contract") != {
            "command": "python3 scripts/validate-adversarial-coverage.py",
            "registry": "evaluation/adversarial-coverage.json",
            "retained_result": "results/adversarial-coverage-validation.json",
        }
        or plan.get("load_qualification") != {
            "command": "python3 scripts/run-sustained-adversarial-load.py",
            "retained_result": "results/sustained-adversarial-load.json",
        }
        or coverage.get("schema_version") != "telosieve.adversarial-coverage/v1"
        or coverage.get("authority_boundary") != "read-only-no-target-mutation"
        or set(coverage.get("modes", [])) != {item["mode"] for item in capabilities}
        or contract["supported_evaluation_modes"] != capabilities
    ):
        raise SystemExit("private-bundle: configurations or test plan do not cover capabilities")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    binary, output = Path(args.binary), Path(args.output)
    source_commit = args.source_commit
    if len(source_commit) != 40 or any(character not in "0123456789abcdef" for character in source_commit):
        raise SystemExit("private-bundle: source commit must be 40 lowercase hexadecimal characters")
    if not binary.is_absolute() or binary.is_symlink() or not binary.is_file():
        raise SystemExit("private-bundle: binary must be an absolute regular file")
    binary_bytes, binary_mode = bounded_read(binary, MAX_BINARY, "binary")
    if binary_mode & 0o111 == 0:
        raise SystemExit("private-bundle: binary is oversized or not executable")
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise SystemExit("private-bundle: output must be an absent absolute path")
    sources = read_sources()
    contract = sources["evaluation/contract.json"]
    with tempfile.TemporaryDirectory(prefix="telosieve-bundle-binary-") as directory:
        snapshot = Path(directory) / "telosieve"
        snapshot.write_bytes(binary_bytes)
        snapshot.chmod(0o500)
        capabilities, capability_document, contract_document = collect_capabilities(snapshot, contract)
    validate_test_inputs(capability_document, contract_document, sources)
    profile = json.dumps({
        "authoritative_ci": "./scripts/ci-local.sh",
        "capabilities_sha256": digest(capabilities),
        "contract_sha256": digest(contract),
        "coverage_contract_sha256": digest(sources["evaluation/adversarial-coverage.json"]),
        "independent_assessment_required": True,
        "schema_version": PROFILE_SCHEMA,
        "signing_required": True,
        "source_commit": source_commit,
        "status": "unsigned-private-evaluation-candidate-input",
    }, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    entries = [
        ("bin/telosieve", binary_bytes, 0o500),
        ("evaluation/capabilities.json", capabilities, 0o400),
        ("evaluation/candidate-profile.json", profile, 0o400),
    ]
    for relative, data in sources.items():
        entries.append((relative, data, 0o400))
    records = [{"path": name, "sha256": digest(data), "size": len(data)} for name, data, _ in entries]
    manifest = json.dumps({"schema_version": SCHEMA, "source_commit": source_commit, "entries": records}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    entries.append(("bundle-manifest.json", manifest, 0o400))
    fd, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    os.close(fd)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, data, mode in entries:
                info = zipfile.ZipInfo(name, FIXED_TIME)
                info.create_system = 3
                info.external_attr = mode << 16
                archive.writestr(info, data)
        os.chmod(temporary, 0o600)
        os.link(temporary, output)
        Path(temporary).unlink()
    finally:
        Path(temporary).unlink(missing_ok=True)
    print(json.dumps({"schema_version": SCHEMA, "sha256": digest(output.read_bytes()), "entries": len(entries)}))
    return 0

if __name__ == "__main__": raise SystemExit(main())
