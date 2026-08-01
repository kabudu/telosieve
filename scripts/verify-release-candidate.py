#!/usr/bin/env python3
"""Verify a private Telosieve release-candidate handoff offline."""

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

VERSION = "0.2.0-rc.1"
MAX_FILE_BYTES = 160 * 1024 * 1024


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def strict_json(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise SystemExit(f"release-candidate-verify: unsafe JSON file: {path.name}")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate key {key}")
            value[key] = item
        return value
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"release-candidate-verify: invalid JSON: {path.name}") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--trusted-telosieve", required=True)
    args = parser.parse_args()
    root = Path(args.directory)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise SystemExit("release-candidate-verify: handoff must be an absolute directory")
    trusted = Path(args.trusted_telosieve)
    if (not trusted.is_absolute() or trusted.is_symlink() or not trusted.is_file()
            or trusted.stat().st_size > 128 * 1024 * 1024
            or trusted.stat().st_mode & 0o111 == 0):
        raise SystemExit("release-candidate-verify: trusted verifier binary is unsafe")
    names = {
        f"telosieve-{VERSION}-private-evaluation.zip",
        f"telosieve-{VERSION}.signature.json",
        f"telosieve-{VERSION}.trust.json",
        f"telosieve-{VERSION}-release-notes.md",
        f"telosieve-{VERSION}.candidate.json",
        "verify-release-candidate.py",
        "SHA256SUMS",
    }
    if {item.name for item in root.iterdir()} != names:
        raise SystemExit("release-candidate-verify: handoff file set is not exact")
    for name in names:
        path = root / name
        metadata = path.stat()
        if (path.is_symlink() or not path.is_file() or metadata.st_nlink != 1
                or metadata.st_size > MAX_FILE_BYTES or metadata.st_mode & 0o022):
            raise SystemExit(f"release-candidate-verify: unsafe artifact: {name}")
    checksum_lines = (root / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    expected_checksum_names = sorted(names - {"SHA256SUMS"})
    checksums = {}
    for line in checksum_lines:
        parts = line.split("  ")
        if len(parts) != 2 or len(parts[0]) != 64 or parts[1] in checksums:
            raise SystemExit("release-candidate-verify: invalid checksum record")
        checksums[parts[1]] = parts[0]
    if sorted(checksums) != expected_checksum_names:
        raise SystemExit("release-candidate-verify: checksum set is incomplete")
    if any(digest(root / name) != expected for name, expected in checksums.items()):
        raise SystemExit("release-candidate-verify: artifact checksum mismatch")

    manifest_path = root / f"telosieve-{VERSION}.candidate.json"
    manifest = strict_json(manifest_path)
    required = {
        "schema_version", "version", "source_commit", "status", "authority_boundary",
        "signing_identity", "validity", "binary_sha256", "artifacts",
        "candidate_readiness_gates_satisfied", "independent_assessment_required",
        "production_promotion_authorized", "public_release_authorized",
    }
    if (
        not isinstance(manifest, dict) or set(manifest) != required
        or manifest["schema_version"] != "telosieve.private-evaluation-release-candidate/v1"
        or manifest["version"] != VERSION
        or manifest["status"] != "signed-private-evaluation-release-candidate"
        or manifest["authority_boundary"] != "read-only-no-target-mutation"
        or manifest["candidate_readiness_gates_satisfied"] != 8
        or manifest["independent_assessment_required"] is not True
        or manifest["production_promotion_authorized"] is not False
        or manifest["public_release_authorized"] is not False
        or not isinstance(manifest["source_commit"], str)
        or len(manifest["source_commit"]) != 40
        or any(value not in "0123456789abcdef" for value in manifest["source_commit"])
    ):
        raise SystemExit("release-candidate-verify: candidate manifest is invalid")
    artifacts = manifest["artifacts"]
    if (not isinstance(artifacts, list) or not all(isinstance(item, dict) for item in artifacts)
            or {item.get("name") for item in artifacts} != names - {"SHA256SUMS", manifest_path.name}):
        raise SystemExit("release-candidate-verify: candidate artifact inventory is invalid")
    for item in artifacts:
        path = root / item["name"]
        if set(item) != {"name", "sha256", "bytes"} or item["sha256"] != digest(path) or item["bytes"] != path.stat().st_size:
            raise SystemExit("release-candidate-verify: candidate artifact record mismatch")

    bundle = root / f"telosieve-{VERSION}-private-evaluation.zip"
    trust = strict_json(root / f"telosieve-{VERSION}.trust.json")
    identity = manifest["signing_identity"]
    validity = manifest["validity"]
    if (
        not isinstance(identity, dict) or set(identity) != {"context", "signer", "key_id", "custody"}
        or identity["custody"] != "project-controlled-evaluation"
        or not isinstance(validity, dict) or set(validity) != {"issued_at", "expires_at", "evaluation_time"}
        or trust.get("context") != identity["context"] or trust.get("evaluation_time") != validity["evaluation_time"]
        or not isinstance(trust.get("keys"), list) or len(trust["keys"]) != 1
        or trust["keys"][0].get("signer") != identity["signer"]
        or trust["keys"][0].get("key_id") != identity["key_id"]
        or trust["keys"][0].get("not_before") != validity["issued_at"]
        or trust["keys"][0].get("not_after") != validity["expires_at"]
    ):
        raise SystemExit("release-candidate-verify: signing metadata mismatch")
    with zipfile.ZipFile(bundle) as archive:
        infos = archive.infolist()
        if len({item.filename for item in infos}) != len(infos):
            raise SystemExit("release-candidate-verify: duplicate bundle entry")
        binary_info = archive.getinfo("bin/telosieve")
        if binary_info.compress_type != zipfile.ZIP_STORED or binary_info.file_size > 128 * 1024 * 1024:
            raise SystemExit("release-candidate-verify: unsafe bundled binary")
        bundle_manifest = json.loads(archive.read("bundle-manifest.json"))
        profile = json.loads(archive.read("evaluation/candidate-profile.json"))
        binary_bytes = archive.read("bin/telosieve")
    if bundle_manifest.get("source_commit") != manifest["source_commit"] or profile.get("source_commit") != manifest["source_commit"]:
        raise SystemExit("release-candidate-verify: embedded source commit mismatch")
    if hashlib.sha256(binary_bytes).hexdigest() != manifest["binary_sha256"]:
        raise SystemExit("release-candidate-verify: embedded binary digest mismatch")
    version = subprocess.run([str(trusted), "--version"], capture_output=True, check=False, timeout=5)
    verify = subprocess.run([
        str(trusted), "bundle-verify", str(bundle),
        str(root / f"telosieve-{VERSION}.signature.json"),
        str(root / f"telosieve-{VERSION}.trust.json"),
    ], capture_output=True, check=False, timeout=10)
    if version.returncode or version.stdout.decode().strip() != f"telosieve {VERSION}" or verify.returncode:
        raise SystemExit("release-candidate-verify: trusted binary version or signature verification failed")
    print(json.dumps({"schema_version": "telosieve.release-candidate-verification/v1",
                      "version": VERSION, "source_commit": manifest["source_commit"],
                      "artifacts": 7, "signature_valid": True,
                      "trusted_verifier_sha256": digest(trusted),
                      "independent_evidence": False, "status": "passed"}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
