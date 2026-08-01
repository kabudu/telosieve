#!/usr/bin/env python3
"""Build and sign an atomic private evaluation release-candidate handoff."""

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = "0.2.0-rc.1"
CONTEXT = "telosieve/private-evaluation"
MAX_BUNDLE_BYTES = 160 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 16 * 1024


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def run(command: list[str], timeout: int = 180) -> bytes:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, check=False, timeout=timeout)
    if result.returncode:
        detail = (result.stdout + result.stderr)[-MAX_DIAGNOSTIC_BYTES:].decode(errors="replace")
        raise SystemExit(f"release-candidate: command failed ({command[0]}): {detail}")
    return result.stdout


def clean_commit(expected: str) -> None:
    if len(expected) != 40 or any(value not in "0123456789abcdef" for value in expected):
        raise SystemExit("release-candidate: invalid source commit")
    if run(["git", "rev-parse", "HEAD"]).decode().strip() != expected:
        raise SystemExit("release-candidate: source commit does not match HEAD")
    if run(["git", "status", "--porcelain"]):
        raise SystemExit("release-candidate: working tree is not clean")
    if run(["git", "branch", "--show-current"]).decode().strip() != "master":
        raise SystemExit("release-candidate: candidate must be built from master")


def safe_key(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise SystemExit("release-candidate: signing key path is unsafe")
    metadata = path.stat()
    if (metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != 64 or metadata.st_uid != os.getuid()):
        raise SystemExit("release-candidate: signing key shape is unsafe")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--signing-key", required=True)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--signer", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--issued-at", required=True, type=int)
    parser.add_argument("--expires-at", required=True, type=int)
    parser.add_argument("--evaluation-time", required=True, type=int)
    args = parser.parse_args()
    clean_commit(args.source_commit)
    if len(args.expected_binary_sha256) != 64 or any(c not in "0123456789abcdef" for c in args.expected_binary_sha256):
        raise SystemExit("release-candidate: invalid expected binary digest")
    if (not (0 <= args.issued_at <= args.evaluation_time <= args.expires_at)
            or args.issued_at >= args.expires_at
            or args.expires_at - args.issued_at > 30 * 24 * 60 * 60):
        raise SystemExit("release-candidate: invalid signing interval")
    if any(not value or len(value) > 128 or not value.isascii() for value in (args.signer, args.key_id)):
        raise SystemExit("release-candidate: invalid signer identity")
    key = Path(args.signing_key)
    output = Path(args.output_directory)
    safe_key(key)
    if not output.is_absolute() or output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise SystemExit("release-candidate: output directory must be an absent absolute path")
    run(["cargo", "build", "--release", "--locked", "--offline"], timeout=180)
    binary = (ROOT / "target/release/telosieve").resolve()
    version = run([str(binary), "--version"]).decode().strip()
    if version != f"telosieve {VERSION}" or digest(binary) != args.expected_binary_sha256:
        raise SystemExit("release-candidate: version or reproducible binary digest mismatch")

    with tempfile.TemporaryDirectory(prefix=f".{output.name}.", dir=output.parent) as raw:
        stage = Path(raw)
        bundle = stage / f"telosieve-{VERSION}-private-evaluation.zip"
        signature = stage / f"telosieve-{VERSION}.signature.json"
        trust = stage / f"telosieve-{VERSION}.trust.json"
        notes = stage / f"telosieve-{VERSION}-release-notes.md"
        verifier = stage / "verify-release-candidate.py"
        manifest_path = stage / f"telosieve-{VERSION}.candidate.json"
        checksums = stage / "SHA256SUMS"
        run([str(ROOT / "scripts/build-private-bundle.py"), "--binary", str(binary),
             "--source-commit", args.source_commit, "--output", str(bundle)])
        if bundle.stat().st_size > MAX_BUNDLE_BYTES:
            raise SystemExit("release-candidate: bundle exceeds size bound")
        public_key = run([str(binary), "bundle-public-key", str(key)]).decode().strip()
        run([str(binary), "bundle-sign", str(bundle), str(key), CONTEXT, args.signer,
             args.key_id, str(args.issued_at), str(args.expires_at), str(signature)])
        trust.write_text(json.dumps({
            "context": CONTEXT, "evaluation_time": args.evaluation_time,
            "keys": [{"signer": args.signer, "key_id": args.key_id,
                      "public_key": public_key, "not_before": args.issued_at,
                      "not_after": args.expires_at}],
        }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        trust.chmod(0o400)
        run([str(binary), "bundle-verify", str(bundle), str(signature), str(trust)])
        shutil.copyfile(ROOT / f"RELEASE_NOTES_v{VERSION}.md", notes)
        notes.chmod(0o400)
        shutil.copyfile(ROOT / "scripts/verify-release-candidate.py", verifier)
        verifier.chmod(0o500)
        artifacts = [bundle, signature, trust, notes, verifier]
        manifest = {
            "schema_version": "telosieve.private-evaluation-release-candidate/v1",
            "version": VERSION, "source_commit": args.source_commit,
            "status": "signed-private-evaluation-release-candidate",
            "authority_boundary": "read-only-no-target-mutation",
            "signing_identity": {"context": CONTEXT, "signer": args.signer,
                                 "key_id": args.key_id, "custody": "project-controlled-evaluation"},
            "validity": {"issued_at": args.issued_at, "expires_at": args.expires_at,
                         "evaluation_time": args.evaluation_time},
            "binary_sha256": args.expected_binary_sha256,
            "artifacts": [{"name": item.name, "sha256": digest(item), "bytes": item.stat().st_size}
                          for item in artifacts],
            "candidate_readiness_gates_satisfied": 8,
            "independent_assessment_required": True,
            "production_promotion_authorized": False,
            "public_release_authorized": False,
        }
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        manifest_path.chmod(0o400)
        checksum_files = [*artifacts, manifest_path]
        checksums.write_text("".join(f"{digest(item)}  {item.name}\n" for item in checksum_files), encoding="ascii")
        checksums.chmod(0o400)
        for item in (bundle, signature):
            item.chmod(0o400)
        os.rename(stage, output)
    print(json.dumps({"schema_version": "telosieve.release-candidate-build/v1",
                      "version": VERSION, "source_commit": args.source_commit,
                      "output_directory": str(output), "artifacts": 7,
                      "status": "passed"}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
