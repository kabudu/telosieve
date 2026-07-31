#!/usr/bin/env python3
"""Build a deterministic, checksummed private evaluation ZIP."""
import argparse, hashlib, json, os, tempfile, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "telosieve.private-bundle/v2"
FILES = [
    "AGENTS.md", "README.md", "Cargo.lock", "docs/EVALUATION_CLI.md",
    "docs/EVALUATION_LIFECYCLE.md", "docs/OPERATOR_DIAGNOSTICS.md",
    "docs/OPERATIONS.md", "docs/PRIVATE_BUNDLE.md", "docs/RELEASE.md",
    "docs/BUILD_PROVENANCE.md", "docs/CANDIDATE_SIGNING.md",
    "deploy/kubernetes/evaluation-rbac.yaml", "evaluation/config.example.json",
    "evaluation/config.live.example.json", "evaluation/contract.json",
    "scripts/evaluation-lifecycle.py", "scripts/evaluation-diagnostics.py",
]
MAX_BINARY = 128 * 1024 * 1024
FIXED_TIME = (2026, 1, 1, 0, 0, 0)

def digest(data): return hashlib.sha256(data).hexdigest()

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
    if binary.stat().st_size > MAX_BINARY or binary.stat().st_mode & 0o111 == 0:
        raise SystemExit("private-bundle: binary is oversized or not executable")
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise SystemExit("private-bundle: output must be an absent absolute path")
    entries = [("bin/telosieve", binary.read_bytes(), 0o500)]
    for relative in FILES:
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise SystemExit(f"private-bundle: invalid source {relative}")
        entries.append((relative, path.read_bytes(), 0o400))
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
