#!/usr/bin/env python3
"""Exercise private release-candidate construction and offline verification."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT = 240


def run(command, cwd, success=True):
    result = subprocess.run(command, cwd=cwd, capture_output=True, check=False, timeout=TIMEOUT)
    if (result.returncode == 0) != success:
        raise SystemExit(f"release-candidate-qualification: unexpected result: {command[0]}\n{result.stderr.decode(errors='replace')[-2048:]}")
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def builder(repository, commit, binary_digest, key, output):
    return [str(repository / "scripts/build-release-candidate.py"),
            "--source-commit", commit, "--expected-binary-sha256", binary_digest,
            "--signing-key", str(key), "--output-directory", str(output),
            "--signer", "telosieve-project-evaluation", "--key-id", "v0.2.0-rc.1",
            "--issued-at", "1785580800", "--expires-at", "1788172800",
            "--evaluation-time", "1785580800"]


def main():
    with tempfile.TemporaryDirectory(prefix="telosieve-rc-qualification-") as raw:
        work = Path(raw)
        repository = work / "repository"
        shutil.copytree(ROOT, repository, ignore=shutil.ignore_patterns(".git", "target", "out", "__pycache__"))
        run(["git", "init", "-b", "master"], repository)
        run(["git", "config", "user.email", "qualification@telosieve.invalid"], repository)
        run(["git", "config", "user.name", "Telosieve Qualification"], repository)
        run(["git", "add", "."], repository)
        run(["git", "commit", "-m", "qualification snapshot"], repository)
        commit = run(["git", "rev-parse", "HEAD"], repository).stdout.decode().strip()
        run(["cargo", "build", "--release", "--locked", "--offline"], repository)
        binary_digest = digest(repository / "target/release/telosieve")
        key = work / "evaluation-key.hex"
        key.write_text("71" * 32, encoding="ascii")
        key.chmod(0o600)
        output = work / "candidate"
        result = run(builder(repository, commit, binary_digest, key, output), repository)
        report = json.loads(result.stdout)
        if report.get("status") != "passed" or len(list(output.iterdir())) != 7:
            raise SystemExit("release-candidate-qualification: candidate build result is invalid")
        trusted = repository / "target/release/telosieve"
        verify = run([str(repository / "scripts/verify-release-candidate.py"), str(output),
                      "--trusted-telosieve", str(trusted.resolve())], repository)
        if json.loads(verify.stdout).get("status") != "passed":
            raise SystemExit("release-candidate-qualification: verifier result is invalid")

        refused = 0
        run(builder(repository, commit, binary_digest, key, output), repository, success=False)
        refused += 1
        unsafe_key = work / "unsafe.hex"
        unsafe_key.write_text("72" * 32); unsafe_key.chmod(0o644)
        run(builder(repository, commit, binary_digest, unsafe_key, work / "unsafe-output"), repository, success=False)
        refused += 1
        run(builder(repository, commit, "0" * 64, key, work / "wrong-digest"), repository, success=False)
        refused += 1
        dirty = repository / "dirty"
        dirty.write_text("dirty")
        run(builder(repository, commit, binary_digest, key, work / "dirty-output"), repository, success=False)
        dirty.unlink()
        refused += 1
        bundle = output / "telosieve-0.2.0-rc.1-private-evaluation.zip"
        bundle.chmod(0o600)
        original = bundle.read_bytes()
        bundle.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        run([str(repository / "scripts/verify-release-candidate.py"), str(output),
             "--trusted-telosieve", str(trusted.resolve())], repository, success=False)
        refused += 1
    print(json.dumps({"schema_version": "telosieve.release-candidate-qualification/v1",
                      "accepted": 1, "refused": refused, "artifacts": 7,
                      "atomic_publication": True, "independent_evidence": False,
                      "status": "passed"}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
