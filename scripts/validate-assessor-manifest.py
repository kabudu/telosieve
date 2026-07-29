#!/usr/bin/env python3
"""Validate the frozen assessor handoff against immutable Git objects."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = (
    Path(sys.argv[1]).resolve()
    if len(sys.argv) == 2
    else ROOT / "assessment/manifest.json"
)
SHA = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
EXPECTED_COMMANDS = (
    "./scripts/ci-local.sh",
    "./scripts/run-incident-drills.sh",
    "./scripts/run-parser-corpora.sh",
)
EXPECTED_KEYS = {
    "schema_version",
    "source_commit",
    "repository_visibility",
    "authoritative_ci",
    "commands",
    "artifacts",
    "claim_boundaries",
    "release_blockers",
}


def fail(message: str) -> None:
    raise ValueError(message)


def git(*arguments: str) -> bytes:
    return subprocess.run(
        ("git", *arguments),
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def validate_nonempty_strings(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        fail(f"{label} must be a non-empty array")
    if not all(isinstance(item, str) and item.strip() == item and item for item in value):
        fail(f"{label} must contain non-empty normalized strings")
    if len(set(value)) != len(value):
        fail(f"{label} must not contain duplicates")
    return value


def main() -> int:
    try:
        if len(sys.argv) > 2:
            fail("usage: validate-assessor-manifest.py [manifest.json]")
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict) or set(manifest) != EXPECTED_KEYS:
            fail("manifest fields do not exactly match the v1 schema")
        if manifest["schema_version"] != "telosieve.assessor-handoff/v1":
            fail("unsupported manifest schema")
        if manifest["repository_visibility"] != "private":
            fail("handoff must preserve the private-repository boundary")
        if manifest["authoritative_ci"] != EXPECTED_COMMANDS[0]:
            fail("authoritative local CI command changed")
        if tuple(manifest["commands"]) != EXPECTED_COMMANDS:
            fail("verification command set or order changed")

        source_commit = manifest["source_commit"]
        if not isinstance(source_commit, str) or COMMIT.fullmatch(source_commit) is None:
            fail("source_commit must be a full lowercase Git object ID")
        git("cat-file", "-e", f"{source_commit}^{{commit}}")
        git("merge-base", "--is-ancestor", source_commit, "HEAD")
        tracked_paths = git("ls-tree", "-r", "--name-only", source_commit).splitlines()
        if any(path.startswith(b".github/workflows/") for path in tracked_paths):
            fail("assessed commit contains forbidden hosted CI")

        artifacts = manifest["artifacts"]
        if not isinstance(artifacts, list) or not artifacts:
            fail("artifacts must be a non-empty array")
        paths: list[str] = []
        for artifact in artifacts:
            if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
                fail("artifact entries require exactly path and sha256")
            path = artifact["path"]
            expected = artifact["sha256"]
            if (
                not isinstance(path, str)
                or not path
                or path.startswith("/")
                or ".." in Path(path).parts
            ):
                fail("artifact path must be repository-relative")
            if not isinstance(expected, str) or SHA.fullmatch(expected) is None:
                fail(f"invalid SHA-256 for {path}")
            actual = hashlib.sha256(git("show", f"{source_commit}:{path}")).hexdigest()
            if actual != expected:
                fail(f"digest mismatch for {path}: expected {expected}, got {actual}")
            paths.append(path)
        if paths != sorted(paths) or len(set(paths)) != len(paths):
            fail("artifact paths must be sorted and unique")

        validate_nonempty_strings(manifest["claim_boundaries"], "claim_boundaries")
        validate_nonempty_strings(manifest["release_blockers"], "release_blockers")
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"assessor-manifest: {error}", file=sys.stderr)
        return 1

    print(
        "assessor-manifest: passed "
        f"commit={manifest['source_commit']} artifacts={len(manifest['artifacts'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
