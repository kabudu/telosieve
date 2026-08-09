#!/usr/bin/env python3
"""Reject drift between candidate version, notes, lockfile, and assessor surface."""

import re
import tomllib
from pathlib import Path

from release_metadata import candidate_version, release_notes_path


ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    version = candidate_version()
    errors: list[str] = []
    notes = release_notes_path().read_text(encoding="utf-8")
    if not notes.startswith(f"# Telosieve v{version}:"):
        errors.append("release notes title does not contain product, version, and theme")

    with (ROOT / "Cargo.lock").open("rb") as stream:
        packages = tomllib.load(stream).get("package", [])
    own_versions = [item.get("version") for item in packages if item.get("name") == "telosieve"]
    if own_versions != [version]:
        errors.append("Cargo.lock package version differs from Cargo.toml")

    assessor = (ROOT / "docs/EXTERNAL_ASSESSMENT.md").read_text(encoding="utf-8")
    signed_version = "0.2.0-rc.3"
    required = (
        f"Telosieve `v{signed_version}`",
        f"version: `{signed_version}`",
        f"--expected-version {signed_version}",
    )
    for phrase in required:
        if phrase not in assessor:
            errors.append(f"assessor guide missing current version binding: {phrase}")

    for relative in (
        "scripts/build-release-candidate.py",
        "scripts/build-private-bundle.py",
        "scripts/run-private-bundle-qualification.py",
        "scripts/run-release-candidate-qualification.py",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        if re.search(r'VERSION\s*=\s*"[0-9]', text) or re.search(r'RELEASE_NOTES_v[0-9]', text):
            errors.append(f"hard-coded active release metadata: {relative}")

    for error in errors:
        print(f"release-metadata-validation: {error}")
    if errors:
        return 1
    print(f"release-metadata-validation: passed ({version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
