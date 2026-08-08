#!/usr/bin/env python3
"""Read and validate release metadata from the Cargo package manifest."""

import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+\Z")


def candidate_version(root: Path = ROOT) -> str:
    with (root / "Cargo.toml").open("rb") as stream:
        version = tomllib.load(stream).get("package", {}).get("version")
    if not isinstance(version, str) or VERSION_PATTERN.fullmatch(version) is None:
        raise SystemExit("release-metadata: Cargo package version is not an rc candidate")
    return version


def release_notes_path(root: Path = ROOT) -> Path:
    version = candidate_version(root)
    path = root / f"RELEASE_NOTES_v{version}.md"
    if not path.is_file() or path.is_symlink():
        raise SystemExit("release-metadata: release notes are missing or unsafe")
    return path
