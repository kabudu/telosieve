#!/usr/bin/env python3
"""Validate public-source governance without authorizing publication."""

import subprocess
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REQUIRED = (
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "docs/PUBLIC_OPENING_DECISION.md",
    "docs/DILIGENCE_REFRESH_2026-08-08.md",
)


def main() -> int:
    errors: list[str] = []
    for relative in REQUIRED:
        path = ROOT / relative
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            errors.append(f"missing or unsafe public-source file: {relative}")

    with (ROOT / "Cargo.toml").open("rb") as stream:
        package = tomllib.load(stream).get("package", {})
    expected = {
        "license": "Apache-2.0",
        "repository": "https://github.com/kabudu/telosieve",
        "homepage": "https://github.com/kabudu/telosieve",
        "readme": "README.md",
        "rust-version": "1.97",
        "publish": False,
    }
    for key, value in expected.items():
        if package.get(key) != value:
            errors.append(f"Cargo package metadata mismatch: {key}")
    if not isinstance(package.get("description"), str) or not package["description"]:
        errors.append("Cargo package description is missing")
    if not isinstance(package.get("keywords"), list) or not 1 <= len(package["keywords"]) <= 5:
        errors.append("Cargo package keywords are missing or unbounded")
    if not isinstance(package.get("categories"), list) or not package["categories"]:
        errors.append("Cargo package categories are missing")

    licence = (ROOT / "LICENSE").read_text(encoding="utf-8")
    if "Apache License" not in licence or "Version 2.0, January 2004" not in licence:
        errors.append("Apache-2.0 licence text is incomplete")
    decision = (ROOT / "docs/PUBLIC_OPENING_DECISION.md").read_text(encoding="utf-8")
    for phrase in ("evaluation software", "hosted CI", "does not authorize"):
        if phrase not in decision:
            errors.append(f"public-opening boundary missing: {phrase}")

    history = subprocess.run(
        ["python3", "scripts/audit-public-history.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if history.returncode:
        errors.append(history.stdout.strip() or history.stderr.strip() or "public history audit failed")

    for error in errors:
        print(f"open-source-readiness: {error}")
    if errors:
        return 1
    print(history.stdout.strip())
    print("open-source-readiness: passed (publication not authorized by validation alone)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
