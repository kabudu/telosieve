#!/usr/bin/env python3
"""Validate Telosieve's product identity, assets, tokens, and claim boundary."""

import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BRAND = ROOT / "assets/brand"
REQUIRED = (
    "BRAND_ASSET_MANIFEST.json",
    "LICENSES/README.md",
    "source/telosieve-symbol.svg",
    "source/telosieve-small.svg",
    "source/telosieve-wordmark.svg",
    "source/telosieve-horizontal.svg",
    "source/telosieve-stacked.svg",
    "source/telosieve-monochrome.svg",
    "source/telosieve-reversed.svg",
    "concepts/direction-a-aperture.svg",
    "concepts/direction-b-ledger-weave.svg",
    "concepts/direction-c-bounded-horizon.svg",
    "tokens/brand.tokens.json",
    "tokens/brand.css",
    "templates/release-card.svg",
    "templates/diagram-key.svg",
    "templates/chart-key.svg",
    "exports/favicon-32.png",
    "exports/avatar-256.png",
    "exports/social-card-1200x630.png",
)
PUBLIC_COPY = (
    "README.md",
    "Cargo.toml",
    "RELEASE_NOTES_v0.2.0-rc.2.md",
    "SECURITY.md",
)
PROHIBITED = (
    re.compile(r"(?i)\bproduction[- ]ready\b"),
    re.compile(r"(?i)\bprovably safe\b"),
    re.compile(r"(?i)\bbyzantine[- ]resilient\b"),
    re.compile(r"(?i)\benterprise[- ]grade\b"),
    re.compile(r"(?i)\bprevents? (?:ai|agent|all|arbitrary) (?:escape|compromise|attack)"),
)


def main() -> int:
    errors: list[str] = []
    for relative in REQUIRED:
        path = BRAND / relative
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            errors.append(f"missing or unsafe brand asset: {relative}")

    result = subprocess.run(
        ["python3", "scripts/build-brand-assets.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if result.returncode:
        errors.append(result.stdout.strip() or result.stderr.strip() or "brand asset build check failed")

    tokens = json.loads((BRAND / "tokens/brand.tokens.json").read_text(encoding="utf-8"))
    if tokens.get("schema_version") != "telosieve.brand-tokens/v1" or tokens.get("brand_version") != "1.0.0-evaluation":
        errors.append("brand token version mismatch")
    expected_states = {"verified", "refused", "warning", "unknown"}
    if not expected_states.issubset(tokens.get("colour", {})):
        errors.append("brand tokens omit semantic states")

    identity = (ROOT / "docs/BRAND_IDENTITY.md").read_text(encoding="utf-8")
    for phrase in (
        "Brand version: `1.0.0-evaluation`",
        "| A: evidence aperture",
        "Colour never carries state alone",
        "Remaining human gates",
        "not evidence of safety",
    ):
        if phrase not in identity:
            errors.append(f"brand governance missing phrase: {phrase}")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "assets/brand/source/telosieve-horizontal.svg" not in readme:
        errors.append("README does not use the canonical horizontal brand asset")
    for relative in PUBLIC_COPY:
        text = (ROOT / relative).read_text(encoding="utf-8")
        for pattern in PROHIBITED:
            if pattern.search(text):
                errors.append(f"prohibited public claim in {relative}: {pattern.pattern}")

    for error in errors:
        print(f"brand-validation: {error}")
    if errors:
        return 1
    print(result.stdout.strip())
    print("brand-validation: passed version=1.0.0-evaluation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
