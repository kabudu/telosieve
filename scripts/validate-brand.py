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
    "source/telosieve-favicon.svg",
    "source/telosieve-wordmark.svg",
    "source/telosieve-horizontal.svg",
    "source/telosieve-stacked.svg",
    "source/telosieve-monochrome.svg",
    "source/telosieve-reversed.svg",
    "concepts/direction-a-convergence-gate.svg",
    "concepts/direction-b-sieve-monogram.svg",
    "concepts/direction-c-evidence-loom.svg",
    "tokens/brand.tokens.json",
    "tokens/brand.css",
    "templates/release-card.svg",
    "templates/evaluation-overlay.svg",
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
MATURITY_TERMS = re.compile(r"(?i)\b(?:alpha|beta|evaluation|experimental|preview|production[- ]ready|release candidate)\b")
MATURITY_NEUTRAL = (
    "source/telosieve-symbol.svg",
    "source/telosieve-small.svg",
    "source/telosieve-favicon.svg",
    "source/telosieve-wordmark.svg",
    "source/telosieve-horizontal.svg",
    "source/telosieve-stacked.svg",
    "source/telosieve-monochrome.svg",
    "source/telosieve-reversed.svg",
    "templates/release-card.svg",
    "tokens/brand.tokens.json",
    "tokens/brand.css",
)
TAGLINE_ASSETS = (
    "source/telosieve-horizontal.svg",
    "source/telosieve-stacked.svg",
    "templates/release-card.svg",
)
TAGLINE = "QUESTION THE INSTRUCTION BEFORE ENFORCING IT"


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
    if tokens.get("schema_version") != "telosieve.brand-tokens/v1" or tokens.get("brand_version") != "2.0.0":
        errors.append("brand token version mismatch")
    expected_states = {"verified", "refused", "warning", "unknown"}
    if not expected_states.issubset(tokens.get("colour", {})):
        errors.append("brand tokens omit semantic states")

    identity = (ROOT / "docs/BRAND_IDENTITY.md").read_text(encoding="utf-8")
    for phrase in (
        "Brand version: `2.0.0`",
        "Product maturity is not brand identity",
        "| A: convergence gate",
        "Colour never carries state alone",
        "Remaining human gates",
        "not evidence of safety",
    ):
        if phrase not in identity:
            errors.append(f"brand governance missing phrase: {phrase}")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "assets/brand/source/telosieve-horizontal.svg" not in readme:
        errors.append("README does not use the canonical horizontal brand asset")
    for relative in MATURITY_NEUTRAL:
        text = (BRAND / relative).read_text(encoding="utf-8")
        if MATURITY_TERMS.search(text):
            errors.append(f"maturity term leaked into canonical brand asset: {relative}")
    for relative in TAGLINE_ASSETS:
        if TAGLINE not in (BRAND / relative).read_text(encoding="utf-8"):
            errors.append(f"canonical tagline drifted: {relative}")
    mutation_cases = ("alpha", "beta", "evaluation", "experimental", "preview", "production-ready", "release candidate")
    if any(MATURITY_TERMS.search(value) is None for value in mutation_cases):
        errors.append("maturity-term refusal self-test failed")
    overlay = (BRAND / "templates/evaluation-overlay.svg").read_text(encoding="utf-8")
    if "EVALUATION CANDIDATE" not in overlay or "Independent validation required" not in overlay:
        errors.append("evaluation maturity overlay is incomplete")
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
    print(f"brand-validation: passed version=2.0.0 permanent_identity=true maturity_refusals={len(mutation_cases)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
