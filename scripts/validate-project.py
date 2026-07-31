#!/usr/bin/env python3
"""Validate Telosieve's repository-owned documentation contract."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REQUIRED = (
    "README.md",
    "AGENTS.md",
    "docs/ARCHITECTURE.md",
    "docs/ASSESSOR_HANDOFF.md",
    "docs/AUTHORITY_PROTOCOL.md",
    "docs/E2E_TESTING.md",
    "docs/EVALUATION_PRODUCT_DECISION.md",
    "docs/EVALUATION_CLI.md",
    "docs/EVALUATION_LIFECYCLE.md",
    "docs/OPERATOR_DIAGNOSTICS.md",
    "docs/PRIVATE_BUNDLE.md",
    "docs/CANDIDATE_SIGNING.md",
    "docs/IMPLEMENTATION_PLAN.md",
    "docs/RELEASE.md",
    "docs/REQUIREMENTS_TRACEABILITY.md",
    "docs/SUPPLY_CHAIN.md",
    "docs/THREAT_MODEL.md",
    "docs/VALIDATION.md",
    "docs/WITNESS_OPERATOR_HANDOFF.md",
    "assessment/manifest.json",
    "assessment/witness-operator-request.json",
    "evaluation/contract.json",
    "evaluation/config.example.json",
    "scripts/evaluation-lifecycle.py",
    "scripts/run-evaluation-lifecycle-qualification.py",
    "scripts/evaluation-diagnostics.py",
    "scripts/run-diagnostics-qualification.py",
    "scripts/build-private-bundle.py",
    "scripts/run-private-bundle-qualification.py",
)
LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
PLACEHOLDER = re.compile(r"\b(?:TODO|FIXME|REPLACE_WITH)\b")


def main() -> int:
    errors: list[str] = []
    for relative in REQUIRED:
        if not (ROOT / relative).is_file():
            errors.append(f"missing required file: {relative}")

    for path in sorted(ROOT.glob("**/*.md")):
        if "target" in path.parts:
            continue
        relative = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8")
        if not text.startswith("# "):
            errors.append(f"missing H1: {relative}")
        if PLACEHOLDER.search(text):
            errors.append(f"placeholder marker: {relative}")
        if re.search(r"[ \t]+$", text, re.MULTILINE):
            errors.append(f"trailing whitespace: {relative}")
        for link in LINK.findall(text):
            if link.startswith(("http://", "https://", "#", "mailto:")):
                continue
            target = (path.parent / link.split("#", 1)[0]).resolve()
            if not target.exists():
                errors.append(f"broken local link in {relative}: {link}")

    plan = (ROOT / "docs/IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    if "- [ ] " not in plan:
        errors.append("implementation plan has no unchecked work")

    release = (ROOT / "docs/RELEASE.md").read_text(encoding="utf-8").lower()
    for phrase in ("local ci", "hosted ci", "explicit user approval"):
        if phrase not in release:
            errors.append(f"release policy missing required phrase: {phrase}")

    if (ROOT / ".github/workflows").exists():
        errors.append("hosted CI workflows are forbidden while private")

    for error in errors:
        print(f"project-validation: {error}", file=sys.stderr)
    if errors:
        return 1
    print("project-validation: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
