#!/usr/bin/env python3
"""Validate the bounded, least-privilege public GitHub workflow surface."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github/workflows"
EXPECTED = {"ci.yml", "pages.yml", "release.yml"}
PINNED_USE = re.compile(r"uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}(?:\s+# .+)?$")


def main() -> int:
    errors: list[str] = []
    actual = {path.name for path in WORKFLOWS.glob("*.yml") if path.is_file()}
    if actual != EXPECTED:
        errors.append(f"workflow inventory drifted: {sorted(actual ^ EXPECTED)}")
    texts = {name: (WORKFLOWS / name).read_text(encoding="utf-8") for name in EXPECTED}
    for name, text in texts.items():
        if "pull_request_target" in text or "persist-credentials: true" in text:
            errors.append(f"unsafe trigger or checkout credential persistence: {name}")
        if "timeout-minutes:" not in text or "permissions:" not in text:
            errors.append(f"workflow lacks bounded runtime or explicit permissions: {name}")
        for line in text.splitlines():
            if line.lstrip().startswith("uses:") and not PINNED_USE.fullmatch(line.strip()):
                errors.append(f"workflow action is not commit pinned: {name}: {line.strip()}")
    combined_pr_surface = texts["ci.yml"] + texts["pages.yml"]
    if "secrets." in combined_pr_surface or "contents: write" in combined_pr_surface:
        errors.append("pull-request or Pages surface can access secrets or write contents")
    pages = texts["pages.yml"]
    if pages.count("pages: write") != 1 or "enablement: true" in pages:
        errors.append("Pages write permission must remain confined to deployment after activation")
    validate_step = pages.find("python3 scripts/validate-pages-site.py")
    build_step = pages.find("python3 scripts/build-pages-site.py")
    upload_step = pages.find("actions/upload-pages-artifact@")
    if min(validate_step, build_step, upload_step) < 0 or not validate_step < build_step < upload_step:
        errors.append("Pages workflow must validate, build, then upload the deployment artifact")
    if "ref: ${{ github.event.pull_request.head.sha || github.sha }}" not in texts["ci.yml"]:
        errors.append("pull-request CI does not bind checkout to the exact head SHA")
    release = texts["release.yml"]
    for phrase in ("environment: crates-io", "secrets.CARGO_REGISTRY_TOKEN", "--verify-tag", "--prerelease"):
        if phrase not in release:
            errors.append(f"release workflow missing safeguard: {phrase}")
    for error in errors:
        print(f"hosted-workflows: {error}")
    if errors:
        return 1
    print("hosted-workflows: passed workflows=3 pinned_actions=5 pr_secrets=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
