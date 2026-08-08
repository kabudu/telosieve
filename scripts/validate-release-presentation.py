#!/usr/bin/env python3
"""Validate and render the curated GitHub release presentation."""

from __future__ import annotations

import argparse
import html
import re
import tempfile
from pathlib import Path

from release_metadata import candidate_version, release_notes_path


ROOT = Path(__file__).resolve().parent.parent
LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
REQUIRED_SECTIONS = (
    "## Highlights",
    "## Evaluation boundary",
    "## Installation",
    "## Evidence and compatibility",
    "## External validation requested",
)


def inline(value: str) -> str:
    escaped = html.escape(value)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    return LINK.sub(lambda match: f'<a href="{html.escape(match.group(2), quote=True)}">{html.escape(match.group(1))}</a>', escaped)


def render(lines: list[str]) -> str:
    body: list[str] = []
    in_list = False
    for line in lines:
        if line.startswith("# "):
            body.append(f"<h1>{inline(line[2:])}</h1>")
        elif line.startswith("## "):
            if in_list:
                body.append("</ul>")
                in_list = False
            body.append(f"<h2>{inline(line[3:])}</h2>")
        elif line.startswith("- "):
            if not in_list:
                body.append("<ul>")
                in_list = True
            body.append(f"<li>{inline(line[2:])}</li>")
        elif line:
            if in_list:
                body.append("</ul>")
                in_list = False
            body.append(f"<p>{inline(line)}</p>")
    if in_list:
        body.append("</ul>")
    return """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Telosieve release preview</title><style>:root{color-scheme:light dark}body{font:16px/1.55 system-ui,sans-serif;max-width:760px;margin:0 auto;padding:32px;color:#101820;background:#fff;overflow-wrap:anywhere}h1{font-size:2rem;line-height:1.2}h2{margin-top:2rem}li{margin:.6rem 0}code{font-family:ui-monospace,monospace;background:#eef2f6;padding:.1rem .3rem;border-radius:4px}a{color:#006b5f}@media(max-width:480px){body{padding:20px}h1{font-size:1.65rem}}@media(prefers-color-scheme:dark){body{color:#f7fafc;background:#101820}code{background:#263442}a{color:#57d7c0}}</style><main>""" + "".join(body) + "</main></html>"


def validate(text: str, path: Path, version: str) -> tuple[list[str], int]:
    lines = text.splitlines()
    errors: list[str] = []
    title = f"# Telosieve v{version}: "
    if not lines or not lines[0].startswith(title) or len(lines[0]) <= len(title):
        errors.append("title must contain product, version, and theme")
    if sum(line.startswith("# ") for line in lines) != 1:
        errors.append("release notes must contain exactly one H1")
    missing_sections = [section for section in REQUIRED_SECTIONS if section not in lines]
    if missing_sections:
        errors.append("required release-note section is missing")
    highlights = 0
    if not missing_sections:
        highlights = sum(line.startswith("- ") for line in lines[lines.index("## Highlights") + 1:lines.index("## Evaluation boundary")])
    if not 3 <= highlights <= 7:
        errors.append("release highlights must contain three to seven items")
    if "Release Notes" in text or chr(0x2014) in text:
        errors.append("release notes contain forbidden presentation text")
    for index, line in enumerate(lines[:-1]):
        if line and lines[index + 1] and not line.startswith(("#", "- ")) and not lines[index + 1].startswith(("#", "- ")):
            errors.append(f"hard-wrapped prose at lines {index + 1}-{index + 2}")
    for _, target in LINK.findall(text):
        if target.startswith(("https://", "http://", "#")):
            continue
        if not (path.parent / target.split("#", 1)[0]).resolve().exists():
            errors.append(f"broken release-note link: {target}")
    page = render(lines)
    if len(page.encode("utf-8")) > 64 * 1024:
        errors.append("rendered release preview exceeds size bound")
    return errors, highlights


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    version = candidate_version()
    path = release_notes_path()
    text = path.read_text(encoding="utf-8")
    errors, highlights = validate(text, path, version)
    for error in errors:
        print(f"release-presentation: {error}")
    if errors:
        return 1
    mutations = (
        text.replace("## Evaluation boundary", "## Missing boundary", 1),
        text.replace("# Telosieve", "# Other product", 1),
        text.replace("## Installation\n", "## Installation\nRelease Notes\n", 1),
        text.replace("## External validation requested\n", "## External validation requested\nFirst wrapped line\nsecond wrapped line\n", 1),
    )
    if any(not validate(mutation, path, version)[0] for mutation in mutations):
        raise SystemExit("release-presentation: adversarial mutation was accepted")
    lines = text.splitlines()
    page = render(lines)
    if args.output is not None:
        if not args.output.is_absolute() or args.output.exists() or not args.output.parent.is_dir():
            raise SystemExit("release-presentation: output must be an absent absolute path")
        args.output.write_text(page, encoding="utf-8")
    else:
        with tempfile.TemporaryDirectory(prefix="telosieve-release-preview-") as raw:
            preview = Path(raw) / "index.html"
            preview.write_text(page, encoding="utf-8")
            if preview.stat().st_size == 0:
                raise SystemExit("release-presentation: empty rendered preview")
    print(f"release-presentation: passed version={version} highlights={highlights} refusals={len(mutations)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
