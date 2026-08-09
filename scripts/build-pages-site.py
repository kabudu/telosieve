#!/usr/bin/env python3
"""Assemble the dependency-free Telosieve GitHub Pages site locally."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
DEFAULT_OUTPUT = ROOT / "target" / "pages"
SOURCE_FILES = (
    (SITE / "index.html", Path("index.html")),
    (SITE / "styles.css", Path("styles.css")),
    (SITE / ".nojekyll", Path(".nojekyll")),
    (SITE / "assets/telosieve-architecture.svg", Path("assets/telosieve-architecture.svg")),
    (ROOT / "assets/brand/source/telosieve-symbol.svg", Path("assets/telosieve-symbol.svg")),
    (ROOT / "assets/brand/exports/favicon-32.png", Path("assets/favicon-32.png")),
    (ROOT / "assets/brand/exports/social-card-1200x630.png", Path("assets/social-card-1200x630.png")),
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output: Path) -> None:
    resolved = output.resolve()
    if resolved == ROOT or ROOT not in resolved.parents:
        raise SystemExit("pages-build: output must remain inside the repository")
    if resolved.exists():
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True)
    entries = []
    for source, relative in SOURCE_FILES:
        if not source.is_file() or source.is_symlink():
            raise SystemExit(f"pages-build: missing or unsafe source: {source.relative_to(ROOT)}")
        destination = resolved / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        entries.append({"path": relative.as_posix(), "sha256": digest(destination), "bytes": destination.stat().st_size})
    manifest = {"schema_version": "telosieve.pages-build/v1", "entries": sorted(entries, key=lambda item: item["path"])}
    (resolved / "site-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"pages-build: passed files={len(entries) + 1} output={resolved.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    build(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
