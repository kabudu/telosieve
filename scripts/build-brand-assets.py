#!/usr/bin/env python3
"""Build and verify deterministic Telosieve brand exports and provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BRAND = ROOT / "assets/brand"
MANIFEST = BRAND / "BRAND_ASSET_MANIFEST.json"
MAX_SVG_BYTES = 256 * 1024
MAX_PNG_BYTES = 2 * 1024 * 1024
EXPORTS = {
    "exports/favicon-32.png": ("source/telosieve-favicon.svg", 32, 32),
    "exports/avatar-256.png": ("source/telosieve-reversed.svg", 256, 256),
    "exports/social-card-1200x630.png": ("templates/release-card.svg", 1200, 630),
}
CONTRAST_PAIRS = (
    ("#101820", "#F7FAFC", 7.0),
    ("#006B5F", "#FFFFFF", 4.5),
    ("#B42318", "#FFFFFF", 4.5),
    ("#475467", "#FFFFFF", 4.5),
    ("#F7FAFC", "#101820", 7.0),
    ("#57D7C0", "#101820", 4.5),
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def channel(value: int) -> float:
    component = value / 255
    return component / 12.92 if component <= 0.04045 else ((component + 0.055) / 1.055) ** 2.4


def luminance(colour: str) -> float:
    values = [int(colour[index:index + 2], 16) for index in (1, 3, 5)]
    return 0.2126 * channel(values[0]) + 0.7152 * channel(values[1]) + 0.0722 * channel(values[2])


def contrast(first: str, second: str) -> float:
    high, low = sorted((luminance(first), luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def validate_svg(path: Path) -> None:
    data = path.read_bytes()
    label = path.relative_to(ROOT) if path.is_relative_to(ROOT) else Path(path.name)
    if len(data) > MAX_SVG_BYTES:
        raise SystemExit(f"brand-assets: oversized SVG: {label}")
    root = ET.fromstring(data)
    namespace = "{http://www.w3.org/2000/svg}"
    if root.tag != f"{namespace}svg" or root.find(f"{namespace}title") is None or root.find(f"{namespace}desc") is None:
        raise SystemExit(f"brand-assets: SVG lacks accessible title/description: {label}")
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1].lower()
        if local_name in {"script", "foreignobject", "image", "metadata"}:
            raise SystemExit(f"brand-assets: unsafe SVG element: {label}")
        for key, value in element.attrib.items():
            lowered = value.lower()
            if key.rsplit("}", 1)[-1].lower() == "href" or any(
                item in lowered for item in ("javascript:", "http://", "https://", "url(")
            ):
                raise SystemExit(f"brand-assets: unsafe SVG attribute: {label}")


def png_dimensions(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    if len(data) > MAX_PNG_BYTES or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise SystemExit(f"brand-assets: invalid or oversized PNG: {path.relative_to(ROOT)}")
    return struct.unpack(">II", data[16:24])


def rasterise(source: Path, output: Path, width: int, height: int) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    raw = output.with_suffix(".raw.png")
    if shutil.which("sips"):
        render = ["sips", "-s", "format", "png", "-z", str(height), str(width), str(source), "--out", str(raw)]
    elif shutil.which("rsvg-convert"):
        render = ["rsvg-convert", "--width", str(width), "--height", str(height), "--output", str(raw), str(source)]
    else:
        raise SystemExit("brand-assets: sips or rsvg-convert is required for faithful SVG text rendering")
    result = subprocess.run(render, cwd=ROOT, check=False, capture_output=True, timeout=30)
    if result.returncode:
        detail = result.stderr.decode(errors="replace")[-2048:]
        raise SystemExit(f"brand-assets: SVG rendering failed: {detail}")
    normalise = ["magick", str(raw), "-strip", "-define", "png:exclude-chunks=date,time", f"PNG32:{output}"]
    result = subprocess.run(normalise, cwd=ROOT, check=False, capture_output=True, timeout=30)
    raw.unlink(missing_ok=True)
    if result.returncode:
        detail = result.stderr.decode(errors="replace")[-2048:]
        raise SystemExit(f"brand-assets: PNG normalisation failed: {detail}")
    if png_dimensions(output) != (width, height):
        raise SystemExit(f"brand-assets: raster dimensions drifted: {output.name}")


def manifest_for(export_root: Path) -> dict:
    entries = []
    for path in sorted(BRAND.glob("**/*")):
        if not path.is_file() or path == MANIFEST or "exports" in path.parts:
            continue
        relative = path.relative_to(BRAND).as_posix()
        entries.append({
            "path": relative,
            "sha256": sha256(path),
            "bytes": path.stat().st_size,
            "license": "Apache-2.0",
            "provenance": "repository-authored",
            "allowed_use": "Telosieve product, documentation, evaluation, and community communication",
        })
    for relative, (_, width, height) in sorted(EXPORTS.items()):
        path = export_root / Path(relative).name
        entries.append({
            "path": relative,
            "sha256": sha256(path),
            "bytes": path.stat().st_size,
            "dimensions": [width, height],
            "colour_space": "sRGB with alpha",
            "license": "Apache-2.0",
            "provenance": "deterministic platform SVG render normalized by ImageMagick from declared SVG source",
            "allowed_use": "Telosieve product, documentation, release, and social communication",
            "export_command": f"python3 scripts/build-brand-assets.py --rebuild ({EXPORTS[relative][0]} -> {relative})",
        })
    return {"schema_version": "telosieve.brand-assets/v1", "brand_version": "4.0.0", "entries": entries}


def build(directory: Path) -> dict:
    for path in sorted(BRAND.glob("**/*.svg")):
        validate_svg(path)
    for foreground, background, minimum in CONTRAST_PAIRS:
        if contrast(foreground, background) < minimum:
            raise SystemExit(f"brand-assets: contrast failure: {foreground} on {background}")
    for relative, (source, width, height) in EXPORTS.items():
        rasterise(BRAND / source, directory / Path(relative).name, width, height)
    return manifest_for(directory)


def canonical(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=False) + "\n").encode("utf-8")


def exercise_refusals(directory: Path) -> int:
    cases = {
        "script.svg": '<svg xmlns="http://www.w3.org/2000/svg"><title>x</title><desc>x</desc><script/></svg>',
        "remote.svg": '<svg xmlns="http://www.w3.org/2000/svg"><title>x</title><desc>x</desc><path href="https://invalid.example/x"/></svg>',
        "missing-description.svg": '<svg xmlns="http://www.w3.org/2000/svg"><title>x</title></svg>',
    }
    refused = 0
    for name, content in cases.items():
        path = directory / name
        path.write_text(content, encoding="utf-8")
        try:
            validate_svg(path)
        except SystemExit:
            refused += 1
        else:
            raise SystemExit(f"brand-assets: unsafe SVG self-test accepted: {name}")
    oversized = directory / "oversized.svg"
    oversized.write_bytes(b"x" * (MAX_SVG_BYTES + 1))
    try:
        validate_svg(oversized)
    except SystemExit:
        refused += 1
    else:
        raise SystemExit("brand-assets: oversized SVG self-test accepted")
    return refused


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rebuild", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.rebuild == args.check:
        raise SystemExit("brand-assets: select exactly one of --rebuild or --check")
    with tempfile.TemporaryDirectory(prefix="telosieve-brand-") as raw:
        first = Path(raw) / "first"
        second = Path(raw) / "second"
        refusals = Path(raw) / "refusals"
        first.mkdir()
        second.mkdir()
        refusals.mkdir()
        refusal_count = exercise_refusals(refusals)
        first_manifest = build(first)
        second_manifest = build(second)
        for relative in EXPORTS:
            name = Path(relative).name
            if (first / name).read_bytes() != (second / name).read_bytes():
                raise SystemExit(f"brand-assets: nondeterministic export: {relative}")
        if first_manifest != second_manifest:
            raise SystemExit("brand-assets: nondeterministic manifest")
        if args.rebuild:
            exports = BRAND / "exports"
            exports.mkdir(parents=True, exist_ok=True)
            for relative in EXPORTS:
                name = Path(relative).name
                shutil.copyfile(first / name, exports / name)
            MANIFEST.write_bytes(canonical(first_manifest))
            print(f"brand-assets: rebuilt exports={len(EXPORTS)} entries={len(first_manifest['entries'])} refusals={refusal_count}")
            return 0
        if not MANIFEST.is_file() or MANIFEST.read_bytes() != canonical(first_manifest):
            raise SystemExit("brand-assets: manifest drift; run with --rebuild")
        for relative in EXPORTS:
            name = Path(relative).name
            if (BRAND / relative).read_bytes() != (first / name).read_bytes():
                raise SystemExit(f"brand-assets: committed export drift: {relative}")
        print(f"brand-assets: passed exports={len(EXPORTS)} entries={len(first_manifest['entries'])} refusals={refusal_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
