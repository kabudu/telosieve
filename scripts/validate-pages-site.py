#!/usr/bin/env python3
"""Validate Telosieve's static website, architecture SVG, and Pages boundary."""

from __future__ import annotations

import hashlib
import json
import re
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
EXPECTED_OUTPUTS = {
    ".nojekyll", "index.html", "styles.css", "site-manifest.json",
    "assets/favicon-32.png", "assets/social-card-1200x630.png",
    "assets/telosieve-architecture.svg", "assets/telosieve-symbol.svg",
}
MAX_SITE_BYTES = 512 * 1024
MAX_ASSET_BYTES = 2 * 1024 * 1024


class SiteHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.links: list[str] = []
        self.sources: list[str] = []
        self.images = 0
        self.images_with_alt = 0
        self.has_main = False
        self.has_nav_label = False
        self.has_viewport = False
        self.has_description = False
        self.has_title = False
        self.has_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if identifier := values.get("id"):
            self.ids.add(identifier)
        if tag == "a" and values.get("href"):
            self.links.append(values["href"] or "")
        if tag in {"img", "link", "script"}:
            value = values.get("src") or values.get("href")
            if value:
                self.sources.append(value)
        if tag == "img":
            self.images += 1
            if "alt" in values:
                self.images_with_alt += 1
        if tag == "main":
            self.has_main = True
        if tag == "nav" and values.get("aria-label"):
            self.has_nav_label = True
        if tag == "meta" and values.get("name") == "viewport":
            self.has_viewport = True
        if tag == "meta" and values.get("name") == "description":
            self.has_description = True
        if tag == "script":
            self.has_script = True

    def handle_data(self, data: str) -> None:
        if self.get_starttag_text() is None and data.strip():
            return

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


def files(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}


def validate_svg(path: Path, errors: list[str]) -> None:
    namespace = "{http://www.w3.org/2000/svg}"
    try:
        root = ET.fromstring(path.read_bytes())
    except ET.ParseError as error:
        errors.append(f"architecture SVG is invalid: {error}")
        return
    if root.tag != f"{namespace}svg" or root.find(f"{namespace}title") is None or root.find(f"{namespace}desc") is None:
        errors.append("architecture SVG lacks accessible title or description")
    if root.get("viewBox") != "0 0 1600 920":
        errors.append("architecture SVG viewBox drifted")
    for element in root.iter():
        name = element.tag.rsplit("}", 1)[-1].lower()
        if name in {"script", "foreignobject", "image", "metadata"}:
            errors.append(f"unsafe architecture SVG element: {name}")
        for key, value in element.attrib.items():
            lowered = value.lower()
            if key.rsplit("}", 1)[-1].lower() == "href" or any(item in lowered for item in ("javascript:", "http://", "https://")):
                errors.append("unsafe architecture SVG reference")


def main() -> int:
    errors: list[str] = []
    html_text = (SITE / "index.html").read_text(encoding="utf-8")
    css = (SITE / "styles.css").read_text(encoding="utf-8")
    parser = SiteHTML()
    parser.feed(html_text)
    if not all((parser.has_main, parser.has_nav_label, parser.has_viewport, parser.has_description)):
        errors.append("site omits required semantic or metadata boundary")
    for phrase in (
        "<title>Telosieve | Question the instruction</title>",
        'property="og:url" content="https://kabudu.github.io/telosieve/"',
        'property="og:image" content="https://kabudu.github.io/telosieve/assets/social-card-1200x630.png"',
    ):
        if phrase not in html_text:
            errors.append(f"site metadata missing: {phrase}")
    if parser.images == 0 or parser.images != parser.images_with_alt:
        errors.append("every site image must declare alt text, including empty decorative alt")
    if parser.has_script:
        errors.append("dependency-free site must not include scripts")
    for link in parser.links:
        if link.startswith("#") and link[1:] not in parser.ids:
            errors.append(f"broken site fragment: {link}")
        elif link.startswith("https://"):
            parsed = urlparse(link)
            if parsed.netloc != "github.com" or not parsed.path.startswith("/kabudu/telosieve"):
                errors.append(f"unapproved external link: {link}")
        elif not link.startswith("#"):
            errors.append(f"unsupported site link form: {link}")
    for source in parser.sources:
        if source.startswith(("http://", "https://", "//", "data:")):
            errors.append(f"external or embedded runtime asset: {source}")
    for required in ("@media(max-width:980px)", "@media(max-width:620px)", "prefers-reduced-motion"):
        if required not in css:
            errors.append(f"responsive/accessibility CSS missing: {required}")
    if re.search(r"url\s*\(\s*['\"]?(?:https?:)?//", css, re.IGNORECASE):
        errors.append("CSS loads a remote asset")
    if len(html_text.encode()) + len(css.encode()) > MAX_SITE_BYTES:
        errors.append("site HTML/CSS budget exceeded")
    validate_svg(SITE / "assets/telosieve-architecture.svg", errors)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for phrase in ("Telosieve is a read-only evaluation system", "## How Telosieve works", "site/assets/telosieve-architecture.svg"):
        if phrase not in readme:
            errors.append(f"README comprehension surface missing: {phrase}")
    policy = (ROOT / "docs/GITHUB_PAGES.md").read_text(encoding="utf-8")
    for phrase in ("not activated", "explicit user approval", "hosted workflow", "publicly accessible"):
        if phrase not in policy:
            errors.append(f"Pages policy boundary missing: {phrase}")

    (ROOT / "target").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="telosieve-pages-", dir=ROOT / "target") as raw:
        first, second = Path(raw) / "first", Path(raw) / "second"
        for output in (first, second):
            result = subprocess.run(["python3", "scripts/build-pages-site.py", "--output", str(output)], cwd=ROOT, capture_output=True, text=True, timeout=30)
            if result.returncode:
                errors.append(result.stderr.strip() or result.stdout.strip() or "Pages build failed")
                break
        first_files, second_files = files(first), files(second)
        if set(first_files) != EXPECTED_OUTPUTS:
            errors.append(f"Pages output drifted: {sorted(set(first_files) ^ EXPECTED_OUTPUTS)}")
        if first_files != second_files:
            errors.append("Pages build is not byte deterministic")
        for relative, content in first_files.items():
            if len(content) > MAX_ASSET_BYTES:
                errors.append(f"Pages asset exceeds bound: {relative}")
        if "site-manifest.json" in first_files:
            manifest = json.loads(first_files["site-manifest.json"])
            for entry in manifest.get("entries", []):
                content = first_files.get(entry["path"])
                if content is None or hashlib.sha256(content).hexdigest() != entry["sha256"] or len(content) != entry["bytes"]:
                    errors.append(f"Pages manifest mismatch: {entry['path']}")
        favicon = first_files.get("assets/favicon-32.png", b"")
        if len(favicon) < 24 or favicon[:8] != b"\x89PNG\r\n\x1a\n" or struct.unpack(">II", favicon[16:24]) != (32, 32):
            errors.append("Pages favicon dimensions or format drifted")

    for error in errors:
        print(f"pages-validation: {error}")
    if errors:
        return 1
    print(f"pages-validation: passed outputs={len(EXPECTED_OUTPUTS)} external_runtime_assets=0 scripts=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
