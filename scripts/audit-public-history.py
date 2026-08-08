#!/usr/bin/env python3
"""Bounded secret, identity, and unsafe-path audit across Git history and the worktree."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MAX_OBJECTS = 10_000
MAX_BLOB_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_CURRENT_FILE_BYTES = 16 * 1024 * 1024
MAX_CURRENT_TOTAL_BYTES = 128 * 1024 * 1024
MAX_METADATA_TOTAL_BYTES = 16 * 1024 * 1024
RISKY_NAME = re.compile(
    r"(?i)(?:^|/)(?:\.env(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)|credentials?|secrets?)(?:$|[./])|\.(?:pem|key|p12|pfx)$"
)
RISKY_CONTENT = (
    ("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("github-token", re.compile(rb"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("slack-token", re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("owner-absolute-path", re.compile(b"/Users/" + b"kab" + b"udu" + rb"(?:/|\b)")),
    ("owner-personal-email", re.compile(b"kab" + b"udu" + b"@" + b"gmail" + rb"\.com", re.IGNORECASE)),
)


def run(command: list[str], *, input_bytes: bytes | None = None) -> bytes:
    return subprocess.run(
        command,
        cwd=ROOT,
        input=input_bytes,
        capture_output=True,
        check=True,
        timeout=30,
    ).stdout


def scan(label: str, data: bytes, findings: list[str]) -> None:
    for kind, pattern in RISKY_CONTENT:
        if pattern.search(data):
            findings.append(f"{kind}: {label}")


def main() -> int:
    findings: list[str] = []
    object_lines = run(["git", "rev-list", "--objects", "--all"]).decode("utf-8").splitlines()
    object_ids = sorted({line.split(" ", 1)[0] for line in object_lines})
    if len(object_ids) > MAX_OBJECTS:
        raise SystemExit("public-history-audit: Git object count exceeds audit bound")

    paths_by_object: dict[str, set[str]] = {}
    for line in object_lines:
        object_id, _, path = line.partition(" ")
        if path:
            paths_by_object.setdefault(object_id, set()).add(path)
            if RISKY_NAME.search(path):
                findings.append(f"risky-path: {path}")

    query = "".join(f"{object_id}\n" for object_id in object_ids).encode("ascii")
    metadata = run(["git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"], input_bytes=query)
    total = 0
    scanned_blobs = 0
    metadata_total = 0
    scanned_metadata = 0
    for line in metadata.decode("ascii").splitlines():
        object_id, object_type, raw_size = line.split()
        if object_type in {"commit", "tag"}:
            size = int(raw_size)
            metadata_total += size
            if metadata_total > MAX_METADATA_TOTAL_BYTES:
                raise SystemExit("public-history-audit: Git metadata bytes exceed audit bound")
            scan(f"git-{object_type}:{object_id}", run(["git", "cat-file", object_type, object_id]), findings)
            scanned_metadata += 1
            continue
        if object_type != "blob":
            continue
        size = int(raw_size)
        if size > MAX_BLOB_BYTES:
            findings.append(f"oversized-history-blob: {object_id} ({size} bytes)")
            continue
        total += size
        if total > MAX_TOTAL_BYTES:
            raise SystemExit("public-history-audit: historical blob bytes exceed audit bound")
        data = run(["git", "cat-file", "blob", object_id])
        label = ",".join(sorted(paths_by_object.get(object_id, {object_id})))
        scan(label, data, findings)
        scanned_blobs += 1

    current_paths = run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
    ).decode("utf-8").split("\0")
    current_total = 0
    current_files = 0
    for relative in sorted(path for path in current_paths if path):
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            findings.append(f"unsafe-current-path: {relative}")
            continue
        if RISKY_NAME.search(relative):
            findings.append(f"risky-current-path: {relative}")
        size = path.stat().st_size
        if size > MAX_CURRENT_FILE_BYTES:
            findings.append(f"oversized-current-file: {relative} ({size} bytes)")
            continue
        current_total += size
        if current_total > MAX_CURRENT_TOTAL_BYTES:
            raise SystemExit("public-history-audit: current file bytes exceed audit bound")
        scan(relative, path.read_bytes(), findings)
        current_files += 1

    if findings:
        for finding in sorted(set(findings)):
            print(f"public-history-audit: {finding}")
        return 1
    print(
        "public-history-audit: passed "
        f"objects={len(object_ids)} metadata_objects={scanned_metadata} "
        f"metadata_bytes={metadata_total} historical_blobs={scanned_blobs} "
        f"historical_bytes={total} current_files={current_files} current_bytes={current_total}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
