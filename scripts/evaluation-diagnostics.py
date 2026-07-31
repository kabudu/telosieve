#!/usr/bin/env python3
"""Generate bounded, content-redacted private evaluation diagnostics."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path


SCHEMA = "telosieve.operator-diagnostics/v1"
INSTALL_SCHEMA = "telosieve.evaluation-install/v1"
MAX_FILES = 1_000
MAX_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024


class DiagnosticError(Exception):
    pass


def sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & 0o077
        ):
            raise DiagnosticError("opened diagnostic input is not a private regular file")
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
        value.st_mode, value.st_nlink,
    )
    if identity(before) != identity(after):
        raise DiagnosticError("file changed during diagnostics")
    return digest.hexdigest(), after.st_size


def regular_private(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        raise DiagnosticError(f"{label} is not a single-link regular file")
    if path.stat().st_mode & 0o077:
        raise DiagnosticError(f"{label} grants group or other permissions")


def canonical_root(value: str) -> Path:
    root = Path(value)
    if not root.is_absolute() or root == Path("/") or root.is_symlink() or not root.is_dir():
        raise DiagnosticError("root must be an absolute private installation directory")
    root = root.resolve(strict=True)
    if root.stat().st_mode & 0o077:
        raise DiagnosticError("root grants group or other permissions")
    return root


def active_release(root: Path) -> Path:
    current = root / "current"
    releases = root / "releases"
    if not current.is_symlink() or releases.is_symlink() or not releases.is_dir():
        raise DiagnosticError("installation has no managed active release")
    release = current.resolve(strict=True)
    if release.parent != releases.resolve(strict=True):
        raise DiagnosticError("active release escapes the managed root")
    if os.readlink(current) != str(Path("releases") / release.name):
        raise DiagnosticError("active release link is noncanonical")
    if release.is_symlink() or release.stat().st_mode & 0o077:
        raise DiagnosticError("active release permissions are unsafe")
    expected = {"telosieve", "evaluation.json", "install.json"}
    entries = list(release.iterdir())
    if {entry.name for entry in entries} != expected:
        raise DiagnosticError("active release shape is invalid")
    for entry in entries:
        regular_private(entry, "active release file")
    manifest_path = release / "install.json"
    if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise DiagnosticError("install manifest exceeds its bound")
    try:
        manifest = json.loads(manifest_path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiagnosticError(f"install manifest is invalid: {error}") from error
    if manifest.get("schema_version") != INSTALL_SCHEMA:
        raise DiagnosticError("install manifest schema is invalid")
    if set(manifest) != {
        "schema_version", "binary_sha256", "binary_size",
        "configuration_sha256", "configuration_size",
    }:
        raise DiagnosticError("install manifest fields are invalid")
    binary_digest, binary_size = sha256(release / "telosieve")
    config_digest, config_size = sha256(release / "evaluation.json")
    if (
        manifest.get("binary_sha256") != binary_digest
        or manifest.get("binary_size") != binary_size
        or manifest.get("configuration_sha256") != config_digest
        or manifest.get("configuration_size") != config_size
    ):
        raise DiagnosticError("active release content does not match its manifest")
    return release


def evidence_summary(root: Path) -> tuple[list[dict[str, object]], int]:
    evidence = root / "evidence"
    if evidence.is_symlink() or not evidence.is_dir() or evidence.stat().st_mode & 0o077:
        raise DiagnosticError("evidence directory is missing or unsafe")
    files: list[Path] = []
    for entry in sorted(evidence.rglob("*")):
        if entry.is_symlink() or (not entry.is_dir() and not entry.is_file()):
            raise DiagnosticError("evidence contains an unsupported entry")
        if entry.stat().st_mode & 0o077:
            raise DiagnosticError("evidence contains group- or other-accessible content")
        if entry.is_file():
            regular_private(entry, "evidence file")
            files.append(entry)
    if len(files) > MAX_FILES:
        raise DiagnosticError(f"evidence exceeds {MAX_FILES} files")
    records: list[dict[str, object]] = []
    total = 0
    for index, path in enumerate(files, 1):
        digest, observed_size = sha256(path)
        if total + observed_size > MAX_BYTES:
            raise DiagnosticError(f"evidence exceeds {MAX_BYTES} bytes")
        total += observed_size
        records.append({"id": index, "sha256": digest, "size": observed_size})
    return records, total


def write_export(root: Path, output_value: str) -> None:
    output = Path(output_value)
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise DiagnosticError("output must be an absent absolute path")
    parent = output.parent.resolve(strict=True)
    if parent == root or parent.is_relative_to(root):
        raise DiagnosticError("output must be outside the installation root")
    release = active_release(root)
    records, total = evidence_summary(root)
    manifest = json.loads((release / "install.json").read_bytes())
    result = {
        "schema_version": SCHEMA,
        "status": "healthy",
        "privacy": {
            "content_included": False,
            "environment_included": False,
            "paths_included": False,
        },
        "installation": {
            "release_id": release.name,
            "binary_sha256": manifest["binary_sha256"],
            "configuration_sha256": manifest["configuration_sha256"],
        },
        "evidence": {"file_count": len(records), "total_bytes": total, "files": records},
        "checks": {
            "active_release_verified": True,
            "evidence_bounds_verified": True,
            "owner_only_permissions_verified": True,
        },
    }
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, output)
        Path(temporary).unlink()
        directory = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        Path(temporary).unlink(missing_ok=True)
        raise
    print(json.dumps({"status": "exported", "files": len(records), "bytes": total}))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    try:
        write_export(canonical_root(arguments.root), arguments.output)
    except (DiagnosticError, OSError) as error:
        print(f"evaluation-diagnostics: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
