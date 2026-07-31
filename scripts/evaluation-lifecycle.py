#!/usr/bin/env python3
"""Bounded, fail-closed lifecycle manager for private Telosieve evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path


SCHEMA = "telosieve.evaluation-install/v1"
BACKUP_SCHEMA = "telosieve.evaluation-backup/v1"
CONFIG_SCHEMAS = {
    "telosieve.evaluation-config/v2",
    "telosieve.evaluation-config/v3",
    "telosieve.evaluation-config/v4",
}
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_CONFIG_BYTES = 64 * 1024
MAX_BACKUP_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_BACKUP_BYTES = 1024 * 1024 * 1024
MAX_BACKUP_FILES = 10_000
MAX_RELEASES = 16


class LifecycleError(Exception):
    """Expected fail-closed lifecycle rejection."""


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def strict_json(value: bytes, label: str) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise LifecycleError(f"{label} contains duplicate key {key!r}")
            result[key] = item
        return result

    try:
        return json.loads(value, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LifecycleError(f"{label} JSON is invalid: {error}") from error


def bounded_file(path: Path, maximum: int, label: str) -> bytes:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise LifecycleError(f"{label} must be an absolute regular file")
    metadata = path.stat()
    if metadata.st_nlink != 1:
        raise LifecycleError(f"{label} must not be hard-linked")
    if metadata.st_size > maximum:
        raise LifecycleError(f"{label} exceeds {maximum} bytes")
    return path.read_bytes()


def validated_root(value: str) -> Path:
    root = Path(value)
    if not root.is_absolute() or root == Path("/") or root.is_symlink():
        raise LifecycleError("root must be an absolute, non-symlink directory below /")
    if root.exists() and not root.is_dir():
        raise LifecycleError("root exists and is not a directory")
    if root.exists() and root.stat().st_mode & 0o077:
        raise LifecycleError("existing root must not grant group or other permissions")
    parent = root.parent.resolve(strict=True)
    return parent / root.name


def validated_inputs(binary_value: str, config_value: str) -> tuple[bytes, bytes]:
    binary_path = Path(binary_value)
    config_path = Path(config_value)
    binary = bounded_file(binary_path, MAX_BINARY_BYTES, "binary")
    config = bounded_file(config_path, MAX_CONFIG_BYTES, "configuration")
    if binary_path.stat().st_mode & 0o111 == 0:
        raise LifecycleError("binary is not executable")
    parsed = strict_json(config, "configuration")
    if not isinstance(parsed, dict) or parsed.get("schema_version") not in CONFIG_SCHEMAS:
        raise LifecycleError("configuration schema is unsupported")
    expected = {
        "telosieve.evaluation-config/v4": {
            "schema_version", "mode", "scenario_path", "snapshot_path",
            "observation_trust_path", "observation_quorum_path",
            "certificate_path", "ledger_path",
        },
        "telosieve.evaluation-config/v2": {
            "schema_version", "mode", "scenario_path", "certificate_path",
            "ledger_path", "kubernetes",
        },
        "telosieve.evaluation-config/v3": {
            "schema_version", "mode", "scenario_path", "plan_path",
            "certificate_path", "ledger_path",
        },
    }[parsed["schema_version"]]
    expected_mode = {
        "telosieve.evaluation-config/v4": "kubernetes-shadow",
        "telosieve.evaluation-config/v2": "kubernetes-live",
        "telosieve.evaluation-config/v3": "opentofu-plan",
    }[parsed["schema_version"]]
    if set(parsed) != expected or parsed.get("mode") != expected_mode:
        raise LifecycleError("configuration fields or mode do not match its schema")
    string_fields = expected - {"schema_version", "mode", "kubernetes"}
    if any(not isinstance(parsed.get(field), str) or not parsed[field] for field in string_fields):
        raise LifecycleError("configuration path fields must be nonempty strings")
    if any(
        len(parsed[field]) > 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in parsed[field])
        or not Path(parsed[field]).is_absolute()
        for field in string_fields
    ):
        raise LifecycleError("packaged configuration paths must be bounded absolute paths")
    if parsed["schema_version"] == "telosieve.evaluation-config/v2":
        kubernetes = parsed.get("kubernetes")
        kubernetes_fields = {
            "kubectl_path", "kubeconfig_path", "context", "namespace",
            "desired_config_map", "observed_stateful_set",
        }
        if (
            not isinstance(kubernetes, dict)
            or set(kubernetes) != kubernetes_fields
            or any(
                not isinstance(kubernetes.get(field), str) or not kubernetes[field]
                for field in kubernetes_fields
            )
        ):
            raise LifecycleError("live Kubernetes configuration shape is invalid")
        if not Path(kubernetes["kubectl_path"]).is_absolute() or not Path(
            kubernetes["kubeconfig_path"]
        ).is_absolute():
            raise LifecycleError("live Kubernetes file paths must be absolute")
    return binary, config


def atomic_write(path: Path, value: bytes, mode: int) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        Path(temporary).unlink(missing_ok=True)
        raise


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def release_identifier(binary: bytes, config: bytes) -> str:
    return digest_bytes(
        b"telosieve-evaluation-release-v1\0"
        + hashlib.sha256(binary).digest()
        + hashlib.sha256(config).digest()
    )


def release_manifest(binary: bytes, config: bytes) -> bytes:
    value = {
        "schema_version": SCHEMA,
        "binary_sha256": digest_bytes(binary),
        "binary_size": len(binary),
        "configuration_sha256": digest_bytes(config),
        "configuration_size": len(config),
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def materialize_release(root: Path, binary: bytes, config: bytes) -> Path:
    releases = root / "releases"
    if releases.is_symlink():
        raise LifecycleError("managed releases directory is a symlink")
    releases.mkdir(parents=True, exist_ok=True, mode=0o700)
    identifier = release_identifier(binary, config)
    destination = releases / identifier
    expected_manifest = release_manifest(binary, config)
    if destination.exists():
        verify_release(destination)
        if (destination / "install.json").read_bytes() != expected_manifest:
            raise LifecycleError("existing release identifier has conflicting content")
        return destination
    if sum(1 for path in releases.iterdir() if path.is_dir() and not path.is_symlink()) >= MAX_RELEASES:
        raise LifecycleError(f"installation exceeds {MAX_RELEASES} retained releases")
    staging = Path(tempfile.mkdtemp(prefix=".release.", dir=releases))
    try:
        atomic_write(staging / "telosieve", binary, 0o500)
        atomic_write(staging / "evaluation.json", config, 0o400)
        atomic_write(staging / "install.json", expected_manifest, 0o400)
        fsync_directory(staging)
        os.replace(staging, destination)
        fsync_directory(releases)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination


def activate(root: Path, release: Path) -> None:
    relative = Path("releases") / release.name
    temporary = root / f".current.{os.getpid()}"
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(relative, target_is_directory=True)
    os.replace(temporary, root / "current")
    fsync_directory(root)


def verify_release(release: Path) -> dict[str, object]:
    if release.is_symlink() or not release.is_dir():
        raise LifecycleError("release is not a regular directory")
    if release.stat().st_mode & 0o077:
        raise LifecycleError("release directory grants group or other permissions")
    allowed = {"telosieve", "evaluation.json", "install.json"}
    entries = list(release.iterdir())
    if {path.name for path in entries} != allowed or any(path.is_symlink() for path in entries):
        raise LifecycleError("release contains unexpected or missing files")
    if any(path.stat().st_mode & 0o077 for path in entries):
        raise LifecycleError("release file grants group or other permissions")
    binary = bounded_file((release / "telosieve").resolve(), MAX_BINARY_BYTES, "release binary")
    config = bounded_file(
        (release / "evaluation.json").resolve(), MAX_CONFIG_BYTES, "release configuration"
    )
    manifest_bytes = bounded_file(
        (release / "install.json").resolve(), MAX_CONFIG_BYTES, "release manifest"
    )
    manifest = strict_json(manifest_bytes, "release manifest")
    if manifest_bytes != release_manifest(binary, config):
        raise LifecycleError("release manifest or content digest does not match")
    if release.name != release_identifier(binary, config):
        raise LifecycleError("release directory identifier does not match")
    if (release / "telosieve").stat().st_mode & 0o111 == 0:
        raise LifecycleError("release binary is not executable")
    return manifest


def active_release(root: Path) -> Path:
    current = root / "current"
    if not current.is_symlink():
        raise LifecycleError("installation has no managed current release")
    resolved = current.resolve(strict=True)
    releases = (root / "releases").resolve(strict=True)
    if resolved.parent != releases:
        raise LifecycleError("current release escapes the managed releases directory")
    if os.readlink(current) != str(Path("releases") / resolved.name):
        raise LifecycleError("current release link is not in canonical managed form")
    verify_release(resolved)
    return resolved


def install_or_upgrade(
    root: Path, binary_value: str, config_value: str, require_existing: bool
) -> None:
    exists = (root / "current").exists() or (root / "current").is_symlink()
    if require_existing != exists:
        action = "upgrade" if require_existing else "install"
        state = "requires an existing installation" if require_existing else "refuses an existing installation"
        raise LifecycleError(f"{action} {state}")
    if exists:
        active_release(root)
    binary, config = validated_inputs(binary_value, config_value)
    root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)
    evidence = root / "evidence"
    if evidence.is_symlink() or (evidence.exists() and not evidence.is_dir()):
        raise LifecycleError("managed evidence path is not a regular directory")
    evidence.mkdir(mode=0o700, exist_ok=True)
    if evidence.stat().st_mode & 0o077:
        raise LifecycleError("managed evidence directory grants group or other permissions")
    release = materialize_release(root, binary, config)
    activate(root, release)
    print(json.dumps({"status": "activated", "release": release.name}, sort_keys=True))


def inventory(
    directory: Path, excluded: frozenset[str] = frozenset()
) -> tuple[list[dict[str, object]], int]:
    records: list[dict[str, object]] = []
    total = 0
    if not directory.exists():
        return records, total
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise LifecycleError(f"backup source contains symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise LifecycleError(f"backup source contains unsupported entry: {path}")
        relative = path.relative_to(directory).as_posix()
        if relative in excluded:
            continue
        size = path.stat().st_size
        if len(records) + 1 > MAX_BACKUP_FILES or total + size > MAX_BACKUP_BYTES:
            raise LifecycleError("backup exceeds file-count or byte bound")
        data = path.read_bytes()
        total += size
        records.append({"path": relative, "sha256": digest_bytes(data), "size": len(data)})
    return records, total


def backup(root: Path, output_value: str) -> None:
    release = active_release(root)
    output = Path(output_value)
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise LifecycleError("backup output must be an absent absolute path")
    output_parent = output.parent.resolve(strict=True)
    if output_parent == root or output_parent.is_relative_to(root):
        raise LifecycleError("backup output must be outside the installation root")
    evidence = root / "evidence"
    if evidence.is_symlink() or (evidence.exists() and not evidence.is_dir()):
        raise LifecycleError("managed evidence path is not a regular directory")
    inventory(evidence)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        backup_release = staging / "release" / release.name
        backup_release.parent.mkdir(mode=0o700)
        shutil.copytree(release, backup_release)
        if evidence.exists():
            shutil.copytree(evidence, staging / "evidence")
        for directory in [staging, *[path for path in staging.rglob("*") if path.is_dir()]]:
            os.chmod(directory, 0o700)
        for file in [path for path in staging.rglob("*") if path.is_file()]:
            os.chmod(file, 0o500 if file.name == "telosieve" else 0o400)
        records, total = inventory(staging)
        manifest = {
            "schema_version": BACKUP_SCHEMA,
            "active_release": release.name,
            "files": records,
            "total_bytes": total,
        }
        manifest_bytes = (
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        if len(manifest_bytes) > MAX_BACKUP_MANIFEST_BYTES:
            raise LifecycleError("backup manifest exceeds its byte bound")
        atomic_write(
            staging / "backup.json",
            manifest_bytes,
            0o600,
        )
        os.chmod(staging, 0o700)
        fsync_directory(staging)
        os.replace(staging, output)
        fsync_directory(output.parent)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print(json.dumps({"status": "backed-up", "files": len(records), "bytes": total}, sort_keys=True))


def verified_backup(path: Path) -> tuple[bytes, bytes]:
    manifest_bytes = bounded_file(
        path / "backup.json", MAX_BACKUP_MANIFEST_BYTES, "backup manifest"
    )
    manifest = strict_json(manifest_bytes, "backup manifest")
    if manifest.get("schema_version") != BACKUP_SCHEMA or not isinstance(manifest.get("files"), list):
        raise LifecycleError("backup manifest schema is invalid")
    actual, total = inventory(path, frozenset({"backup.json"}))
    for entry in path.rglob("*"):
        if entry.stat().st_mode & 0o077:
            raise LifecycleError("backup contains group- or other-accessible content")
    if manifest.get("files") != actual or manifest.get("total_bytes") != total:
        raise LifecycleError("backup content digest, size, or inventory does not match")
    identifier = manifest.get("active_release")
    if not isinstance(identifier, str) or len(identifier) != 64:
        raise LifecycleError("backup active release identifier is invalid")
    release = path / "release" / identifier
    verify_release(release)
    if identifier != release.name:
        raise LifecycleError("backup active release does not match")
    return (release / "telosieve").read_bytes(), (release / "evaluation.json").read_bytes()


def rollback(root: Path, backup_value: str) -> None:
    active_release(root)
    backup_path = Path(backup_value)
    if not backup_path.is_absolute() or backup_path.is_symlink() or not backup_path.is_dir():
        raise LifecycleError("rollback backup must be an absolute regular directory")
    binary, config = verified_backup(backup_path)
    release = materialize_release(root, binary, config)
    activate(root, release)
    print(json.dumps({"status": "rolled-back", "release": release.name}, sort_keys=True))


def uninstall(root: Path, confirmation: str) -> None:
    if confirmation != str(root):
        raise LifecycleError("uninstall requires --confirm-root equal to the canonical root")
    active_release(root)
    current = root / "current"
    current.unlink()
    releases = root / "releases"
    if releases.is_symlink():
        raise LifecycleError("managed releases directory is a symlink")
    shutil.rmtree(releases)
    fsync_directory(root)
    print(json.dumps({"status": "uninstalled", "evidence_preserved": True}, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)
    for name in ("install", "upgrade"):
        command = subparsers.add_parser(name)
        command.add_argument("--root", required=True)
        command.add_argument("--binary", required=True)
        command.add_argument("--config", required=True)
    command = subparsers.add_parser("backup")
    command.add_argument("--root", required=True)
    command.add_argument("--output", required=True)
    command = subparsers.add_parser("rollback")
    command.add_argument("--root", required=True)
    command.add_argument("--backup", required=True)
    command = subparsers.add_parser("uninstall")
    command.add_argument("--root", required=True)
    command.add_argument("--confirm-root", required=True)
    return result


@contextmanager
def lifecycle_lock(root: Path):
    root.mkdir(mode=0o700, exist_ok=True)
    lock = root / ".lifecycle.lock"
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError as error:
        raise LifecycleError("another lifecycle operation may be active") from error
    try:
        yield
    finally:
        lock.rmdir()


def main() -> int:
    arguments = parser().parse_args()
    try:
        root = validated_root(arguments.root)
        with lifecycle_lock(root):
            if arguments.command == "install":
                install_or_upgrade(root, arguments.binary, arguments.config, False)
            elif arguments.command == "upgrade":
                install_or_upgrade(root, arguments.binary, arguments.config, True)
            elif arguments.command == "backup":
                backup(root, arguments.output)
            elif arguments.command == "rollback":
                rollback(root, arguments.backup)
            elif arguments.command == "uninstall":
                uninstall(root, arguments.confirm_root)
            else:
                raise LifecycleError("unsupported command")
    except (LifecycleError, OSError) as error:
        print(f"evaluation-lifecycle: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
