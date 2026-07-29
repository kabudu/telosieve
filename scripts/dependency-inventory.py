#!/usr/bin/env python3
"""Generate or verify the deterministic locked dependency inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LOCKFILE = ROOT / "Cargo.lock"
SHA256 = re.compile(r"[0-9a-f]{64}")


def fail(message: str) -> None:
    raise ValueError(message)


def metadata() -> dict[str, object]:
    completed = subprocess.run(
        ("cargo", "metadata", "--locked", "--offline", "--format-version", "1"),
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    return json.loads(completed.stdout)


def generate() -> dict[str, object]:
    lock_bytes = LOCKFILE.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    cargo = metadata()
    cargo_packages = {
        (package["name"], package["version"], package["source"]): package
        for package in cargo["packages"]
    }
    root_id = cargo["resolve"]["root"]
    root_node = next(node for node in cargo["resolve"]["nodes"] if node["id"] == root_id)
    direct_ids = {dependency["pkg"] for dependency in root_node["deps"]}
    direct_keys = {
        (package["name"], package["version"], package["source"])
        for package in cargo["packages"]
        if package["id"] in direct_ids
    }

    packages: list[dict[str, object]] = []
    for locked in lock["package"]:
        source = locked.get("source")
        key = (locked["name"], locked["version"], source)
        package = cargo_packages.get(key)
        if package is None:
            fail(f"Cargo metadata omitted locked package {key}")
        license_expression = package.get("license")
        if not isinstance(license_expression, str) or not license_expression:
            fail(f"missing license expression for {locked['name']} {locked['version']}")
        checksum = locked.get("checksum")
        if source is not None and (
            not isinstance(checksum, str) or SHA256.fullmatch(checksum) is None
        ):
            fail(f"third-party package lacks a SHA-256 checksum: {key}")
        packages.append(
            {
                "name": locked["name"],
                "version": locked["version"],
                "source": source or "path:repository",
                "checksum": checksum,
                "license": license_expression,
                "direct": key in direct_keys,
            }
        )
    packages.sort(key=lambda item: (item["name"], item["version"], item["source"]))
    if len(packages) != len(cargo_packages):
        fail("Cargo.lock and resolved metadata package counts differ")

    return {
        "schema_version": "telosieve.dependency-inventory/v1",
        "lockfile_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "package_count": len(packages),
        "third_party_package_count": sum(
            package["source"] != "path:repository" for package in packages
        ),
        "packages": packages,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", type=Path)
    arguments = parser.parse_args()
    try:
        rendered = json.dumps(generate(), indent=2, sort_keys=False) + "\n"
        if arguments.check is None:
            sys.stdout.write(rendered)
        elif arguments.check.read_text(encoding="utf-8") != rendered:
            fail(f"dependency inventory drift: regenerate {arguments.check}")
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
        tomllib.TOMLDecodeError,
    ) as error:
        print(f"dependency-inventory: {error}", file=sys.stderr)
        return 1
    if arguments.check is not None:
        print("dependency-inventory: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
