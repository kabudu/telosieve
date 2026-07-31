#!/usr/bin/env python3
"""Qualify same-host locked/offline release-build reproducibility."""
import hashlib
import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAX_SECONDS = 120
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_WORK_BYTES = 1024 * 1024 * 1024
MAX_PEAK_RSS_BYTES = 1024 * 1024 * 1024


def run(*arguments: str, timeout: int = 10) -> str:
    result = subprocess.run(
        arguments, cwd=ROOT, check=True, capture_output=True, text=True,
        timeout=timeout,
    )
    return result.stdout.strip()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_size(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def main() -> int:
    commit = run("git", "rev-parse", "HEAD")
    clean = not run("git", "status", "--porcelain")
    rustc = run("rustc", "-vV")
    cargo = run("cargo", "--version")
    host = next(line.split(": ", 1)[1] for line in rustc.splitlines() if line.startswith("host: "))
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="telosieve-repro-build-") as temporary:
        work = Path(temporary)
        binaries = []
        environment = os.environ.copy()
        environment["CARGO_INCREMENTAL"] = "0"
        for name in ("first", "second"):
            target = work / name
            subprocess.run(
                ["cargo", "build", "--release", "--locked", "--offline", "--target-dir", str(target)],
                cwd=ROOT, env=environment, check=True, capture_output=True,
                timeout=MAX_SECONDS,
            )
            binary = target / "release" / "telosieve"
            if not binary.is_file() or binary.stat().st_size > MAX_BINARY_BYTES:
                raise SystemExit("reproducible-build: binary missing or oversized")
            binaries.append(binary)
        first_digest, second_digest = map(digest, binaries)
        if first_digest != second_digest or binaries[0].read_bytes() != binaries[1].read_bytes():
            raise SystemExit("reproducible-build: isolated release binaries differ")
        altered = work / "altered"
        shutil.copyfile(binaries[0], altered)
        altered_bytes = bytearray(altered.read_bytes())
        altered_bytes[-1] ^= 1
        altered.write_bytes(altered_bytes)
        if digest(altered) == first_digest:
            raise SystemExit("reproducible-build: altered binary was not detected")
        work_bytes = tree_size(work)
        if work_bytes > MAX_WORK_BYTES:
            raise SystemExit("reproducible-build: work output exceeds bound")
        binary_bytes = binaries[0].stat().st_size
    elapsed = round(time.monotonic() - started, 3)
    if elapsed > MAX_SECONDS * 2:
        raise SystemExit("reproducible-build: elapsed time exceeds bound")
    peak_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    peak_rss_bytes = peak_rss if sys.platform == "darwin" else peak_rss * 1024
    if peak_rss_bytes > MAX_PEAK_RSS_BYTES:
        raise SystemExit("reproducible-build: peak child RSS exceeds bound")
    print(json.dumps({
        "schema_version": "telosieve.reproducible-build-qualification/v1",
        "source_commit": commit,
        "working_tree_clean": clean,
        "binary_sha256": first_digest,
        "binary_bytes": binary_bytes,
        "target": host,
        "rustc": rustc.splitlines()[0],
        "cargo": cargo,
        "elapsed_seconds": elapsed,
        "peak_child_rss_bytes": peak_rss_bytes,
        "work_bytes": work_bytes,
        "isolated_builds": 2,
        "alteration_refused": True,
        "status": "passed",
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
