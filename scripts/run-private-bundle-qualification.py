#!/usr/bin/env python3
"""Qualify resource shape, interruption safety, and bundle reproducibility."""
import hashlib, json, os, resource, subprocess, tempfile, time, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARY = (ROOT / "target/debug/telosieve").resolve()
BUILDER = ROOT / "scripts/build-private-bundle.py"
SOURCE_COMMIT = "a" * 40

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    with tempfile.TemporaryDirectory(prefix="telosieve-bundle-") as tmp:
        work = Path(tmp); first = work / "one.zip"; second = work / "two.zip"; interrupted = work / "interrupted.zip"; other = work / "other.zip"
        command = ["python3", str(BUILDER), "--binary", str(BINARY), "--source-commit", SOURCE_COMMIT, "--output"]
        started = time.monotonic()
        subprocess.run([*command, str(first)], check=True, capture_output=True, timeout=15)
        wall_ms = round((time.monotonic() - started) * 1000, 3)
        subprocess.run([*command, str(second)], check=True, capture_output=True, timeout=15)
        assert first.read_bytes() == second.read_bytes()
        process = subprocess.Popen([*command, str(interrupted)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process.kill(); process.wait(timeout=5)
        assert not interrupted.exists()
        subprocess.run([*command, str(interrupted)], check=True, capture_output=True, timeout=15)
        assert sha(interrupted) == sha(first)
        subprocess.run(["python3", str(BUILDER), "--binary", str(BINARY), "--source-commit", "b" * 40, "--output", str(other)], check=True, capture_output=True, timeout=15)
        assert sha(other) != sha(first)
        malformed = subprocess.run(["python3", str(BUILDER), "--binary", str(BINARY), "--source-commit", "HEAD", "--output", str(work / "invalid.zip")], capture_output=True, timeout=15)
        assert malformed.returncode != 0 and not (work / "invalid.zip").exists()
        with zipfile.ZipFile(first) as archive:
            manifest = json.loads(archive.read("bundle-manifest.json"))
            assert manifest["schema_version"] == "telosieve.private-bundle/v2"
            assert manifest["source_commit"] == SOURCE_COMMIT
            for record in manifest["entries"]:
                data = archive.read(record["path"])
                assert len(data) == record["size"] and hashlib.sha256(data).hexdigest() == record["sha256"]
        peak_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        assert first.stat().st_size <= 160 * 1024 * 1024 and wall_ms < 15_000
        bundle_digest = sha(first)
    print(json.dumps({"schema_version":"telosieve.private-bundle-qualification/v2","platform":os.uname().sysname,"bundle_sha256":bundle_digest,"wall_ms":wall_ms,"peak_child_rss":peak_rss,"reproducible":True,"interruption_recovered":True,"source_commit_bound":True,"status":"passed"}, separators=(",", ":")))
    return 0
if __name__ == "__main__": raise SystemExit(main())
