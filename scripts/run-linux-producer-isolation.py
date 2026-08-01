#!/usr/bin/env python3
"""Qualify observation relays under distinct Linux kernel identities."""

import json
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/workspace")
WORK = Path("/qualification/producer-identities")
RELAY = ROOT / "scripts/observation-source-relay.py"
CLIENT = ROOT / "scripts/observation-source-client.py"
PRODUCERS = ((2001, 2101, "a"), (2002, 2102, "b"))
EVALUATOR = (2003, 2103, [2101, 2102])
OUTSIDER = (2004, 2104, [])
EXPECTED_PREFIX = b'{"schema_version":"telosieve.observation-source/v1"'
DEADLINE_SECONDS = 8


def identity(uid: int, gid: int, groups: list[int]):
    def apply() -> None:
        os.setgroups(groups)
        os.setgid(gid)
        os.setuid(uid)
    return apply


def write(path: Path, data: bytes, mode: int, uid: int, gid: int) -> None:
    path.write_bytes(data)
    os.chown(path, uid, gid)
    path.chmod(mode)


def run_as(command: list[str], uid: int, gid: int, groups: list[int]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True,
        check=False, timeout=DEADLINE_SECONDS, preexec_fn=identity(uid, gid, groups),
    )


def wait_ready(process: subprocess.Popen[bytes], socket_path: Path) -> None:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _, error = process.communicate()
            raise SystemExit(f"linux-producer-isolation: relay exited: {error.decode(errors='replace')}")
        if socket_path.exists():
            return
        time.sleep(0.01)
    raise SystemExit("linux-producer-isolation: relay readiness timeout")


def process_identity(pid: int, expected_uid: int, expected_gid: int) -> None:
    status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
    gid_line = next(line for line in status.splitlines() if line.startswith("Gid:"))
    if [int(value) for value in uid_line.split()[1:]] != [expected_uid] * 4:
        raise SystemExit("linux-producer-isolation: relay UID mismatch")
    if [int(value) for value in gid_line.split()[1:]] != [expected_gid] * 4:
        raise SystemExit("linux-producer-isolation: relay GID mismatch")


def main() -> int:
    if os.geteuid() != 0 or sys.platform != "linux":
        raise SystemExit("linux-producer-isolation: Linux root namespace required")
    WORK.mkdir(parents=True, mode=0o711, exist_ok=False)
    relays: list[subprocess.Popen[bytes]] = []
    paths: dict[str, tuple[Path, Path, Path]] = {}
    refused = 0
    accepted = 0
    try:
        for uid, gid, name in PRODUCERS:
            directory = WORK / name
            directory.mkdir(mode=0o750)
            os.chown(directory, uid, gid)
            token = directory / "relay.token"
            write(token, name.encode() * 32, 0o440, uid, gid)
            producer = directory / "producer"
            payload = (
                "#!/bin/sh\nprintf '%s\\n' "
                f"'{{\"schema_version\":\"telosieve.observation-source/v1\",\"producer\":\"{name}\"}}'\n"
            ).encode()
            write(producer, payload, 0o500, uid, gid)
            socket_path = directory / "relay.sock"
            configuration = directory / "relay.json"
            document = json.dumps({
                "schema_version": "telosieve.observation-relay/v1",
                "socket_path": str(socket_path),
                "token_path": str(token),
                "producer": {"executable_path": str(producer), "arguments": []},
            }, separators=(",", ":")).encode()
            write(configuration, document, 0o400, uid, gid)
            process = subprocess.Popen(
                [str(RELAY), "--config", str(configuration)], cwd=ROOT,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                preexec_fn=identity(uid, gid, []),
            )
            relays.append(process)
            wait_ready(process, socket_path)
            process_identity(process.pid, uid, gid)
            metadata = socket_path.stat()
            if stat.S_IMODE(metadata.st_mode) != 0o660 or metadata.st_uid != uid or metadata.st_gid != gid:
                raise SystemExit("linux-producer-isolation: socket ownership or mode mismatch")
            paths[name] = (socket_path, token, configuration)

        evaluator_uid, evaluator_gid, evaluator_groups = EVALUATOR
        for name in ("a", "b"):
            socket_path, token, _ = paths[name]
            result = run_as(
                [str(CLIENT), "--socket", str(socket_path), "--token", str(token)],
                evaluator_uid, evaluator_gid, evaluator_groups,
            )
            if result.returncode or not result.stdout.startswith(EXPECTED_PREFIX) or f'"producer":"{name}"'.encode() not in result.stdout:
                raise SystemExit(
                    "linux-producer-isolation: authorized evaluator failed "
                    f"producer={name} rc={result.returncode} "
                    f"stdout={result.stdout.decode(errors='replace')!r} "
                    f"stderr={result.stderr.decode(errors='replace')!r}"
                )
            accepted += 1

        wrong = WORK / "wrong.token"
        write(wrong, b"x" * 32, 0o400, evaluator_uid, evaluator_gid)
        result = run_as(
            [str(CLIENT), "--socket", str(paths["a"][0]), "--token", str(wrong)],
            evaluator_uid, evaluator_gid, evaluator_groups,
        )
        if result.returncode == 0:
            raise SystemExit("linux-producer-isolation: wrong token accepted")
        refused += 1

        outsider_uid, outsider_gid, outsider_groups = OUTSIDER
        result = run_as(
            [str(CLIENT), "--socket", str(paths["a"][0]), "--token", str(paths["a"][1])],
            outsider_uid, outsider_gid, outsider_groups,
        )
        if result.returncode == 0:
            raise SystemExit("linux-producer-isolation: unrelated identity accepted")
        refused += 1

        for source, target in (("a", "b"), ("b", "a")):
            source_uid, source_gid, _ = next(item for item in PRODUCERS if item[2] == source)
            for protected in paths[target][1:]:
                result = run_as(
                    [sys.executable, "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).read_bytes()", str(protected)],
                    source_uid, source_gid, [],
                )
                if result.returncode == 0:
                    raise SystemExit("linux-producer-isolation: producer crossed identity boundary")
                refused += 1
            result = run_as(
                [str(CLIENT), "--socket", str(paths[target][0]), "--token", str(paths[source][1])],
                source_uid, source_gid, [],
            )
            if result.returncode == 0:
                raise SystemExit("linux-producer-isolation: producer reached peer relay")
            refused += 1
    finally:
        for process in relays:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        for socket_path, _, _ in paths.values():
            if socket_path.exists():
                raise SystemExit("linux-producer-isolation: relay socket not cleaned up")

    print(json.dumps({
        "schema_version": "telosieve.linux-producer-isolation/v1",
        "container_image": os.environ["TELOSIEVE_CONTAINER_IMAGE"],
        "kernel": os.uname().release,
        "architecture": os.uname().machine,
        "producer_uids": [item[0] for item in PRODUCERS],
        "producer_client_gids": [item[1] for item in PRODUCERS],
        "evaluator_uid": EVALUATOR[0],
        "accepted": accepted,
        "refused": refused,
        "socket_mode": "0660",
        "network": "none",
        "limits": {
            "memory_bytes": 256 * 1024 * 1024,
            "pids": 64,
            "qualification_tmpfs_bytes": 32 * 1024 * 1024,
            "private_tmpfs_bytes": 8 * 1024 * 1024,
            "repository_read_only": True,
        },
        "separate_os_identities_exercised": True,
        "separate_hosts_exercised": False,
        "independent_evidence": False,
        "status": "passed",
    }, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
