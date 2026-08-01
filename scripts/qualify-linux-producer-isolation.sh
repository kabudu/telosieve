#!/bin/sh
set -eu

image="rust:1.97-bookworm"
expected_digest="sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa"
repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "linux-producer-isolation: cached image required: $image" >&2
    exit 1
fi
actual_digest="$(docker image inspect "$image" --format '{{index .RepoDigests 0}}')"
actual_digest="${actual_digest#*@}"
if [ "$actual_digest" != "$expected_digest" ]; then
    echo "linux-producer-isolation: image digest mismatch: $actual_digest" >&2
    exit 1
fi

case "$(docker info --format '{{.Architecture}}')" in
    arm64 | aarch64) platform="linux/arm64" ;;
    amd64 | x86_64) platform="linux/amd64" ;;
    *) echo "linux-producer-isolation: unsupported Docker architecture" >&2; exit 1 ;;
esac

docker run --rm \
    --platform "$platform" \
    --network none \
    --read-only \
    --pids-limit 64 \
    --memory 256m \
    --tmpfs /qualification:rw,exec,nosuid,nodev,size=32m,mode=0711 \
    --tmpfs /tmp:rw,nosuid,nodev,size=8m,mode=1777 \
    --mount type=bind,source="$repository",destination=/workspace,readonly \
    -e TELOSIEVE_CONTAINER_IMAGE="$image@$expected_digest" \
    -w /workspace \
    "$image" \
    python3 scripts/run-linux-producer-isolation.py
