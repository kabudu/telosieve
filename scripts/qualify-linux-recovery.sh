#!/bin/sh
set -eu

image="rust:1.97-bookworm"
expected_digest="sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa"
repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
host_registry="${CARGO_HOME:-${HOME}/.cargo}/registry"
platform="${1:-}"

case "$platform" in
    linux/arm64)
        expected_architecture="aarch64"
        docker_architecture="arm64"
        ;;
    linux/amd64)
        expected_architecture="x86_64"
        docker_architecture="amd64"
        ;;
    *)
        echo "usage: $0 linux/arm64|linux/amd64" >&2
        exit 2
        ;;
esac

if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "linux-recovery: cached image required: $image" >&2
    exit 1
fi
actual_digest="$(docker image inspect "$image" --format '{{index .RepoDigests 0}}')"
actual_digest="${actual_digest#*@}"
if [ "$actual_digest" != "$expected_digest" ]; then
    echo "linux-recovery: image digest mismatch: $actual_digest" >&2
    exit 1
fi
if [ ! -d "$host_registry" ]; then
    echo "linux-recovery: Cargo registry cache not found: $host_registry" >&2
    exit 1
fi
case "$(docker info --format '{{.Architecture}}')" in
    arm64 | aarch64) daemon_architecture="arm64" ;;
    amd64 | x86_64) daemon_architecture="amd64" ;;
    *) daemon_architecture="unknown" ;;
esac
if [ "$daemon_architecture" = "$docker_architecture" ]; then
    execution_environment="docker-linux-vm-native-$docker_architecture"
else
    execution_environment="docker-linux-vm-emulated-$docker_architecture"
fi

echo "linux-recovery: qualifying $platform with $image@$expected_digest" >&2
docker run --rm \
    --platform "$platform" \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,exec,size=4g \
    --mount type=volume,destination=/qualification \
    --mount type=volume,destination=/workspace/target \
    -e CARGO_HOME=/tmp/cargo \
    -e CARGO_TARGET_DIR=/tmp/target \
    -e TMPDIR=/qualification \
    -e TELOSIEVE_CONTAINER_IMAGE="$image@$expected_digest" \
    -e TELOSIEVE_EXECUTION_ENVIRONMENT="$execution_environment" \
    -e TELOSIEVE_EXPECTED_ARCHITECTURE="$expected_architecture" \
    -v "$repository:/workspace:ro" \
    -v "$host_registry:/host-registry:ro" \
    -w /workspace \
    "$image" \
    sh -c '
        set -eu
        mkdir -p /tmp/cargo
        cp -R /host-registry /tmp/cargo/registry
        observed_architecture="$(uname -m)"
        if [ "$observed_architecture" != "$TELOSIEVE_EXPECTED_ARCHITECTURE" ]; then
            echo "linux-recovery: architecture mismatch: $observed_architecture" >&2
            exit 1
        fi
        echo "linux-recovery: $(rustc --version)" >&2
        echo "linux-recovery: $(cargo --version)" >&2
        echo "linux-recovery: kernel $(uname -srmo)" >&2
        qualification_filesystem="$(stat -f -c %T /qualification)"
        export TELOSIEVE_QUALIFICATION_FILESYSTEM="$qualification_filesystem"
        echo "linux-recovery: qualification filesystem $qualification_filesystem" >&2
        cargo test --locked --offline --lib actuator_store::tests >&2
        cargo test --locked --offline --test m0 \
            forced_termination_stress_never_exposes_torn_actuator_state >&2
        cargo run --quiet --release --locked --offline \
            --example recovery_benchmark -- scenarios/benign.json
    '
echo "linux-recovery: passed $platform" >&2
