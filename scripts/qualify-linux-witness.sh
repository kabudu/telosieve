#!/bin/sh
set -eu

image="rust:1.97-bookworm"
expected_digest="sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa"
repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
host_registry="${CARGO_HOME:-${HOME}/.cargo}/registry"
platform="${1:-}"
transfer_directory="$(mktemp -d)"
trap 'rm -rf "$transfer_directory"' EXIT

case "$platform" in
    linux/arm64) architecture="aarch64" ;;
    linux/amd64) architecture="x86_64" ;;
    *) echo "usage: $0 linux/arm64|linux/amd64" >&2; exit 2 ;;
esac

actual_digest="$(docker image inspect "$image" --format '{{index .RepoDigests 0}}')"
actual_digest="${actual_digest#*@}"
if [ "$actual_digest" != "$expected_digest" ]; then
    echo "linux-witness: image digest mismatch: $actual_digest" >&2
    exit 1
fi
if [ ! -d "$host_registry" ]; then
    echo "linux-witness: Cargo registry cache missing" >&2
    exit 1
fi

echo "linux-witness: qualifying $platform offline" >&2
cargo run --quiet --locked --offline --example witness_tip_transfer -- \
    create "$transfer_directory/tips.json"
docker run --rm \
    --platform "$platform" \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,exec,size=4g \
    --mount type=volume,destination=/qualification \
    --mount type=bind,source="$transfer_directory",destination=/transfer,readonly \
    -e CARGO_HOME=/tmp/cargo \
    -e CARGO_TARGET_DIR=/tmp/target \
    -e TMPDIR=/qualification \
    -e EXPECTED_ARCHITECTURE="$architecture" \
    -v "$repository:/workspace:ro" \
    -v "$host_registry:/host-registry:ro" \
    -w /workspace \
    "$image" sh -c '
        set -eu
        test "$(uname -m)" = "$EXPECTED_ARCHITECTURE"
        mkdir -p /tmp/cargo
        cp -R /host-registry /tmp/cargo/registry
        cargo run --quiet --locked --offline --example witness_tip_transfer -- \
            verify /transfer/tips.json
        cargo test --locked --offline --lib witness_tip_store::tests >&2
    '

printf '{\n'
printf '  "schema_version":"telosieve.witness-durability-linux/v1",\n'
printf '  "platform":"%s",\n' "$platform"
printf '  "architecture":"%s",\n' "$architecture"
printf '  "container_image":"%s@%s",\n' "$image" "$expected_digest"
printf '  "network":"none",\n'
printf '  "filesystem":"docker-managed-volume",\n'
printf '  "cases":["host-to-linux-read-only-transfer","interrupted-previous","interrupted-next","stale-backup","exact-latest-restore","independent-path-copy","rollback-equivocation-refusal","missing-witness-refusal","oversized-state-refusal"],\n'
printf '  "passed":9,\n'
printf '  "failed":0\n'
printf '}\n'
echo "linux-witness: passed $platform" >&2
