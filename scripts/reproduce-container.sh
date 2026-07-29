#!/bin/sh
set -eu

image="rust:1.97-bookworm"
expected_image_id="sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa"
repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
host_registry="${CARGO_HOME:-${HOME}/.cargo}/registry"

if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "reproduction: cached image required: $image" >&2
    exit 1
fi
actual_image_id="$(docker image inspect "$image" --format '{{.Id}}')"
if [ "$actual_image_id" != "$expected_image_id" ]; then
    echo "reproduction: image ID mismatch: $actual_image_id" >&2
    exit 1
fi
if [ ! -d "$host_registry" ]; then
    echo "reproduction: Cargo registry cache not found: $host_registry" >&2
    exit 1
fi

docker run --rm \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,exec,size=2g \
    --tmpfs /workspace/target:rw,exec,size=1g \
    -e CARGO_HOME=/tmp/cargo \
    -e CARGO_TARGET_DIR=/tmp/target \
    -v "$repository:/workspace:ro" \
    -v "$host_registry:/host-registry:ro" \
    -w /workspace \
    "$image" \
    sh -c '
        mkdir -p /tmp/cargo
        cp -R /host-registry /tmp/cargo/registry
        rustc --version
        cargo --version
        python3 --version
        cargo test --locked --offline --all-targets --all-features
        RUSTDOCFLAGS=-Dwarnings cargo doc --locked --offline --no-deps
        cargo metadata --locked --offline --no-deps --format-version 1 >/tmp/metadata.json
        python3 scripts/validate-project.py
        cargo run --release --locked --offline --example benchmark -- scenarios/*.json
    '
