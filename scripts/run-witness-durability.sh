#!/bin/sh
set -eu

repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repository"

echo "witness-durability: transactional store lifecycle" >&2
cargo test --locked --offline --lib witness_tip_store::tests >&2
echo "witness-durability: bounded availability matrix" >&2
cargo test --locked --offline --lib \
    witness_availability::tests::matrix_preserves_bounded_availability_and_fail_closed_outages \
    -- --exact >&2
cargo run --quiet --locked --offline --example witness_availability
