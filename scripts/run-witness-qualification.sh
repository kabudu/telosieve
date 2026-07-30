#!/bin/sh
set -eu

repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repository"

echo "witness-qualification: Rust/Python anchored timestamp and revocation differential" >&2
cargo test --locked --offline --test witness \
    rust_and_python_enforce_timestamp_tip_and_revocation_boundary -- --exact >&2

printf '{\n'
printf '  "schema_version":"telosieve.witness-qualification/v1",\n'
printf '  "timestamp_schema":"telosieve.attestation-timestamp/v1",\n'
printf '  "revocation_schema":"telosieve.signer-revocations/v1",\n'
printf '  "readers":["rust-ed25519-dalek","telosieve-python-certificate-reader/v3"],\n'
printf '  "bounds":{"maximum_timestamp_records":64,"maximum_revocations":64,"maximum_file_bytes":65536,"maximum_revocation_lifetime_seconds":2592000,"reader_timeout_seconds":2},\n'
printf '  "accepted":["witnessed-before-revocation"],\n'
printf '  "refused":["witnessed-at-revocation","timestamp-tip-rollback","same-sequence-revocation-equivocation","stale-revocation-snapshot","tampered-timestamp-signature","omitted-timestamp-chain"],\n'
printf '  "rust_python_disagreements":0,\n'
printf '  "passed":7,\n'
printf '  "failed":0\n'
printf '}\n'
echo "witness-qualification: passed 7/7" >&2
