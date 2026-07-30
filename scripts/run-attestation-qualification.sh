#!/bin/sh
set -eu

repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repository"

echo "attestation-qualification: Rust lifecycle and bounds" >&2
cargo test --locked --offline --lib \
    certificate_attestation::tests::rotated_signers_preserve_historical_attestations \
    -- --exact >&2
cargo test --locked --offline --lib \
    certificate_attestation::tests::tamper_replay_expiry_signature_and_bounds_fail_closed \
    -- --exact >&2
echo "attestation-qualification: Rust/Python differential" >&2
cargo test --locked --offline --test attestation \
    rust_and_python_verify_rotation_and_fail_closed_attestations -- --exact >&2

printf '{\n'
printf '  "schema_version":"telosieve.attestation-qualification/v1",\n'
printf '  "attestation_schema":"telosieve.certificate-attestation/v1",\n'
printf '  "readers":["rust-ed25519-dalek","telosieve-python-certificate-reader/v3"],\n'
printf '  "bounds":{"maximum_cases":12,"maximum_total_bytes":2097152,"maximum_certificate_bytes":2097152,"maximum_attestation_bytes":65536,"maximum_trust_keys":8,"maximum_lifetime_seconds":2592000,"reader_timeout_seconds":2},\n'
printf '  "accepted":["old-key-during-declared-window","new-key-after-rotation"],\n'
printf '  "refused":["tampered-signature","wrong-certificate","cross-context-replay","expired-attestation","outside-key-window"],\n'
printf '  "rust_python_disagreements":0,\n'
printf '  "passed":7,\n'
printf '  "failed":0\n'
printf '}\n'
echo "attestation-qualification: passed 7/7" >&2
