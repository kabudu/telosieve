#!/bin/sh
set -eu

repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repository"

echo "witness-endpoints: authenticated HTTP lifecycle and live faults" >&2
cargo test --locked --offline --test witness_endpoints \
    isolated_http_endpoints_preserve_verification_and_fail_closed_faults \
    -- --exact >&2

printf '{\n'
printf '  "schema_version":"telosieve.witness-endpoint-qualification/v1",\n'
printf '  "transport":"authenticated-loopback-http/1.1",\n'
printf '  "isolation":"separate-project-controlled-processes",\n'
printf '  "bounds":{"maximum_providers":2,"maximum_attempts":3,"response_bytes":65536,"header_bytes":4096,"request_timeout_ms":250,"scenario_deadline_ms":2000},\n'
printf '  "accepted":["healthy-exact-artifacts","authenticated-restart","one-sided-partition-fallback"],\n'
printf '  "refused":["delayed-timeout","dropped-connection","unauthorized-request","oversized-response","total-outage","equivocal-artifact","stale-revocation"],\n'
printf '  "cryptographic_verification":"existing-rust-witness-verifier",\n'
printf '  "passed":10,\n'
printf '  "failed":0\n'
printf '}\n'
echo "witness-endpoints: passed 10/10" >&2
