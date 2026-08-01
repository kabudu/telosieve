#!/bin/sh
set -eu

repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repository"

run_vector() {
    vector="$1"
    test_filter="$2"
    echo "compatibility-corpus: $vector" >&2
    cargo test --locked --offline --test compatibility "$test_filter" -- --exact >&2
    printf '    {"vector":"%s","command":"cargo test --locked --offline --test compatibility %s -- --exact","status":"passed"}' \
        "$vector" "$test_filter"
}

printf '{\n'
printf '  "schema_version":"telosieve.compatibility-corpus/v1",\n'
printf '  "migration_policy":"validate-then-regenerate-no-automatic-rewrite",\n'
printf '  "bounds":{"maximum_cases":16,"maximum_total_bytes":2097152,"maximum_certificate_bytes":2097152},\n'
printf '  "supported_certificate_versions":["telosieve.certificate/v7","telosieve.certificate/v8","telosieve.certificate/v9","telosieve.certificate/v10","telosieve.certificate/v11"],\n'
printf '  "vectors":[\n'
run_vector "scenario-old-new-and-migration" "scenario_migration_vectors_preserve_legacy_and_fail_closed"
printf ',\n'
run_vector "certificate-v7-v8-v9-v10-v11-and-future" "certificate_vectors_accept_v7_to_v11_and_reject_future_or_confused_shapes"
printf '\n  ],\n'
printf '  "passed":2,\n'
printf '  "failed":0\n'
printf '}\n'
echo "compatibility-corpus: passed 2/2" >&2
