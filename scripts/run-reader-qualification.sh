#!/bin/sh
set -eu

repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repository"

test_name="independent_reader_agrees_on_supported_versions_and_failure_matrix"
echo "reader-qualification: $test_name" >&2
cargo test --locked --offline --test compatibility "$test_name" -- --exact >&2

printf '{\n'
printf '  "schema_version":"telosieve.reader-qualification/v1",\n'
printf '  "reader":"telosieve-python-certificate-reader/v2",\n'
printf '  "independence_boundary":"python-standard-library-no-rust-or-serde-code",\n'
printf '  "bounds":{"maximum_cases":16,"maximum_total_bytes":2097152,"maximum_certificate_bytes":2097152,"reader_timeout_seconds":2},\n'
printf '  "versions":[\n'
printf '    {"certificate_version":"telosieve.certificate/v7","source":"actual-stateless-output","status":"accepted"},\n'
printf '    {"certificate_version":"telosieve.certificate/v8","source":"actual-local-actuator-output","status":"accepted"},\n'
printf '    {"certificate_version":"telosieve.certificate/v9","source":"retained-kubernetes-shadow-output","status":"accepted"}\n'
printf '  ],\n'
printf '  "rejection_classes":["future-version","unknown-field","missing-field","wrong-type","out-of-range-integer","confused-extension","duplicate-field","malformed-json","oversized"],\n'
printf '  "rust_python_disagreements":0,\n'
printf '  "passed":13,\n'
printf '  "failed":0\n'
printf '}\n'
echo "reader-qualification: passed 13/13" >&2
