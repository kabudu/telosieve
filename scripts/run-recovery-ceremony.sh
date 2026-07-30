#!/bin/sh
set -eu

repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repository"

run_case() {
    case_id="$1"
    test_filter="$2"
    echo "recovery-ceremony: $case_id" >&2
    cargo test --locked --offline "recovery_ceremony::tests::$test_filter" -- --exact >&2
    printf '    {"case":"%s","command":"cargo test --locked --offline recovery_ceremony::tests::%s -- --exact","status":"passed"}' \
        "$case_id" "$test_filter"
}

printf '{\n'
printf '  "schema_version":"telosieve.recovery-ceremony-result/v1",\n'
printf '  "execution_mode":"credential-free-deterministic-local",\n'
printf '  "participants":3,\n'
printf '  "quorum":2,\n'
printf '  "maximum_participants":7,\n'
printf '  "maximum_duration_seconds":3600,\n'
printf '  "cases":[\n'
run_case "quorum-and-exclusion" "quorum_ceremony_emits_bound_approval_and_survives_exclusion"
printf ',\n'
run_case "abort-matrix" "duplicate_missing_divergent_stale_veto_and_compromised_votes_abort"
printf '\n  ],\n'
printf '  "abort_classes":["duplicate","missing","divergent","stale","veto","excluded-compromised"],\n'
printf '  "passed":2,\n'
printf '  "failed":0\n'
printf '}\n'
echo "recovery-ceremony: passed 2/2" >&2
