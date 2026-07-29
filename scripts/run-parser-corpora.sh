#!/bin/sh
set -eu

repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repository"

run_corpus() {
    corpus="$1"
    test_filter="$2"
    echo "parser-corpus: $corpus" >&2
    cargo test --locked --offline --test parser_corpora "$test_filter" -- --exact >&2
    printf '    {"corpus":"%s","command":"cargo test --locked --offline --test parser_corpora %s -- --exact","status":"passed"}' \
        "$corpus" "$test_filter"
}

printf '{\n  "schema_version":"telosieve.parser-corpora/v1",\n'
printf '  "generator":"deterministic-truncation-and-type-mutation",\n'
printf '  "bounds":{"maximum_cases_per_corpus":16,"maximum_total_bytes_per_corpus":2097152},\n'
printf '  "corpora":[\n'
run_corpus "authority" "authority_parser_corpus_is_bounded_and_fail_closed"
printf ',\n'
run_corpus "lifecycle" "lifecycle_parser_corpus_is_bounded_and_fail_closed"
printf ',\n'
run_corpus "kubernetes-shadow" "shadow_parser_corpus_is_bounded_and_structurally_bounded"
printf ',\n'
run_corpus "recovery" "recovery_parser_corpus_is_bounded_and_fail_closed"
printf '\n  ],\n  "retained_regressions":4,\n  "discrepancies_discovered":0,\n  "passed":4,\n  "failed":0\n}\n'
echo "parser-corpus: passed 4/4" >&2
