# Bounded Parser Corpora

Date: 2026-07-29

`./scripts/run-parser-corpora.sh` executes deterministic corpora for authority
envelopes, key-lifecycle statements, Kubernetes shadow snapshots, and local
actuator recovery state. The runner uses locked offline dependencies and emits
`telosieve.parser-corpora/v1` JSON only after all four corpora pass.

Each corpus starts with a valid round trip and applies bounded truncation,
field-type confusion, and missing or unknown fields. Across the relevant
corpora, mutations also cover malformed enums and structural resource bounds. A
corpus contains at most 16 cases and at most 2 MiB of input. There is no random
seed, network access, unbounded generation, or production credential.

Four minimized rejection fixtures are retained under `tests/regressions/`:
negative authority time, an unknown lifecycle action field, a string-valued
shadow generation, and a string-valued recovery generation. The current run
found no parser discrepancy. Any future input that violates a corpus oracle must
be minimized, added to that directory, and counted before the discrepancy is
fixed.

This is deterministic mutation/property coverage, not coverage-guided native
fuzzing, memory-sanitizer evidence, a proof over arbitrary JSON, or independent
parser assessment. Rust's `unsafe_code = "forbid"` applies to Telosieve itself,
but dependency memory safety remains outside this corpus evidence.
