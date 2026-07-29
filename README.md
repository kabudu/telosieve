# Telosieve

**Question the instruction before enforcing it.**

Telosieve is a research project for fail-closed service repair when the desired-state
authority itself may be stale, compromised, or malicious. It separates three
authorities—goal, observed phenotype, and viability constraints—then evaluates
explicit fault hypotheses before permitting a repair.

The first experiment is deliberately narrow: a deterministic replicated key-value
service under a bounded fault model. This repository contains the research and
delivery corpus, not a claim of a finished product.

## Candidate contribution

A provenance-separated repair protocol that can suspect the goal authority,
exclude suspected evidence from planning, require independently checked viability,
and refuse repair when surviving evidence cannot distinguish safe outcomes.

## Status

M3 is complete with an explicit decision to **narrow** the project. Telosieve
remains private research. A post-M3 multi-principal experiment removes the
registered weakened-viability unsafe approval under a one-principal fault bound,
but productisation and public release remain blocked pending broader adversarial
and independent validation. The harness authenticates a bounded scenario,
evaluates its declared hypotheses, applies only one common independently checked
transition, and otherwise emits a refusal certificate. See
[VALIDATION](docs/VALIDATION.md) for the falsification plan, [NOVELTY](docs/NOVELTY.md)
for claim limits, and [IMPLEMENTATION_PLAN](docs/IMPLEMENTATION_PLAN.md) for scope.

## Run the registered scenarios

Requires stable Rust 1.97 or newer.

```sh
cargo test
mkdir -p out
cargo run -- run scenarios/benign.json out/benign-certificate.json out/ledger.jsonl
cargo run -- run scenarios/poisoned-goal.json out/refusal-certificate.json out/ledger.jsonl
```

For the complete private-repository quality gate, run:

```sh
./scripts/ci-local.sh
```

Hosted CI is intentionally disabled until an explicitly approved public-opening
or research-release gate.

M2 results and negative findings are reported in
[M2 Adversarial Results](docs/M2_RESULTS.md).
The evidence-to-product comparison is recorded in
[Productisation Assessment](docs/PRODUCTISATION_ASSESSMENT.md).
The binding M3 outcome and its reopening conditions are recorded in
[Productisation Decision](docs/PRODUCTISATION_DECISION.md).

Each run authenticates all authority envelopes before evaluation. The certificate
is deterministic for identical inputs; the JSONL ledger is append-only. The
fixture generator uses deterministic research-only signing keys:

```sh
cargo run --example generate_fixtures
```

## Repository policy

This is a private repository with `origin` configured for `kabudu/telosieve`. The
default branch is `master`.
