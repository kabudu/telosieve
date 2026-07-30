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

The original M3 decision narrowed Telosieve to private research. After the
registered unsafe approval was removed and the bounded evidence base expanded,
the project authorized a private, production-shaped evaluation product on
2026-07-30. Evaluation engineering is active; no evaluation candidate has yet
met its readiness gates. Public release, autonomous production actuation, and
general safety claims remain blocked pending their separate explicit decisions;
production promotion additionally requires independent validation of the exact
candidate. Certificate v4's
stable-key continuity kernel removes every unsafe approval reproduced by the
registered fixtures and 512-scenario generated state space without changing
their oracles. Certificate v5's two agreeing declared goal domains also remove
the 64 measured safe-case refusals. Domain labels do not prove organizational
independence. Certificate v6 permits only separately authorized, goal/tip-bound
exact key deletion; certificate v7 atomically consumes an applied authorization
once in the single-host anchored path. Certificate v8 adds a transactional local
reference actuator with committed-state receipts. Ordinary omission still
refuses. The bounded result is not a general safety proof. The harness
authenticates a bounded scenario,
evaluates its declared hypotheses, applies only one common independently checked
transition, and otherwise emits a refusal certificate. See
[VALIDATION](docs/VALIDATION.md) for the falsification plan, [NOVELTY](docs/NOVELTY.md)
for claim limits, and [IMPLEMENTATION_PLAN](docs/IMPLEMENTATION_PLAN.md) for scope.

Opt-in recovery-root-signed authority lifecycle chains now rotate, expire, and
revoke operational keys without invalidating historical phenotype signatures.
This is a bounded research protocol, not a production identity service. See
[Authority Key Lifecycle](docs/KEY_LIFECYCLE.md).

## Run the registered scenarios

Requires stable Rust 1.97 or newer.

```sh
cargo test
mkdir -p out
cargo run -- run scenarios/benign.json out/benign-certificate.json out/ledger.jsonl
cargo run -- run scenarios/poisoned-goal.json out/refusal-certificate.json out/ledger.jsonl
```

For durable history rollback detection, explicitly initialize and use the
anchored path. This is also the only path that provides one-shot deletion
consumption:

```sh
cargo run -- anchor-init scenarios/benign.json out/phenotype-anchor.json
cargo run -- run-anchored scenarios/benign.json \
  out/benign-certificate.json out/ledger.jsonl out/phenotype-anchor.json
```

Exercise the transactional single-host reference actuator:

```sh
cargo run -- local-init scenarios/benign.json out/local-actuator.json
cargo run -- apply-local scenarios/benign.json \
  out/benign-certificate.json out/ledger.jsonl out/local-actuator.json
cargo run -- local-show out/local-actuator.json
```

This reference backend proves atomic adapter semantics; it is not a production
service integration.

Evaluate a bounded exported Kubernetes snapshot without cluster access or
actuation:

```sh
cargo run --locked --offline -- shadow-kubernetes \
  scenarios/benign.json snapshots/kubernetes-shadow-benign.json \
  out/shadow-certificate.json out/shadow-ledger.jsonl
```

See [Kubernetes Shadow Adapter](docs/KUBERNETES_SHADOW.md).

Run the stable, versioned private-evaluation boundary with a strict
configuration:

```sh
mkdir -p out
cargo run --locked --offline -- evaluate evaluation/config.example.json
```

See [Versioned Evaluation CLI](docs/EVALUATION_CLI.md). This mode writes only
certificate and ledger evidence; it has no target-system mutation authority.

Back up, restore, and recover its current single-host generation:

```sh
cargo run -- local-backup out/local-actuator.json out/actuator-backup.json
cargo run -- local-restore out/local-actuator.json out/actuator-backup.json
cargo run -- local-recover out/local-actuator.json
```

Actuator schema-v1 files must be upgraded with `local-upgrade`; do not
reinitialize them and discard deletion-consumption history. See
[Actuator Recovery](docs/ACTUATOR_RECOVERY.md).

Reproduce the bounded Linux recovery qualification from the cached pinned image:

```sh
./scripts/qualify-linux-recovery.sh linux/arm64
./scripts/qualify-linux-recovery.sh linux/amd64
```

The amd64 run is emulated on the current arm64 host. Both runs are
network-disabled and use disposable Docker-managed Linux volumes; neither is a
bare-metal or whole-disk durability claim.

For the complete private-repository quality gate, run:

```sh
./scripts/ci-local.sh
```

Generate the bounded 512-scenario safety/availability report:

```sh
cargo run --locked --offline --example state_space -- results/generated-state-space.json
```

Hosted CI is intentionally disabled until an explicitly approved public-opening
or research-release gate.

M2 results and negative findings are reported in
[M2 Adversarial Results](docs/M2_RESULTS.md).
The evidence-to-product comparison is recorded in
[Productisation Assessment](docs/PRODUCTISATION_ASSESSMENT.md).
The binding M3 outcome and its reopening conditions are recorded in
[Productisation Decision](docs/PRODUCTISATION_DECISION.md). The later bounded
authorization is recorded in
[Private Evaluation Product Decision](docs/EVALUATION_PRODUCT_DECISION.md).

Each run authenticates all authority envelopes before evaluation. The certificate
is deterministic for identical inputs; the JSONL ledger is append-only. The
fixture generator uses deterministic research-only signing keys:

```sh
cargo run --example generate_fixtures
```

## Repository policy

This is a private repository with `origin` configured for `kabudu/telosieve`. The
default branch is `master`.
