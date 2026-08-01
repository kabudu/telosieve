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
2026-07-30. Version `0.2.0-rc.1` is the first signed private evaluation
candidate for external assessment. Public release, autonomous production actuation, and
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
The executable [adversarial coverage contract](docs/ADVERSARIAL_COVERAGE.md)
tracks evidence and open attack-surface gaps separately for every evaluation
mode; it currently retains three deferred cells and is not a robustness proof.
An authenticated [observation-quorum primitive](docs/OBSERVATION_QUORUM.md) now
provides the cross-mode cryptographic foundation for those remaining cells, but
evaluation does not yet require it and the cells remain deferred.

## External assessment

External assessors should start with the
[External Assessment Guide](docs/EXTERNAL_ASSESSMENT.md). It identifies the
exact `v0.2.0-rc.1` source and handoff, requires an independently authenticated
trust-record digest and independently built verifier, separates mandatory
integrity checks from environment-dependent integration tests, and defines the
requested findings record. Do not execute the bundled binary before the signed
handoff has been verified.

The older [Independent-Assessment Handoff](docs/ASSESSOR_HANDOFF.md) is retained
only to reproduce the historical Post-M15 evidence; it is not the release-
candidate assessment procedure.

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

Configuration v5 also supports bounded, read-only live Kubernetes collection
through an explicitly selected `kubectl` and kubeconfig. See
[Evaluation CLI](docs/EVALUATION_CLI.md); this remains evaluation software and
requires agreement with a signed multi-domain external-producer quorum. The
fake-process suite is supplemented by a disposable real-cluster/RBAC
qualification; managed and independently operated clusters remain unqualified.

Private macOS/Linux evaluation installations can be managed with the bounded
local lifecycle tool. It atomically installs, upgrades, and rolls back a
digest-bound binary/configuration pair, creates verified backups, and uninstalls
software while preserving evidence. See
[Evaluation Installation Lifecycle](docs/EVALUATION_LIFECYCLE.md).

Generate bounded, content-redacted installation diagnostics with
`scripts/evaluation-diagnostics.py`. The fixed export allowlist excludes paths,
configuration values, evidence contents, environment, and application values;
digests remain sensitive. See
[Operator Diagnostics](docs/OPERATOR_DIAGNOSTICS.md).

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

The first concrete Integration Contract v1 implementation targets a bounded
Redis key namespace. Its pinned disposable Redis 8.8 qualification uses three
distinct read-only ACL users, proves mutation denial, exercises two signed
producers and bounded concurrent load, and retains the shared-control-plane
limitation. See [Redis Read-Only Integration](docs/REDIS_INTEGRATION.md).

PostgreSQL 18.4 is the second concrete contract implementation. It uses a
bounded repeatable-read, read-only transaction, three SELECT-only roles, two
signed producers, concurrent-writer/load campaigns, and explicit mutation,
scope, lock and outage refusals. See
[PostgreSQL Read-Only Integration](docs/POSTGRESQL_INTEGRATION.md).

Inspect the exact machine-checked read-only evaluation surface with:

```sh
cargo run --locked --offline -- evaluation-capabilities
```

Generate and qualify the credential-free OpenTofu plan integration with:

```sh
cargo build --locked --offline
python3 scripts/run-opentofu-plan.py
```

This uses disposable local `terraform_data` state, corroborates the exact plan
bytes through two separately invoked renderer/signing producer processes, and
never grants Telosieve provider, backend, or apply access. See
[OpenTofu Plan Evaluation](docs/OPENTOFU_PLAN.md).

Linux evaluators can place each Kubernetes/OpenTofu observation producer behind
a bounded authenticated Unix relay running as its own systemd identity; see
[Observation Producer Isolation](docs/PRODUCER_ISOLATION.md). The local harness
qualifies transport mechanics, not real multi-user or organizational isolation.

Implement additional read-only systems through the versioned executable
[Integration Contract v1](docs/INTEGRATION_CONTRACT.md). Configuration v7 sends
one bounded request to an absolute adapter executable, requires a canonical
platform-neutral response plus an exact-byte multi-domain producer quorum, and
binds the result into certificate v11. The generic conformance suite qualifies
the contract, not any new platform or its credential scope.

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
