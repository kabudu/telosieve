# Telosieve

![Telosieve](assets/brand/source/telosieve-horizontal.svg)

[![CI](https://github.com/kabudu/telosieve/actions/workflows/ci.yml/badge.svg)](https://github.com/kabudu/telosieve/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/telosieve.svg)](https://crates.io/crates/telosieve)
[![docs.rs](https://img.shields.io/docsrs/telosieve)](https://docs.rs/telosieve)
[![GitHub release](https://img.shields.io/github/v/release/kabudu/telosieve?include_prereleases)](https://github.com/kabudu/telosieve/releases)
[![License](https://img.shields.io/github/license/kabudu/telosieve)](LICENSE)

Telosieve is a read-only evaluation system for infrastructure instructions. Before a desired-state tool acts, Telosieve asks a deliberately uncomfortable question: **what if the instruction itself is wrong?**

It compares authenticated intent with corroborated observations and separately defined viability rules. It then tests the declared ways those sources could be faulty. If every surviving case supports the same bounded result, Telosieve records a certificate. If the evidence is missing, stale, inconsistent, or unsafe under any surviving case, it refuses instead of guessing.

> **Current boundary:** Telosieve evaluates and records decisions but does not change Kubernetes, OpenTofu, Redis, PostgreSQL, or HTTP targets. It is an evaluation candidate, not a general safety proof, and still requires independent assessment.

## The problem in one example

Suppose a Kubernetes controller receives a signed instruction to replace healthy state. A normal reconciler may treat that signature as enough authority and faithfully apply a poisoned instruction. Telosieve keeps the signed goal separate from what multiple read-only collectors observe and from the rules describing what must remain viable. It asks which sources could be wrong, removes each suspect source in turn, and accepts a result only when the independently checked survivors agree.

## How Telosieve works

![Telosieve architecture: authenticated goal, observation quorum, and viability evidence pass through provenance verification, fault hypotheses, independent checking, and unanimous surviving agreement before a bounded certificate or explicit refusal is retained.](site/assets/telosieve-architecture.svg)

1. **Keep evidence separate.** Goal instructions, observed state, and viability rules retain their own provenance rather than being merged into one trusted input.
2. **Verify before reasoning.** Telosieve checks identity, signatures, lineage, freshness, schemas, exact-byte observation quorum, and resource bounds.
3. **Test what could be wrong.** It evaluates the configured fault hypotheses, excluding each suspect authority before deriving and independently checking a plan.
4. **Agree or refuse.** Every surviving hypothesis must support the same viable result. Ambiguity, disagreement, malformed evidence, timeouts, or unsupported input produce an explicit refusal.

## Current status

| Surface | Current evidence | Boundary |
| --- | --- | --- |
| Public release | `v0.2.0-rc.4` | evaluation software for external inspection and assessment |
| Signed handoff | Private `v0.2.0-rc.3` | project-controlled predecessor retained for exact-byte assessment |
| Authority model | Goal, observation, and viability provenance remain separate | bounded registered and generated scenarios, not a general proof |
| Observation | Authenticated multi-domain quorum required in every supported mode | declared domains do not prove organisational independence |
| Integrations | Kubernetes, OpenTofu, Redis, PostgreSQL, and HTTP/JSON | read-only qualification with documented environment limits |
| Actuation | Transactional single-host reference actuator | reference semantics only, no production-system authority |
| Brand | Current source identity `4.0.0` | signed rc.3 carries archived `2.0.0`; legal and external comprehension review remain separate gates |
| CI | GitHub Actions plus `./scripts/ci-local.sh` | hosted checks cover portable gates; local CI retains real disposable integration qualifications |

Public source, hosted CI, package publication, and the website are authorized for the `v0.2.0-rc.4` evaluation release. Production promotion, autonomous actuation, and stronger safety claims remain separately governed. See [Release Strategy](docs/RELEASE.md) and [Public Opening Decision](docs/PUBLIC_OPENING_DECISION.md).

## Five-minute local path

Requirements: stable Rust 1.97 or newer and dependencies already present in the Cargo cache.

```sh
cargo test --locked --offline
mkdir -p out
cargo run --locked --offline -- run \
  scenarios/benign.json out/benign-certificate.json out/ledger.jsonl
cargo run --locked --offline -- run \
  scenarios/poisoned-goal.json out/refusal-certificate.json out/ledger.jsonl
```

The benign scenario emits a deterministic bounded certificate. The poisoned-goal scenario refuses. Neither command mutates an external target system.

After the public crate is available, install the evaluation CLI with `cargo install telosieve --version 0.2.0-rc.4`.

Run the versioned evaluation boundary with:

```sh
cargo run --locked --offline -- evaluate evaluation/config.example.json
```

Inspect the exact compiled capability contract with:

```sh
cargo run --locked --offline -- evaluation-capabilities
```

For rollback-detecting history, deletion-authorization consumption, reference actuation, backup, restore, and recovery commands, use the [Evaluation CLI Guide](docs/EVALUATION_CLI.md), [Actuator Recovery Guide](docs/ACTUATOR_RECOVERY.md), and [Evaluation Lifecycle Guide](docs/EVALUATION_LIFECYCLE.md).

## Choose an evaluation path

| Path | What it evaluates | Start here |
| --- | --- | --- |
| Kubernetes shadow | A bounded exported snapshot without cluster access | [Kubernetes Shadow Adapter](docs/KUBERNETES_SHADOW.md) |
| Kubernetes live | Four bounded read-only API collections with coherence checks | [Real Kubernetes Qualification](docs/KUBERNETES_REAL_CLUSTER.md) |
| OpenTofu | Saved plan bytes through two corroborating producers, never `apply` | [OpenTofu Plan Evaluation](docs/OPENTOFU_PLAN.md) |
| Redis | A bounded key namespace through SELECT-only identities | [Redis Integration](docs/REDIS_INTEGRATION.md) |
| PostgreSQL | A repeatable-read, read-only snapshot through SELECT-only roles | [PostgreSQL Integration](docs/POSTGRESQL_INTEGRATION.md) |
| HTTP/JSON | A fixed GET-only snapshot protocol with bearer or mutual-TLS identity | [HTTP/JSON Integration](docs/HTTP_JSON_INTEGRATION.md) |
| New system | The versioned executable adapter and quorum response contract | [Integration Contract](docs/INTEGRATION_CONTRACT.md) |

Each qualification distinguishes real-system coverage from simulated control planes, loopback-only transport, shared administration, or absent organisational independence. Those limitations are evidence, not footnotes.

## External assessment

Assessors should begin with the [External Assessment Guide](docs/EXTERNAL_ASSESSMENT.md). It defines:

- how to authenticate the trust-record digest through a separate channel;
- how to verify the handoff before executing its binary;
- mandatory integrity tests and environment-dependent integration tests;
- adversarial and lifecycle expectations;
- the findings format and evidence-return procedure.

The [Assessor Handoff](docs/ASSESSOR_HANDOFF.md) is retained only for historical Post-M15 reproduction and is not the current candidate procedure.

## Safety boundary and invariants

The core invariants are:

1. authority provenance is authenticated and never silently merged;
2. every supported evaluation mode requires an exact-byte observation quorum;
3. suspect evidence is excluded under the declared hypothesis;
4. a transition is allowed only when every surviving hypothesis agrees and viability independently accepts it;
5. unsupported, stale, divergent, oversized, replayed, or malformed evidence fails closed;
6. current integration modes write evidence only and have no target mutation authority.

The bounded generated state space contains no reproduced unsafe approval, but finite enumeration is not a proof for arbitrary systems or attackers. Read [Architecture](docs/ARCHITECTURE.md), [Threat Model](docs/THREAT_MODEL.md), [Soundness Case](docs/SOUNDNESS_CASE.md), [Observation Quorum](docs/OBSERVATION_QUORUM.md), and [Adversarial Coverage](docs/ADVERSARIAL_COVERAGE.md) before making stronger claims.

## Development and verification

The complete repository-owned gate is:

```sh
./scripts/ci-local.sh
```

It runs formatting, linting, Rust and Python tests, documentation and metadata checks, supply-chain validation, deterministic packaging, adversarial load, real disposable integration qualifications, reproducible builds, and diff hygiene. GitHub Actions runs the portable subset on pull requests and `master`; the complete local gate remains required for release decisions.

Useful focused commands:

```sh
cargo test --locked --offline --all-targets --all-features
cargo run --locked --offline --example state_space -- results/generated-state-space.json
python3 scripts/validate-brand.py
python3 scripts/validate-open-source-readiness.py
```

Contribution, security-reporting, and release rules are in [Contributing](CONTRIBUTING.md), [Security Policy](SECURITY.md), [Code of Conduct](CODE_OF_CONDUCT.md), and [Changelog](CHANGELOG.md).

## Documentation map

| Need | Document |
| --- | --- |
| Product scope and claim limits | [Product Specification](docs/PRODUCT_SPECIFICATION.md), [Novelty](docs/NOVELTY.md), [Productisation Decision](docs/PRODUCTISATION_DECISION.md) |
| System and protocol design | [Architecture](docs/ARCHITECTURE.md), [Authority Protocol](docs/AUTHORITY_PROTOCOL.md), [Compatibility](docs/PROTOCOL_COMPATIBILITY.md) |
| Security and correctness | [Threat Model](docs/THREAT_MODEL.md), [Soundness Case](docs/SOUNDNESS_CASE.md), [Risk Register](docs/RISK_REGISTER.md) |
| Operations and recovery | [Operations](docs/OPERATIONS.md), [Diagnostics](docs/OPERATOR_DIAGNOSTICS.md), [Lifecycle](docs/EVALUATION_LIFECYCLE.md) |
| Evaluation evidence | [Validation](docs/VALIDATION.md), [E2E Testing](docs/E2E_TESTING.md), [Adversarial Coverage](docs/ADVERSARIAL_COVERAGE.md) |
| Product identity | [Brand Identity](docs/BRAND_IDENTITY.md), [Productisation Decision](docs/EVALUATION_PRODUCTISATION_DECISION.md) |
| Website source and activation boundary | [GitHub Pages Website](docs/GITHUB_PAGES.md) |
| Roadmap and traceability | [Implementation Plan](docs/IMPLEMENTATION_PLAN.md), [Requirements Traceability](docs/REQUIREMENTS_TRACEABILITY.md) |
| Release and assessment | [Release Strategy](docs/RELEASE.md), [Candidate Signing](docs/CANDIDATE_SIGNING.md), [External Assessment](docs/EXTERNAL_ASSESSMENT.md) |

## Repository policy

Telosieve is licensed under [Apache License 2.0](LICENSE). The repository uses `master` as its default branch. Every milestone is delivered through a feature branch, full local CI, remote pull-request diff review, and squash merge. Public distribution does not authorize telemetry, production deployment, mutation authority, or stronger claims.
