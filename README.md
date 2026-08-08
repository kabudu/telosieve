# Telosieve

![Telosieve](assets/brand/source/telosieve-horizontal.svg)

Telosieve questions desired-state instructions before they are enforced. It separates goal, observation, and viability authorities, tests explicit fault hypotheses, and refuses when surviving evidence cannot justify a bounded result.

> Telosieve is currently a read-only evaluation candidate. It does not have production actuation authority, does not provide a general safety proof, and still requires independent assessment.

## Why Telosieve exists

Infrastructure control normally assumes that desired state is trustworthy. That assumption can fail when an authority is stale, compromised, inconsistent, or malicious. Telosieve explores a stricter model: provenance stays visible, observations require authenticated corroboration, and uncertainty produces an explicit refusal instead of a guessed repair.

The candidate contribution is a provenance-separated protocol that can suspect the goal authority, exclude suspect evidence from planning, require independently checked viability, and retain a deterministic certificate explaining either the bounded result or refusal.

## Current status

| Surface | Current evidence | Boundary |
| --- | --- | --- |
| Candidate | `v0.2.0-rc.3` pre-freeze | signed `v0.2.0-rc.1` and `rc.2` were revoked by the privacy-preserving history migration |
| Authority model | Goal, observation, and viability provenance remain separate | bounded registered and generated scenarios, not a general proof |
| Observation | Authenticated multi-domain quorum required in every supported mode | declared domains do not prove organisational independence |
| Integrations | Kubernetes, OpenTofu, Redis, PostgreSQL, and HTTP/JSON | read-only qualification with documented environment limits |
| Actuation | Transactional single-host reference actuator | reference semantics only, no production-system authority |
| Brand | Enduring product identity `2.0.0` | legal and external comprehension review remain separate gates |
| CI | `./scripts/ci-local.sh` | sole authoritative gate while the repository is private |

Public source, production promotion, hosted CI, package publication, autonomous actuation, and stronger safety claims each remain separately governed. See [Release Strategy](docs/RELEASE.md) and [Public Opening Decision](docs/PUBLIC_OPENING_DECISION.md).

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

## Architecture and safety boundary

```text
goal authority ---------\
observation quorum ------> hypothesis evaluation -> bounded certificate or refusal
viability authority ----/             |
                                        +-> append-only evidence and durable anchors
```

The core invariants are:

1. authority provenance is authenticated and never silently merged;
2. every supported evaluation mode requires an exact-byte observation quorum;
3. suspect evidence is excluded under the declared hypothesis;
4. a transition is allowed only when every surviving hypothesis agrees and viability independently accepts it;
5. unsupported, stale, divergent, oversized, replayed, or malformed evidence fails closed;
6. current integration modes write evidence only and have no target mutation authority.

The bounded generated state space contains no reproduced unsafe approval, but finite enumeration is not a proof for arbitrary systems or attackers. Read [Architecture](docs/ARCHITECTURE.md), [Threat Model](docs/THREAT_MODEL.md), [Soundness Case](docs/SOUNDNESS_CASE.md), [Observation Quorum](docs/OBSERVATION_QUORUM.md), and [Adversarial Coverage](docs/ADVERSARIAL_COVERAGE.md) before making stronger claims.

## Development and verification

The complete private-repository gate is:

```sh
./scripts/ci-local.sh
```

It runs formatting, linting, Rust and Python tests, documentation and metadata checks, supply-chain validation, deterministic packaging, adversarial load, real disposable integration qualifications, reproducible builds, and diff hygiene. Hosted CI is intentionally disabled while the repository is private and must never be described as passing.

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
| Roadmap and traceability | [Implementation Plan](docs/IMPLEMENTATION_PLAN.md), [Requirements Traceability](docs/REQUIREMENTS_TRACEABILITY.md) |
| Release and assessment | [Release Strategy](docs/RELEASE.md), [Candidate Signing](docs/CANDIDATE_SIGNING.md), [External Assessment](docs/EXTERNAL_ASSESSMENT.md) |

## Repository policy

Telosieve is licensed under [Apache License 2.0](LICENSE). The private repository uses `master` as its default branch. Every milestone is delivered through a feature branch, full local CI, remote pull-request diff review, and squash merge. Repository visibility alone never authorizes hosted CI, packages, telemetry, production deployment, or stronger claims.
