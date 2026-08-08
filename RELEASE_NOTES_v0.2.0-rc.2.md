# Telosieve v0.2.0-rc.2: Corroborated read-only evaluation

Telosieve v0.2.0-rc.2 is a private, production-shaped evaluation candidate for external testing of fail-closed, corroborated read-only decisions across supported integration modes.

## Highlights

- **Mandatory corroboration:** every supported evaluation capability requires a verified observation quorum whose evidence digest is bound into the compatible certificate.
- **Mainstream integrations:** Kubernetes, saved OpenTofu plans, Redis, PostgreSQL, and fixed-GET HTTP/JSON paths have bounded read-only collectors and retained qualification evidence.
- **Transport and PKI controls:** the HTTP/JSON path includes locally qualified TLS 1.3 mutual authentication, revocation enforcement, readiness checks, monitoring, and fixed-cardinality Prometheus output.
- **Fail-closed isolation:** producer relays, strict schemas, bounded subprocesses, immutable evidence, and exact version checks refuse unavailable, stale, divergent, malformed, or oversized inputs.
- **Evaluator handoff:** deterministic bundle bytes, checksums, provenance, detached signature, public trust, release notes, and an offline verifier bind the reviewed source commit.

## Evaluation boundary

This is evaluation software. It does not actuate supported target systems, hold mutation credentials, establish that authenticated producers are semantically truthful or organisationally independent, or authorize production deployment. Project-controlled local and disposable infrastructure is not independent evidence.

## Installation

Verify the complete handoff first, then follow [External Assessment](docs/EXTERNAL_ASSESSMENT.md). Do not execute a candidate binary before independently authenticating the expected version and trust-record digest.

## Evidence and compatibility

The authoritative private-repository gate is `./scripts/ci-local.sh`. Supported evaluation capabilities and certificate bindings are defined in `evaluation/contract.json`; compatibility and refusal behavior are documented in [Protocol Compatibility](docs/PROTOCOL_COMPATIBILITY.md).

## External validation requested

Assess the exact signed handoff bytes. Priority areas are parser and protocol soundness, correlated producer or control-plane faults, managed Kubernetes and remote-state OpenTofu behavior, independently operated Redis, PostgreSQL and HTTP endpoints, identity and key custody, denial-of-service bounds, cross-platform reproducibility, and operator recovery.

Production promotion remains blocked until independent operator reproduction, independent security assessment, remediation and reassessment of material findings, a named production adapter, production identity, key and clock custody, and a new explicit promotion decision.
