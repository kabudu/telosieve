# Telosieve v0.2.0-rc.1

Telosieve v0.2.0-rc.1 is the first private, production-shaped evaluation
candidate prepared for external testing. It provides read-only Kubernetes
shadow/live and saved OpenTofu plan evaluation without target mutation.

## Highlights

- **Fail-closed evaluation:** strict versioned inputs refuse ambiguity, drift,
  stale or invalid authority evidence, quorum failure, and resource exhaustion.
- **Corroborated observations:** Kubernetes and OpenTofu modes require exact
  agreement from two authenticated producer domains.
- **Producer isolation:** authenticated bounded relays support distinct Linux
  service identities without exposing producer keys or platform credentials to
  the evaluator.
- **Operational lifecycle:** install, backup, upgrade, rollback, diagnostics,
  evidence export, and uninstall paths are bounded and qualified.
- **Evaluator handoff:** deterministic bundle bytes, checksums, provenance,
  detached signature, public trust, and offline verification bind the reviewed
  source commit.

## Evaluation boundary

This is private evaluation software. It does not actuate Kubernetes or OpenTofu,
hold mutation credentials, establish independent producer truth, or authorize
production deployment. The kind cluster, Linux container, signing identity, and
all pre-release evidence are project-controlled.

## External validation requested

Assess the exact signed handoff bytes. Priority areas are parser and protocol
soundness, correlated producer/control-plane faults, managed Kubernetes and
remote-state OpenTofu behavior, identity and key custody, denial-of-service
bounds, cross-platform reproducibility, and operator recovery procedures.
Run the bundled verifier with `--trusted-telosieve` set to a verifier binary
obtained independently of the candidate handoff.

Production promotion remains blocked until independent operator reproduction,
independent security assessment, remediation and reassessment of material
findings, a named production adapter, production identity/key/clock custody,
and a new explicit promotion decision.
