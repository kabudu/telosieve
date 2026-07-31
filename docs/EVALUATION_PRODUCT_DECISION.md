# Private Evaluation Product Decision

Date: 2026-07-30

## Decision

Telosieve is authorized to move from research-only development toward a
production-shaped, privately deployable evaluation product. The evaluation
version exists so external operators and assessors can test an operationally
credible candidate rather than a laboratory harness.

This decision supersedes the productisation prohibition in the 2026-07-29 M3
decision only for the bounded private evaluation lane. It does not authorize
autonomous production actuation, public distribution, production credentials,
hosted CI, default-on telemetry, or general safety claims.

The machine-readable contract is `evaluation/contract.json`. Local validation
must reject any silent weakening of its authorized and prohibited sets.

### 2026-07-31 contract-v2 clarification

Contract v2 expresses the existing authorization as the explicit
`read-only-no-target-mutation` boundary. Its supported inventory is Kubernetes
exported shadow, live read-only Kubernetes collection, and saved OpenTofu plan
evaluation. All three modes produce `target_mutated: false`; the clarification
does not authorize credentials or actuation beyond the boundaries below. The
compiled CLI publishes the same schema-to-mode inventory, and local validation
rejects drift, uncontracted modes, mutation-shaped modes, duplicate schemas, or
a weakened authority boundary.

## Supported evaluation boundary

The first supported mode is read-only shadow evaluation:

- observations may be collected from a named external system with
  least-privilege, read-only access;
- Telosieve may evaluate, refuse, diagnose, and export signed evidence;
- the existing platform reconciler remains the only mutation authority;
- the evaluation process must not hold mutation credentials;
- every input, retry, wait, response, artifact, and retained-history path must
  remain explicitly bounded and fail closed.

The file-backed reference actuator remains a protocol and recovery test backend.
It is not a supported production integration.

## Evaluation candidate readiness

A private evaluation candidate may be assembled only when all of these are
implemented and evidenced:

1. stable, versioned CLI and configuration with strict validation;
2. fail-closed live read-only integration for the named evaluation platform;
3. documented install, upgrade, rollback, backup, and uninstall procedures;
4. least-privilege permissions and secret-free defaults;
5. bounded diagnostics and assessor evidence export without sensitive data;
6. platform, resource, interruption, and recovery qualification;
7. a reproducible private bundle with checksums and an approved signing method;
8. a threat model, operator runbook, incident procedures, and known limits.

Candidate packaging is not a release authorization. The exact version,
artifacts, signing identity, recipients, and distribution channel require a
separate explicit user decision after these gates pass. While the repository is
private, `./scripts/ci-local.sh` remains the sole authoritative CI gate.

## Independent validation and promotion

Independent validation follows construction of the candidate and must target its
exact source commit and artifacts. Production promotion requires:

- independent security assessment and independent operator reproduction;
- remediation and reassessment of material findings;
- a named production adapter with concurrency, authorization, idempotency,
  partial-failure, rollback, and recovery evidence;
- production identity, key, trusted-clock, and custody design; and
- a new explicit promotion decision.

Negative validation findings improve the product backlog; they do not
automatically terminate the project. A finding blocks promotion only to the
extent justified by its severity and affected claim.

## Failure and claim boundaries

The evaluation version must call itself evaluation software. It must not imply
that finite scenarios prove arbitrary safety, that signed input is semantically
true, that declared domains are organizationally independent, or that shadow
decisions authorize mutation. On ambiguity, stale evidence, unavailable
authorities, resource exhaustion, or verification failure, it must refuse and
preserve diagnostic evidence without changing the target system.

Public opening, hosted CI, registry publication, production deployment, and
telemetry remain separate decisions. Repository visibility alone authorizes none
of them, and independent validation alone does not authorize them.
