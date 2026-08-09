# Public Opening Decision

Date: 2026-08-08

## Decision

The owner approves preparing Telosieve for source publication as claim-bounded evaluation software. Productisation, the privacy-preserving history migration, and the signed `v0.2.0-rc.3` successor freeze are complete. Repository visibility may change only after the final public-history audit reports no prohibited material immediately before opening.

This decision authorizes Apache-2.0 source availability at that later gate. It does not authorize production deployment, autonomous actuation, a general safety or novelty claim, package or container registry publication, telemetry, paid services, hosted CI, or publication of private candidate handoffs, signing keys, evaluator identities, credentials, or assessment correspondence.

## Opening conditions

1. Public documentation consistently identifies Telosieve as evaluation software and preserves known limitations and negative findings.
2. Licence, security, contribution, conduct, changelog, package metadata, and brand governance are complete and validated.
3. Current name, registry, company, domain, trademark-risk, prior-art, dependency, advisory, and repository-history diligence is recorded.
4. The exact candidate commit passes `./scripts/ci-local.sh`, deterministic build qualification, signed freeze, and offline verification.
5. The public repository excludes private handoff artifacts, credentials, keys, personal assessment data, machine-specific paths, and the owner's personal email throughout files and Git metadata; [History Privacy Migration](HISTORY_PRIVACY_MIGRATION.md) must complete and a successor candidate must be frozen from the sanitized graph.
6. Visibility is verified after opening, while hosted CI remains disabled until a later explicit approval satisfies every requirement in [Release Strategy](RELEASE.md).

## Claim boundary

Public opening means that others can inspect, build, test, and assess the source. It is not evidence of independent validation, production readiness, organizational fault-domain independence, market fit, legal name clearance, patentability, or freedom to operate. Those claims remain gated by their own evidence.
