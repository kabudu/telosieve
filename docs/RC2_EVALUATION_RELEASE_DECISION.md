# v0.2.0-rc.2 Evaluation Release Decision

Date: 2026-08-08

## Authorization

The owner authorizes freezing Telosieve `v0.2.0-rc.2` from the final reviewed `master` commit after its complete authoritative local gate passes with a clean worktree. This is an evaluation release-candidate authorization, not production promotion or general public artifact distribution.

The authorized release parameters are:

- version and tag: `0.2.0-rc.2` and annotated tag `v0.2.0-rc.2`;
- authority boundary: `read-only-no-target-mutation`;
- signer: `telosieve-project-evaluation`;
- key ID: `v0.2.0-rc.2`;
- signature context: `telosieve/private-evaluation`;
- custody label: `project-controlled-evaluation`;
- validity: no more than 30 days from the ceremony issue time;
- recipients: named prospective external evaluators approved by the owner;
- handoff channel: owner-controlled private create-new transfer outside Git;
- trust authentication: SHA-256 of the public trust record through a separately authenticated channel;
- source publication: separately governed by [Public Opening Decision](PUBLIC_OPENING_DECISION.md);
- hosted CI, crates, container registries, telemetry, production deployment, and autonomous actuation: not authorized.

The private key must be newly generated or retrieved outside the repository, be an owner-only regular single-link file, and never enter Git, the handoff, logs, command output, or assessor correspondence. A project-controlled evaluation signature authenticates the candidate bytes but does not establish independent, hardware-backed, dual-custodian, or production-grade custody.

## Required ceremony evidence

1. Exact clean source commit and pushed `master` SHA.
2. `./scripts/ci-local.sh` success at that commit, with hosted checks described only as absent by policy.
3. Two isolated locked/offline release builds with identical bytes and recorded SHA-256.
4. Atomic seven-file handoff whose embedded commit, binary, capabilities, contract, readiness, brand, licence, and release notes match the source.
5. Offline verification using the independently built source binary plus the expected version.
6. Annotated tag containing the exact commit, bundle digest, trust-record digest, custody boundary, and remaining independent-assessment requirement.
7. Local, remote branch, and remote tag identity verification.

Abort without tagging on a dirty tree, stale branch, CI failure, build drift, unsafe key shape, expired or over-wide interval, output collision, signature failure, artifact mismatch, unexpected disclosure, or incomplete record.

## Non-claims

This decision does not establish operational signing custody, independent assessment, organizational producer independence, cross-platform reproducible builds, external integration qualification, production readiness, legal name clearance, market fit, or safety against arbitrary compromised authorities or agents.
