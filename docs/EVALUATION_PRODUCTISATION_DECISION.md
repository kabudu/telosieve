# Evaluation Productisation Decision

Date: 2026-08-08

## Decision

The owner approves Telosieve as a productised open-source evaluation project under brand identity `1.0.0-evaluation`. This supersedes the 2026-07-29 productisation prohibition for the read-only evaluation and public-source presentation lanes. It does not supersede production, actuation, independent-assessment, legal-clearance, hosted-CI, package-publication, or safety-claim gates.

## Supported product profile

- primary user: platform reliability, infrastructure security, research, and independent assessment practitioners;
- category: corroborated desired-state evaluation;
- authority boundary: `read-only-no-target-mutation`;
- supported integration contract and modes: the exact machine-readable inventory in `evaluation/contract.json`;
- distribution posture: source and exact signed evaluation handoff only after their separate gates;
- support posture: evaluation candidates only, without response-time or production-availability SLA;
- telemetry: absent and unauthorized by default;
- exit: open evidence export, uninstall and preserved evidence procedures, Apache-2.0 source rights.

## Evidence and claim boundary

The identity is backed by current implementation, local qualification, deterministic packaging, threat and risk documentation, and a defined assessor workflow. The identity may make those bounded facts easier to understand. It must not imply that the project is independently validated, production-ready, legally cleared, generally safe, novel, commercially proven, or able to prevent arbitrary agent or infrastructure compromise.

Productisation completion is separate from candidate freeze. The exact `v0.2.0-rc.2` candidate must still pass clean-head local CI, reproducible build qualification, approved signing, offline verification, and tag checks before distribution. Public visibility must still pass the final history/privacy gate.
