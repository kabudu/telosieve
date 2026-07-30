# Operations

The research harness runs locally with fixed seeds and no production credentials.
Every run records source commit, configuration digest, dependency lock digest,
authority envelopes, decision certificate, timing, and outcome.

Operational alerts cover signature failure, equivocation, schema mismatch,
hypothesis-budget exhaustion, checker disagreement, ledger write failure, and
actuator partial failure. No automatic retry may broaden authority or weaken an
invariant. Recovery is replay from the last complete ledger record.

Secrets are test keys stored outside fixtures. Logs must not include application
values. Retention and deletion policy must be defined before real traces are used.

For `apply-local`, durable service commit occurs before certificate and ledger
persistence. An evidence-output failure is therefore an applied-but-unreported
incident: do not retry the stale scenario. Preserve the actuator file, lock or
temporary artifacts, and output errors; read current state and the durable
last-actuation operation digest through `local-show`; obtain a new authenticated
phenotype; and only then evaluate a new operation.
Never break an actuator lock until the writer is proven absent.

## Local actuator recovery runbook

1. Stop new actuator commands and prove the previous writer process is absent.
2. Preserve the primary state, `.witness.json`, lock directory, temporary files,
   certificate, ledger, and stderr for incident analysis.
3. Remove only the stale `.actuator.lock` directory.
4. Run `local-recover`; it validates canonical state and witness before removing
   known temporary files or resolving a pending generation.
5. Run `local-show` and compare its generation, operation digest, and state
   digest with the last complete evidence record.
6. If primary state is missing or corrupt but the witness is committed, restore
   only an exact-latest verified backup with `local-restore`.
7. Obtain a new authenticated phenotype before further evaluation.

Never restore an older backup, replace the witness, infer a generation, or retry
an applied stale scenario. Loss or rollback of both state and witness is a stop
condition outside this protocol.

## Key lifecycle handling

Keep each lifecycle recovery private key offline and separate from its
operational issuer key. Review the exact subject, issuer, authority kind,
sequence, parent digest, effective time, and activated/revoked key before
signing. Distribute the complete chain, its public recovery root, and an
independently obtained trusted tip together. Never repair a missing statement by
editing sequence or parent fields, reuse an old operational key, or fall back to
a revoked bootstrap key. Missing or conflicting lifecycle state is a refusal and
incident condition.

For every enrolled lifecycle, obtain the evaluation time and its bounded
trusted-time assertion through the approved operational source. Refuse a window
wider than 300 seconds or an evaluation outside its inclusive bounds. The local
source label is evidence metadata, not clock authentication; never claim that
Telosieve itself proves wall-clock time.

Run `./scripts/run-recovery-ceremony.sh` after ceremony-protocol changes. A veto,
duplicate, stale, divergent, excluded, or missing-quorum vote aborts the
ceremony. Excluding a suspected custodian requires a new request and must not
lower the original quorum. Preserve the generated aggregate, but never interpret
it as a real recovery-root authorization, signature, custody record, or HSM
operation. See [RECOVERY_ROOT_CEREMONY](RECOVERY_ROOT_CEREMONY.md).

Before consuming retained certificates, parse them through the supported
compatibility boundary and preserve the original bytes. Accept only v7 without
an execution extension, v8 with actuation only, or v9 with shadow evidence only.
Never relabel a version, strip an unknown field, or invent a newly required trust
value. Migration requires verification of the authoritative scenario followed
by new evidence generation; the historical certificate remains immutable. See
[PROTOCOL_COMPATIBILITY](PROTOCOL_COMPATIBILITY.md).

Use `scripts/certificate-reader.py` only through bounded standard input and
preserve its SHA-256 acceptance summary with the source certificate. A refusal
is an incident or migration stop; do not retry after stripping fields or
relabelling versions. Run `scripts/run-reader-qualification.sh` after changing
certificate schemas, readers, or version support.

Do not remove a certificate version operationally until its documented
deprecation has remained in force for two completed milestones, every registered
consumer is inactive or migrated, historical reading remains available, and the
separate explicitly approved major-compatibility gate has merged.

When authenticity is required, preserve the certificate and its detached
attestation as separate immutable files. Verify both against an independently
obtained context, evaluation time, and bounded signer trust set; do not accept an
unsigned fallback after requesting verification. Keep retired public keys while
their historical attestations must verify, but never extend their signing
windows to repair a failure.

Run `scripts/run-attestation-qualification.sh` after changing certificate,
attestation, key-window, or reader logic. The repository’s signing keys are
fixtures only and must never be reused for operational evidence.

When timestamp/revocation verification is required, supply the complete bounded
timestamp chain, current revocation snapshot, and independently retained exact
tips. Treat missing inputs, stale snapshots, tip mismatch, or witness
unavailability as refusal; never extend times or roll tips back to restore
availability. Run `scripts/run-witness-qualification.sh` after related changes.

Persist timestamp and revocation tips together with `WitnessTipStore`; preserve
its primary and recovery-witness files as one operational unit. Restore only a
create-new backup accepted against the surviving committed witness. On missing,
corrupt, locked, pending-inconsistent, stale, or conflicting state, stop
verification and preserve all files. Run `scripts/run-witness-durability.sh`
after store or distribution-policy changes.

Run `scripts/run-witness-endpoint-harness.sh` after endpoint, authentication,
transport, retry, timeout, or response-bound changes. Treat every transport
failure as evidence unavailability; do not cache past expiry, retry beyond the
bound, or accept HTTP success without exact cryptographic verification. Harness
tokens and loopback HTTP are fixtures and must not be deployed.

For Post-M25 handoff work, distribute only the frozen request and exact private
source through an approved read-only channel. Do not provide endpoint
credentials or operate the assessor's environment. Validate returned records
with `python3 scripts/witness_operator_record.py RECORD.json`, then separately
verify operator identity, signature, custody, and raw evidence before changing
any independent-reproduction checklist state.

For `shadow-kubernetes`, export the ConfigMap and StatefulSet evidence through a
separate read-only process, preserve the raw export, and run Telosieve offline.
Treat drift, incomplete observations, stale generations, identity changes, or
authority mismatch as an incident/refusal. Never use the shadow certificate as a
mutation command; it records a research decision only.

Run `./scripts/run-incident-drills.sh` after recovery-protocol changes. A missing
or failed drill blocks the milestone; never edit the aggregate result to convert
a failure into a pass. See [INCIDENT_DRILLS](INCIDENT_DRILLS.md).
