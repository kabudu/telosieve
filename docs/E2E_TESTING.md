# End-to-End Testing

Each scenario fixes seed, service state, authorities, fault declaration, expected
safety envelope, and permitted decisions. Tests replay from clean state.

Required suites:

- benign convergence and rollback;
- malicious but correctly signed goal;
- stale goal and equivocation;
- forged, omitted, delayed, and partitioned phenotype;
- weakened or contradictory viability rules;
- shared-parser discrepancy;
- two faults against a one-fault budget;
- checker timeout, ledger failure, and partial actuator failure.

Assertions cover safety violations, false refusals, recovery latency, evidence
excluded, decision reproducibility, and baseline deltas. An expected refusal is a
successful outcome when evidence is underdetermined.

The M0 integration suite (`tests/m0.rs`) exercises the public file boundary,
signature tampering, hypothesis-budget exhaustion, benign apply and rollback,
poisoned-goal refusal, deterministic byte replay, certificate persistence, and
append-only ledger records. It also replays a signed predecessor distinct from the
current snapshot and rejects missing history, forked records, and an older trusted
tip. The anchored public boundary additionally refuses an uninitialized durable
store before output, then completes after explicit initialization.

`tests/adversarial.rs` registers the M2 hostile-input matrix: poisoned and stale
goals, omitted and forged phenotype evidence, invariant weakening, partitioned
phenotypes, equivocation, parser differential coverage, and correlated faults
against the declared budget. Mutations without valid signatures are expected to
fail at provenance verification; authenticated poisoned intent proceeds to
hypothesis evaluation and refusal.

Certificate-v4 coverage additionally exercises implicit deletion with every
viability domain weakened. The Rust and Python checkers must independently reject
loss of a key present on every current replica, while focused tests preserve
ordinary value updates and key additions. The 512-scenario aggregate assertion
requires zero unsafe approvals without relabelling expected decisions.

Certificate-v6 coverage adds signed authorized and unauthorized deletion
fixtures. It verifies exact key removal through the public engine, unchanged
state on refusal, goal-binding replay rejection, mapping failures, and refusal
when one correlated domain contains every deletion issuer.

Certificate-v7 coverage runs authorized deletion through the public anchored
file boundary twice. The first run applies and persists one record; the second
fails on durable consumption without emitting another. A separate failure-path
test makes ledger persistence fail after durable commit and verifies the
authorization remains burned.

Certificate-v8 coverage adds a real executable lifecycle:
`local-init` initializes authenticated service state, `apply-local` evaluates and
commits it, and `local-show` reads the result through the operator boundary.
Additional public-boundary tests prove refusal is non-mutating, stale replay
emits no second evidence record, and evidence failure cannot roll back or repeat
an already committed transition.

The executable lifecycle now creates a verified backup, removes the primary
state, restores it against the surviving witness, and runs explicit recovery.
A separate 16-process forced-termination test verifies that stale-lock cleanup
plus `local-recover` never exposes a torn generation.

Key-lifecycle coverage runs a retained rotated-goal fixture through the public
engine and binds its chain, recovery root, and trusted tip into the certificate.
Focused protocol tests preserve historical old-key verification while rejecting
superseded, expired, revoked, reused, wrong-kind, tampered, partial, rolled-back,
equivocating, and oversized lifecycle evidence before planning.
They additionally enforce exact exclusive-expiry and inclusive-revocation
boundaries and reject evaluation below, above, or beyond the maximum width of
the trusted-time assertion.

The executable `shadow-kubernetes` lifecycle consumes only local exported JSON,
emits certificate-v9 evidence, and leaves scenario and snapshot bytes unchanged.
It rejects oversized snapshots and any evidence path that aliases an input.

The incident runner selects seven exact failure-path tests and emits a
machine-readable pass aggregate only after all seven exit successfully.

`tests/parser_corpora.rs` runs deterministic bounded mutation corpora across
authority, lifecycle, Kubernetes shadow, and actuator recovery parsers. It
requires valid round trips, fail-closed malformed inputs, structural bounds, and
continued rejection of four minimized fixtures.

`scripts/run-recovery-ceremony.sh` runs exact credential-free ceremony tests
under locked offline resolution. It emits the retained aggregate only after the
2-of-3 success/exclusion path and duplicate, missing, divergent, stale, veto,
and excluded-compromised abort paths pass.

`tests/compatibility.rs` runs bounded old/new scenario and certificate vectors.
It produces actual certificate-v7 and certificate-v8 outputs, reads the retained
certificate-v9 shadow output, and rejects missing required trust, unknown future
fields/versions, cross-version extension confusion, and oversized certificate
input. `scripts/run-compatibility-corpus.sh` retains the two-vector aggregate.

The same suite invokes `scripts/certificate-reader.py` as a separate Python
process and compares its verdict with Rust for real v7, v8, and v9 outputs plus
ten fail-closed vectors across nine refusal classes.
`scripts/run-reader-qualification.sh` retains the 13-case version-by-version
result only after zero disagreements.

`tests/attestation.rs` creates a real certificate-v7 artifact, signs it with old
and rotated Ed25519 keys, and passes the detached envelope through Rust and the
independent Python reader. Both accept the two declared signing windows and
refuse tampering, a different certificate, cross-context replay, expiry, and
issuance outside the selected key window. The runner retains seven cases with a
two-second per-reader deadline.

`tests/witness.rs` then requires both readers to verify a separately signed,
hash-chained timestamp and digest-anchored revocation snapshot. It preserves
pre-revocation history and refuses inclusive revocation, tip rollback,
same-sequence equivocation, staleness, signature tampering, and chain omission
under the same two-second process deadline.

Witness-tip durability tests drive initialization, atomic advance, both pending
recovery boundaries, create-new backup, stale rejection, exact restore after
primary loss, and a primary/witness copy through the public store API. The same
tests run in pinned offline Linux arm64 and amd64 containers. A deterministic
seven-profile distribution model covers delay, loss, partition, outage,
budget exhaustion, and equivocation.

`tests/witness_endpoints.rs` creates real signed artifacts, starts separate
timestamp/revocation HTTP processes, fetches through bounded authenticated
transport, and verifies through the normal Rust witness boundary. It covers
healthy, restart, partition fallback, delay, drop, unauthorized, oversized,
outage, equivocal, and stale cases with deterministic cleanup.

`scripts/qualify-witness-operator-record.py` exercises the Post-M25 return
validator with one conforming synthetic record and thirteen fail-closed
mutations. This qualifies the handoff parser and integrity boundary, not an
operator, organization, endpoint, or independent result.

`tests/evaluation_cli.rs` invokes the real `telosieve evaluate` process through
configuration parsing, shadow verification, checker execution, certificate and
ledger persistence, and versioned report parsing. It verifies unchanged inputs
and no actuation record, then refuses unknown fields, future schema, mutation
mode, final or temporary config/output aliasing, long paths, oversized
configuration, and an oversized scenario before evidence output.
