# Validation

## Registered hypothesis

Against the same bounded faults, provenance-separated multi-authority checking
will approve fewer unsafe repairs than (A) a conventional reconciler, (B) a
signed-history reconciler, and (C) an invariant-gated reconciler, while reporting
its availability cost.

Primary metric: unsafe approvals per scenario. Secondary metrics: false refusal,
recovery latency, hypothesis count, compute cost, and diagnostic fidelity.

The deterministic state space will be exhaustively explored where feasible and
property-tested otherwise. Seeds, scenarios, implementation versions, and raw
results will be retained. A single unsafe approval inside the stated model blocks
productisation. Results outside the model cannot support the core claim.

## Falsifiers

- a baseline matches safety with lower refusal and complexity;
- provenance separation has no causal effect in ablation;
- the checker cannot remain meaningfully independent;
- state-space growth prevents useful bounded decisions;
- safe behavior depends on undeclared operator knowledge.

## M0 registration

The executable scenarios fix seed `7`, evaluation time, three-replica starting
state, authority keys, fault declaration, expected decision, and viability rules.
The registered viability invariants require exactly three replicas, replica
consensus, and `cluster/epoch = 7` on every replica. Certificates report hypothesis
count, unsafe approvals, false refusals, and the conventional-reconciler baseline
verdict. Wall-clock latency and compute-cost benchmarking begin in M1 because
including nondeterministic timing in M0 certificates would break byte replay.

## Authoritative local CI

While the repository remains private, all milestone validation runs through
`./scripts/ci-local.sh`. It checks formatting, strict static analysis, the complete
test suite, warning-free documentation, locked offline dependency resolution,
Cargo metadata, repository-owned documentation validation, diff hygiene,
placeholder markers, and the absence of hosted CI workflow files. Pull requests
record the command and result; no hosted check is expected or implied.

M1 certificates include conventional convergence, signed-history rollback to the
authenticated observed consensus, and invariant-gated convergence baselines. Each
records its decision, proposed transition, checker verdict, and unsafe-approval
status under the same scenario.

## M2 benchmark

`cargo run --release --example benchmark -- scenarios/*.json` measures 20
iterations per authenticated scenario. It reports p50/p95 end-to-end decision
latency, hypothesis count, certificate bytes as a deterministic work/space proxy,
Telosieve unsafe approvals and false refusals, and unsafe approvals for every
baseline. Raw results are retained in `results/m2-benchmark.json`; timings are
machine-specific observations rather than protocol guarantees.

The registered run exposes one stop-ship negative result: with authenticated
weakened viability rules outside the declared fault model, Telosieve applies the
poisoned goal (`unsafe_approvals = 1`). This confirms the documented viability
authority dependency and blocks productisation; it is not treated as an M2 pass.

## Post-M3 viability remediation

The original M2 result remains retained above. The follow-up fault model registers
independently signed viability principals and permits one listed fault domain to
be semantically faulty. Every surviving principal must independently approve the
common transition. The exact bound, failure behavior, and falsifiers are in
[VIABILITY_FAULT_MODEL](VIABILITY_FAULT_MODEL.md).

The retained follow-up run is `results/post-m3-viability-benchmark.json`. It
refuses the weakened-viability transition with zero unsafe approvals while the
benign multi-principal fixture still applies with zero false refusals. This
removes the registered unsafe approval inside the original one-principal model.
The subsequent domain model supersedes that bound and is reported below.

The authenticated-history follow-up is retained in
`results/post-m3-history-benchmark.json`. It replaces the snapshot proxy with a
bounded signed predecessor chain and trusted tip anchor without changing any
registered safety decision.

The separate Linux reproduction is documented in
[INDEPENDENT_REPRODUCTION](INDEPENDENT_REPRODUCTION.md). Its deterministic outputs
match the macOS run; third-party organizational reproduction remains a
productisation gate.

## Correlated fault domains

The correlated experiment is documented in
[CORRELATED_FAULTS](CORRELATED_FAULTS.md). Two weakened principals sharing one
domain are tolerated when a strict independent domain survives. Weakening every
domain produced one certificate-v3 unsafe approval outside the one-domain bound.

## Stable-key safety kernel

Certificate v4 adds a non-bypassable rule that transitions retain every key
present on every current replica. The independent Rust and Python checkers agree
on this boundary. The original oracles remain unchanged; the cross-domain
fixture and all 512 generated scenarios now report zero unsafe approvals. The
64 generated false refusals remain. Scope, complexity, compatibility, and
falsifiers are documented in
[STABLE_KEY_SAFETY_KERNEL](STABLE_KEY_SAFETY_KERNEL.md).

## Multi-principal goal availability

Certificate v5 assigns two agreeing goal issuers to distinct declared domains.
The unchanged 512-scenario oracle now reports zero unsafe approvals and zero
false refusals. Valid but divergent goal envelopes fail closed, invalid mappings
are rejected, and hypothesis growth remains explicitly bounded. This does not
establish organizational independence or availability during disagreement. See
[MULTI_PRINCIPAL_GOALS](MULTI_PRINCIPAL_GOALS.md).

## Authorized deletion

Certificate v6 requires separate, agreeing deletion authorities bound to the
exact goal and phenotype tip. The authorized fixture applies one exact deletion;
the same omission without evidence refuses. Replay into another goal, overbroad
authorization, invalid mappings, and loss of every deletion domain fail closed.
The existing 512-scenario oracle remains zero unsafe approvals and zero false
refusals. See [AUTHORIZED_DELETION](AUTHORIZED_DELETION.md).

Certificate v7 adds anchored one-shot evidence: the first exact authorization
applies and is atomically recorded with the history anchor; identical replay
fails without another ledger record. Capacity, legacy-state, lock, corruption,
and post-commit evidence-failure tests exercise the bounded failure paths. See
[DURABLE_DELETION_CONSUMPTION](DURABLE_DELETION_CONSUMPTION.md).

## Transactional local reference actuator

Certificate v8 is emitted only after the local reference store commits. Tests
verify an applied benign plan changes the operator-visible state once, a refusal
does not change it, stale replay fails before another ledger record, and deletion
plus consumption commit together. Corrupt, oversized, and locked stores fail
closed. A retained failure-path test demonstrates applied-but-unreported state
when evidence persistence fails, and the CLI lifecycle exercises initialization,
application, and readback through the executable boundary. See
[LOCAL_REFERENCE_ACTUATOR](LOCAL_REFERENCE_ACTUATOR.md).

## Local actuator recovery qualification

Schema-v2 tests inject interruption after pending-witness persistence and after
primary-state replacement; recovery retains or commits exactly the witnessed
generation. Additional tests cover interrupted initialization and v1 upgrade,
temporary cleanup, stale/tampered backup, exact restore after primary loss,
full-ledger refusal, and concurrent writers.

The executable stress test kills 16 `apply-local` processes at 0–60 ms delays.
After process death and explicit stale-lock removal, each case must recover to
generation zero/old values/no receipt or generation one/new values/a receipt.
Backup, restore, and consistent recovery latency are measured over 50 iterations.
See [ACTUATOR_RECOVERY](ACTUATOR_RECOVERY.md).

The same nine recovery-state tests, 16-process termination stress test, and
50-iteration benchmark also pass in a pinned network-disabled Linux container on
native arm64 and emulated amd64. Actuator state resides on a Docker-managed
`ext2/ext3`-reported volume. This is cross-architecture VM/filesystem evidence,
not bare-metal, power-loss, or hardware-performance qualification.

## Authority key lifecycle

The rotated-goal fixture applies using a recovery-root-authorized fresh key and
binds the lifecycle chain, root, and trusted tip into the certificate. Unit and
public-boundary tests reject superseded, expired, revoked, reused,
non-canonical, wrong-kind, tampered, partially configured, equivocating,
rolled-back, and oversized lifecycle evidence. An old phenotype record remains
verifiable after rotation while current evidence cannot use its superseded key.
See [KEY_LIFECYCLE](KEY_LIFECYCLE.md).

## Kubernetes shadow adapter

Certificate v9 binds the retained snapshot digest, target UID, resource
versions, and capture time while leaving actuation absent. Mapping and CLI tests
cover drift, partial/stale observations, replacement identity, schema/context
and authority mismatch, resource bounds, output aliasing, deterministic evidence,
and unchanged inputs. See [KUBERNETES_SHADOW](KUBERNETES_SHADOW.md).

## Incident drills

Seven offline drills execute corruption, witness-loss, capacity, lock, upgrade,
key-compromise, and lifecycle-rollback failure paths and retain exact commands
and expected outcomes. See [INCIDENT_DRILLS](INCIDENT_DRILLS.md).

## Bounded parser corpora

Four deterministic corpora exercise valid round trips, truncations, field-type
confusion, missing or unknown fields, enum errors, and applicable resource
bounds. Each corpus is limited to 16 cases and 2 MiB total input. The retained
`telosieve.parser-corpora/v1` result reports four passing corpora, four minimized
rejection fixtures, and zero newly discovered discrepancies. See
[PARSER_CORPORA](PARSER_CORPORA.md).

## Independent-assessment handoff

The assessor manifest freezes the Post-M15 source commit, nine SHA-256-bound
artifacts, three exact commands, explicit claim boundaries, and unresolved
release blockers. A fresh local clone at that commit passes authoritative local
CI and reproduces the incident and parser-corpus aggregates byte-for-byte. The
retained verifier result records that no hosted CI or production credential was
required. See [ASSESSOR_HANDOFF](ASSESSOR_HANDOFF.md).

## Dependency provenance and advisory audit

The deterministic dependency inventory contains 44 exact locked packages, 43
third-party checksums, declared license expressions, sources, and directness.
The retained cargo-audit result binds that lockfile to a named RustSec commit and
reports zero known vulnerabilities, warnings, or accepted findings. Local CI
regenerates the inventory offline and rejects an advisory result older than 30
days. See [SUPPLY_CHAIN](SUPPLY_CHAIN.md).

## Trusted time and recovery-root ceremony

Enrolled key lifecycles now require an inclusive trusted-time window no wider
than 300 seconds around evaluation. Focused tests prove exact exclusive-expiry
and inclusive-revocation behavior and refuse rollback, forward-jump, and
over-wide windows. The trusted-time assertion is content-bound into certificate
authority evidence.

The credential-free recovery-root rehearsal uses a fixed 2-of-3 profile and a
bounded general 3–7 participant model. The retained result is emitted only after
success/exclusion and duplicate, missing, divergent, stale, veto, and
excluded-compromised failure tests pass. This is deterministic local protocol
evidence, not authenticated time, participant identity, private-key custody, or
organizational independence. See
[RECOVERY_ROOT_CEREMONY](RECOVERY_ROOT_CEREMONY.md).

## Protocol compatibility and migration

The bounded compatibility corpus preserves legacy unenrolled scenarios and
current enrolled trusted-time scenarios while proving that an enrolled scenario
without trusted time parses only for diagnosis and then refuses verification.
Unknown scenario fields and future authority/lifecycle versions fail closed.

Actual v7 stateless and v8 actuator certificates plus the retained v9 shadow
certificate pass the supported-certificate boundary. Unknown versions,
top-level fields, confused version/extension shapes, and inputs beyond 2 MiB are
rejected. The two exact vectors pass and are retained in
`results/compatibility-corpus.json`. See
[PROTOCOL_COMPATIBILITY](PROTOCOL_COMPATIBILITY.md).

## Real Kubernetes end to end

The disposable kind qualification runs the real evaluation binary, kubectl,
service-account authentication, Kubernetes API server, RBAC, StatefulSet, Pods,
and two authenticated observation relays. It proves one healthy evidence
lifecycle, eight concurrent relay-path evaluations, and three no-evidence
refusals for authority mismatch, API outage, and relay outage, then removes the
relays and cluster. The run is local
project-controlled evidence, not managed-cluster or independent qualification.

## Private bundle signature boundary

The real CLI derives only the public key, signs exact bundle bytes, and verifies
through a separately written trust file. Its integration test accepts the valid
path and refuses byte tamper, expired evaluation time, and non-owner-only key
material. Unit tests additionally refuse key substitution and context change.
All signing keys are ephemeral test inputs; operational identity, custody, exact
candidate signing, and independent assessment remain open gates.

Bundle qualification also builds otherwise identical version 3 bundles with two
source commits and requires different bundle digests. A malformed commit refuses
before publication. This proves source-identity binding, not that a supplied
commit was reviewed or that an operational ceremony occurred.

## Reproducible candidate build

Two isolated non-incremental locked/offline release builds produce byte-identical
binaries on the current host. Qualification records bounded build resources and
detects a deliberately altered comparison binary. This is same-host
project-controlled evidence, not hermetic or independent reproduction.

## Certificate evidence attestation

Detached certificate attestation binds exact bytes to a context, signer/key,
issuance, and exclusive expiry under domain-separated Ed25519. Old and new
rotation keys both verify within their declared signing windows without changing
retained unsigned certificates.

Rust and Python accept the old/new vectors and refuse signature tampering,
another valid certificate, cross-context replay, expiry, and issuance outside
the signer window. The retained `telosieve.attestation-qualification/v1` result
reports seven passes and zero disagreements within the 2 MiB certificate,
64 KiB attestation, eight-key, 30-day, and two-second limits. See
[CERTIFICATE_ATTESTATION](CERTIFICATE_ATTESTATION.md).

## Timestamp and revocation witnesses

The Rust and Python readers agree on pre-revocation historical acceptance and
refuse inclusive revocation, timestamp-tip rollback, same-sequence revocation
equivocation, stale snapshots, timestamp-signature tampering, and omitted chains.
The retained `telosieve.witness-qualification/v1` result reports seven passes,
zero disagreements, 64-entry/64-KiB limits, and a two-second reader deadline.
See [ATTESTATION_WITNESSES](ATTESTATION_WITNESSES.md).

## Witness durability and availability

The dual-tip store passes previous/next interrupted recovery, stale-backup
rejection, exact-latest restore after primary loss, independent-path copy, and
rollback/equivocation refusal on macOS and pinned network-disabled Linux arm64
and amd64 containers. The seven-profile deterministic availability result
records three available and four refused outcomes within three attempts and a
250 ms virtual budget. See [WITNESS_DURABILITY](WITNESS_DURABILITY.md).

## Isolated witness endpoints

Separate authenticated timestamp and revocation HTTP processes serve immutable
real artifacts to the bounded client harness. Healthy, restart, and partition
fallback paths verify cryptographically; delay, drop, unauthorized, oversized,
outage, equivocal, and stale paths refuse. The retained ten-case result uses a
250 ms request timeout, two-second scenario deadline, 4 KiB headers, 64 KiB
bodies, two providers, and three attempts. See
[WITNESS_ENDPOINT_HARNESS](WITNESS_ENDPOINT_HARNESS.md).

## Independent witness operator handoff

The frozen Post-M25 request binds eight M24 source artifacts, three commands,
three success cases, and seven refusal cases. Its returned-record qualification
accepts one synthetic conforming record and refuses thirteen request, control,
origin, outcome, CI, digest, path, time, and schema faults. This validates only
the repository-owned handoff boundary. See
[WITNESS_OPERATOR_HANDOFF](WITNESS_OPERATOR_HANDOFF.md).
The retained aggregate explicitly sets `independent_evidence` to false.

The producer-isolation lane additionally runs two relays under distinct
non-root Linux UIDs and client groups in a pinned offline container. It verifies
authorized evaluator access and kernel-enforced refusal of unrelated and peer
producer identities. This is single-host, project-controlled evidence and does
not qualify systemd, real credentials, separate administration, or producer
truth.

## Versioned evaluation CLI

The real binary accepts one v1 configuration, validates a bounded exported
snapshot through the existing cryptographic/checker path, persists certificate
and ledger evidence, and emits a v1 report bound to the certificate digest.
Inputs remain byte-identical and the certificate has no actuation record. Nine
field, schema, mode, path, collision, configuration-size, and scenario-size
failures produce no success report; the scenario file boundary is capped at
2 MiB for all CLI paths. See [EVALUATION_CLI](EVALUATION_CLI.md).

## Live Kubernetes collector

The real `telosieve evaluate` process accepts v5 live configuration and drives a
separate fake `kubectl` executable through the production subprocess boundary.
The healthy case proves the exact four-call `get` protocol, output evidence,
report schema, and absence of mutation verbs. Controller drift, unready Pod,
wrong owner, unsupported selector expression, nonzero process exit, output over
1 MiB, and a process exceeding five seconds all fail without certificate or
ledger output. This is a
project-controlled integration harness. Post-M30 adds a separate disposable
real-cluster qualification without claiming managed or independent coverage.
Post-M39 additionally refuses forged, disagreeing, malformed, oversized, or
timed-out producer envelopes and exercises two signed producer processes
against the real local cluster.

## Evaluation installation lifecycle

`scripts/run-evaluation-lifecycle-qualification.py` uses the real locally built
debug binary from outside the repository working directory through install,
version execution, a complete evaluation using the embedded checker, evidence creation, bounded
backup, configuration upgrade, verified rollback, and exact-confirmation
uninstall. The active binary/configuration pair changes through one atomic
symlink, while evidence remains byte-identical. Reinstallation, a tampered
backup, incorrect uninstall confirmation, a relative root, duplicate config,
concurrent operation, symlinked input/evidence file or directory, and an in-root backup refuse
without changing the active release. This is local-filesystem lifecycle
evidence, not
power-loss, package-manager, service-manager, or distribution qualification.

## Operator diagnostics

The diagnostics qualification installs a managed evaluator, writes a unique
secret into a uniquely named evidence file, exports through the public tool, and
validates the exact recursive v1 allowlist. Neither secret, file name, path,
configuration value, nor environment is present. Existing output, evidence
symlink, permission drift, and an in-root destination refuse without an export.
This proves the project-owned disclosure contract, not anonymity of digests or
independent privacy assessment.

## Private bundle qualification

The bundle qualification builds the fixed three-mode private ZIP twice and
requires exact byte identity; verifies every entry, capability, contract,
configuration, test-plan, and unsigned-profile relationship; refuses four
capability process faults; kills a build before publication; confirms no partial
output; and recovers the identical digest. It records local platform, wall time,
peak child RSS, and output size bounds. This is local macOS process/filesystem
evidence, not signing, power-loss, Linux, Kubernetes-load, distribution, or
independent qualification.

## Compatibility consumer qualification

The independent Python reader and Rust compatibility boundary agree on four
accepted version vectors and ten refusal classes. The accepted inputs are an
actual v7 stateless certificate, actual v8 local-actuator certificate, and the
retained v9 Kubernetes shadow certificate, and a v10 OpenTofu envelope. Future versions, unknown or missing
fields, wrong types, out-of-range integers, cross-version extensions, duplicate
keys, malformed JSON, and oversized input all refuse in both implementations.

The retained `telosieve.reader-qualification/v1` aggregate reports 15 passes and
zero disagreements within 16-case and 2 MiB bounds. This is implementation
diversity under project control, not independent assessment. See
[PROTOCOL_COMPATIBILITY](PROTOCOL_COMPATIBILITY.md).
