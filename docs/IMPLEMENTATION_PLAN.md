# Implementation Plan

## M0 — executable research contract (complete)

- [x] Define the finite service state machine and authority schemas.
- [x] Register fault classes, invariants, metrics, seeds, and baseline behavior.
- [x] Implement only enough simulator and checker to run one benign and one
  poisoned-goal scenario.
- [x] Exit: deterministic replay plus a machine-readable refusal certificate.

Evidence: `scenarios/benign.json`, `scenarios/poisoned-goal.json`, and
`tests/m0.rs`. M0 supports a declared budget of zero or one fault and rejects a
configuration whose finite hypothesis count exceeds `maximum_hypotheses`.

## M1 — hypothesis protocol

- [x] Implement bounded general hypothesis enumeration and provenance exclusion.
- [x] Add signed-history rollback and invariant-gated reconciler baselines.
- [x] Replace shared Rust/Serde planner-checker semantics with a diverse checker
  boundary and demonstrate parser/model differential tests.
- [x] Exit: every protocol requirement has behavioural evidence and all three
  baselines replay through the public harness.

## M2 — adversarial evaluation

- [x] Run malicious/stale goals, omitted/forged observations, weakened invariants,
  partitions, equivocation, parser differential, and correlated-fault probes.
- [x] Measure hypothesis growth, compute cost, recovery latency, unsafe approvals,
  and false refusals against every baseline.
- [x] Exit: retain reproducible raw results and report all negative results.

## M3 — productisation decision

- [x] Compare the registered safety claim with quantified availability and
  complexity costs.
- [x] Refresh novelty, name, security, soundness, and release diligence.
- [x] Exit: explicitly proceed, narrow, or archive the project based on evidence.

Decision: **narrow**. Productisation and public release are blocked. See
[PRODUCTISATION_DECISION](PRODUCTISATION_DECISION.md).

## Post-M3 — narrowed research (not productisation)

- [x] Define multi-principal or explicitly suspectable viability semantics,
  preregistering the fault model and falsifiers.
- [x] Replace per-hypothesis process spawning with a bounded checker service or
  batch boundary without reducing semantic diversity.
- [x] Implement an authenticated, replayable history baseline rather than the
  current fixture-level proxy.
- [x] Obtain independent environment/toolchain reproduction of the registered
  experiments.

## Post-M4 — evidence expansion

- [ ] Obtain third-party organizational reproduction and security review.
- [x] Test correlated viability-principal faults and document fault-domain
  independence requirements.
- [x] Prototype a durable rollback-resistant history anchor.
- [x] Measure the safety/availability frontier over a larger generated state
  space.

Evidence: 512 authenticated generated scenarios and per-cell results in
[GENERATED_STATE_SPACE](GENERATED_STATE_SPACE.md).

## Post-M5 — reproduced unsafe-approval remediation

- [x] Add a viability-independent stable-key continuity invariant to both
  checker implementations.
- [x] Preserve value updates and additions while refusing implicit key deletion.
- [x] Re-run retained fixtures and the generated state space without changing
  their safety oracles.
- [x] Exit: zero unsafe approvals across retained evidence, quantified refusal
  cost, versioned certificates/checkers, and explicit residual bounds.

Evidence: [STABLE_KEY_SAFETY_KERNEL](STABLE_KEY_SAFETY_KERNEL.md). Productisation
remained blocked at that milestone by finite-model limits, false refusals,
deletion semantics, and independent-review gates.

## Post-M6 — goal-domain availability

- [x] Authenticate multiple agreeing goal principals and declare their fault
  domains when goal faults are in scope.
- [x] Exclude complete goal domains per bounded hypothesis and require a
  surviving goal principal.
- [x] Reject authenticated disagreement and invalid domain mappings before
  planning.
- [x] Exit: unchanged 512-scenario oracle, zero unsafe approvals, zero false
  refusals, quantified hypothesis/latency costs, and explicit independence limits.

Evidence: [MULTI_PRINCIPAL_GOALS](MULTI_PRINCIPAL_GOALS.md). Third-party
organizational reproduction/security review remains unchecked and cannot be
self-certified by this repository.

## Post-M7 — explicit authorized deletion

- [x] Add separately signed deletion evidence bound to the exact goal and
  phenotype tip.
- [x] Require agreeing deletion principals, complete fault-domain mappings, and
  a surviving authorization domain.
- [x] Enforce exact deletion sets independently in Rust and Python and expose
  per-hypothesis authorization in certificate v6.
- [x] Exit: authorized deletion applies, ordinary omission and replay/overbreadth
  refuse, existing 512-case safety/availability remains 0/0, and costs/bounds
  are retained.

Evidence: [AUTHORIZED_DELETION](AUTHORIZED_DELETION.md). Durable one-shot
consumption and third-party organizational review remained unresolved.

## Post-M8 — durable deletion consumption

- [x] Derive an auditable identifier from the exact authenticated deletion
  envelope set and expose it in certificate v7.
- [x] Atomically commit history-anchor advancement and applied deletion
  consumption in one versioned durable state.
- [x] Fail closed on replay, corruption, legacy state, stale locks, history
  conflicts, and the bounded ledger's capacity limit.
- [x] Preserve deterministic stateless research replay and document safe
  authorization burn when later evidence persistence fails.
- [x] Exit: the anchored authorized fixture applies once, its identical replay
  fails before new evidence is emitted, and existing local validation passes.

Evidence: [DURABLE_DELETION_CONSUMPTION](DURABLE_DELETION_CONSUMPTION.md).
Third-party organizational reproduction/security review remains an external
unchecked gate.

## Post-M9 — transactional local reference actuator

- [x] Add explicit initialization from a verified authenticated phenotype.
- [x] Require commit-time equality with observed service state and the certified
  transition precondition.
- [x] Atomically commit service state, authenticated history, and deletion
  consumption in one bounded local store.
- [x] Emit certificate-v8 actuation receipts while preserving certificate-v7
  deterministic research runs.
- [x] Exercise apply, refusal, replay, contention, corrupt/oversized state,
  post-commit evidence failure, and the real CLI lifecycle.
- [x] Exit: the local reference service changes only after an applied certified
  plan and stale retry cannot duplicate the change.

Evidence: [LOCAL_REFERENCE_ACTUATOR](LOCAL_REFERENCE_ACTUATOR.md). Real production
service integration, platform qualification, and external organizational review
remain unresolved.

## Post-M10 — local actuator recovery qualification

- [x] Add monotonic generations and a separate pending/committed recovery
  witness around every actuator mutation.
- [x] Add bounded create-new backup, exact-latest restore, and stale/tampered
  backup rejection.
- [x] Preserve deletion history through an explicit crash-safe schema-v1 upgrade.
- [x] Resolve commit, initialization, and upgrade interruption without guessing.
- [x] Stress concurrent writers and 16 forced terminations, and retain
  50-iteration backup/restore/recovery measurements.
- [x] Exit: each tested interruption recovers to one exact committed generation
  or fails closed; stale restore cannot roll the witness back.

Evidence: [ACTUATOR_RECOVERY](ACTUATOR_RECOVERY.md). At Post-M10, qualification
was limited to the tested macOS/aarch64 single-host filesystem. Whole-disk
rollback, other platforms, external service integration, and independent review
remained open.

## Post-M11 — Linux recovery qualification

- [x] Run recovery-state and forced-termination tests on Linux arm64 and amd64.
- [x] Use a pinned, network-disabled multi-architecture container with the
  repository mounted read-only.
- [x] Put actuator mutations on Docker-managed Linux volumes rather than tmpfs.
- [x] Retain architecture, image, filesystem, object-size, and latency evidence.
- [x] Exit: both architectures recover every tested termination to an exact
  witnessed generation; emulated timing and VM/storage limits remain explicit.

Evidence: [ACTUATOR_RECOVERY](ACTUATOR_RECOVERY.md). This removes the
macOS-only software-path gap for the tested Linux VM/volume boundary. Bare-metal
Linux, power-loss persistence, whole-disk rollback, external service integration,
and independent review remain open.

## Post-M12 — key and identity lifecycle

- [x] Define authority-key rotation, revocation, expiry, and compromised-key
  recovery without invalidating historical certificates.
- [x] Bind lifecycle statements to authority kind, subject, sequence, and
  predecessor state.
- [x] Reject revoked or superseded keys for new transitions while retaining
  deterministic historical verification.
- [x] Exercise stale rotation, rollback, equivocation, partial availability,
  emergency revocation, and bounded state growth.

Evidence: [KEY_LIFECYCLE](KEY_LIFECYCLE.md). Lifecycle state is bounded and
authenticated but its roots and tips remain trusted scenario configuration, not
a durable organizational identity service.

## Post-M13 — shadow-mode external adapter

- [ ] Name one external target and define a read-only phenotype/goal mapping
  without mutation credentials.
- [ ] Bind observations to resource versions and reject schema or concurrency
  ambiguity.
- [ ] Exercise drift, partial reads, stale watches, identity mismatch, and
  bounded observation size.
- [ ] Retain shadow decisions and operator-facing refusal reasons without adding
  production actuation.
