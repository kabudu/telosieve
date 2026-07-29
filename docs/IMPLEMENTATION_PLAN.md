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
consumption and third-party organizational review remain unresolved.
