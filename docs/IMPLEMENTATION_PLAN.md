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

Implement bounded hypothesis enumeration, provenance exclusion, and three
baselines: conventional reconciler, signed-history rollback, and invariant-gated
reconciler. Replace M0's shared Rust/Serde representation with genuinely diverse
planner/checker parsing and semantics before making an independence claim.

## M2 — adversarial evaluation

Run malicious/stale goals, omitted/forged observations, weakened invariants,
partitions, equivocation, parser differential, and correlated-fault probes. Publish
all negative results.

## M3 — productisation decision

Proceed only if the candidate improves poisoned-goal safety with quantified,
acceptable availability and complexity costs. Otherwise narrow or archive it.
