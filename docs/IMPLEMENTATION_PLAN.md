# Implementation Plan

## M0 — executable research contract (unchecked)

- [ ] Define the finite service state machine and authority schemas.
- [ ] Register fault classes, invariants, metrics, seeds, and baseline behavior.
- [ ] Implement only enough simulator and checker to run one benign and one
  poisoned-goal scenario.
- [ ] Exit: deterministic replay plus a machine-readable refusal certificate.

## M1 — hypothesis protocol

Implement bounded hypothesis enumeration, provenance exclusion, and three
baselines: conventional reconciler, signed-history rollback, and invariant-gated
reconciler.

## M2 — adversarial evaluation

Run malicious/stale goals, omitted/forged observations, weakened invariants,
partitions, equivocation, parser differential, and correlated-fault probes. Publish
all negative results.

## M3 — productisation decision

Proceed only if the candidate improves poisoned-goal safety with quantified,
acceptable availability and complexity costs. Otherwise narrow or archive it.
