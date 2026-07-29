# Soundness Case

## Conditional claim

If authority envelopes are authentic, the declared fault model contains the actual
fault, the checker semantics match the service model, and the actuator is atomic,
then Telosieve applies only transitions satisfying the versioned viability
invariants under every surviving hypothesis.

## Argument obligations

- All consumed bytes are bound to signed, canonical envelopes.
- Suspected evidence cannot influence a plan under its hypothesis.
- Planner and checker failures are not silently correlated.
- “Safe under all hypotheses” is evaluated over a finite, complete hypothesis set.
- The actuator either commits the certified transition or returns observable
  failure without hidden partial effects.

## Known gaps

Authenticity is not truth. A shared compromised signer, poisoned viability
specification, incomplete phenotype, semantic parser differential, or fault beyond
the budget can invalidate the argument. Liveness is intentionally sacrificed when
evidence is ambiguous. These are testable assumptions, not solved problems.
