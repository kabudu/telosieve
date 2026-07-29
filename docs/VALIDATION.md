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
