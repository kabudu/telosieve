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
