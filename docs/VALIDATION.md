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
