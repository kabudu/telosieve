# Productisation Decision — Narrow

Date: 2026-07-29

## Decision

Telosieve will continue only as a private, narrowly scoped research project.
Productisation and public release are blocked.

The M2 evidence preserves a useful research question: under the registered
poisoned-goal fixture, Telosieve refused repair while two baselines made unsafe
approvals. It does not establish a safety result. Under authenticated but
weakened viability constraints, Telosieve made one unsafe approval. That is a
stop-ship failure because authentic provenance does not imply sound semantics.

## Consequences

The repository may continue to investigate the bounded protocol, but it must not:

- claim that Telosieve is safe, production-ready, or generally Byzantine
  resilient;
- add a production actuator, operator control plane, public package, hosted CI,
  or deployment workflow;
- publish a research release or tag without a new explicit release decision;
- treat the four signed fixtures or zero observed false refusals as statistically
  sufficient validation.

Any later proposal to proceed must first eliminate the weakened-viability unsafe
approval under a preregistered fault model, quantify the availability frontier,
demonstrate an operationally credible checker boundary, and obtain independent
reproduction and refreshed diligence.

## Narrowed research scope

The next research cycle is limited to:

1. multi-principal or explicitly suspectable viability semantics;
2. amortising the diverse checker without weakening fail-closed behavior;
3. replacing the current fixture-level history proxy with an authenticated,
   replayable history baseline; and
4. independent reproduction of the registered experiments.

Failure to remove the unsafe approval, or evidence that the resulting availability
or complexity cost is impractical, should archive the project rather than expand
its scope.

## Post-decision evidence

The multi-principal viability experiment documented in
[VIABILITY_FAULT_MODEL](VIABILITY_FAULT_MODEL.md) removes the registered unsafe
approval under a one-principal fault bound without refusing the registered benign
update. This satisfies one reopening condition, but does not reverse the decision:
correlated faults, operational independence, the expanded latency cost, broader
availability evidence, and independent reproduction remain unresolved.

## Evidence basis

- [M2 Adversarial Results](M2_RESULTS.md)
- [Productisation Assessment](PRODUCTISATION_ASSESSMENT.md)
- [Diligence Refresh](DILIGENCE_REFRESH_2026-07-29.md)
- [Validation and falsification plan](VALIDATION.md)
