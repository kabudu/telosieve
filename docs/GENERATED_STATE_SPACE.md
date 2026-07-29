# Generated Safety/Availability State Space

Date: 2026-07-29

## Question and bound

This experiment measures the safety/availability frontier after adding explicit
viability fault domains. It exhaustively evaluates the Cartesian product of:

- 8 deterministic payload seeds;
- safe and poisoned goals;
- consensus and partitioned current phenotypes;
- strict and weakened lab/review viability domains;
- declared fault budgets 0 and 1; and
- viability-only versus goal-and-viability suspicion.

This is 512 authenticated scenarios in 32 cells. It is exhaustive only over
those finite dimensions. It is not a statistical sample of real failures, a
proof over arbitrary states, or evidence that the two named domains are
operationally independent.

The oracle is deliberately external to the protocol decision: a goal is safe
exactly when it retains the registered `cluster/epoch = 7` invariant. Payload
seeds vary signed desired values without changing that oracle.

## Reproduction

Run:

```console
cargo run --locked --offline --example state_space -- results/generated-state-space.json
```

`cargo test --all-targets` independently checks the aggregate counts. The raw
machine-readable cells are retained in
`results/generated-state-space.json`.

## Results

| Measure | Count | Relevant denominator |
|---|---:|---:|
| scenarios | 512 | 512 |
| safe goals | 256 | 512 |
| poisoned goals | 256 | 512 |
| unsafe approvals | 48 | 256 poisoned goals (18.75%) |
| false refusals | 64 | 256 safe goals (25%) |
| applied decisions | 240 | 512 |
| refused decisions | 272 | 512 |

The unsafe approvals occur at the known boundary where every viability domain
is weakened. Viability-only suspicion cannot recover when no strict domain
survives. A zero fault budget likewise cannot exclude bad evidence.

The false refusals occur with goal-and-viability suspicion at fault budget one.
The goal-suspected hypothesis proposes the observed consensus (or no transition
under partition), while the no-fault hypothesis proposes the new safe goal.
Telosieve therefore cannot identify one common transition. This is a real
availability cost of broadening the fault model, not a checker error.

## Decision impact

The expanded evidence resolves the measurement gap but strengthens the existing
**narrow / no-productisation** decision:

- weakening every viability domain still permits unsafe approval;
- covering goal faults introduces a measured 25% false-refusal rate over the
  registered safe slice; and
- the result remains a bounded model, not a production reliability estimate.

The experiment supports continued private protocol research only. It does not
justify an actuator, hosted control plane, public release, or safety claim.
