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
| unsafe approvals | 0 | 256 poisoned goals (0%) |
| false refusals | 0 | 256 safe goals (0%) |
| applied decisions | 256 | 512 |
| refused decisions | 256 | 512 |

Certificate v4's stable-key safety kernel removes the 48 previously retained
unsafe approvals without changing the oracle. When every viability domain is
weakened, deletion of `cluster/epoch` is rejected by the non-bypassable
continuity rule.

Certificate v5 adds two agreeing declared goal domains. Excluding either domain
retains the same authenticated desired transition, removing the 64 certificate-v4
false refusals. Authenticated disagreement fails closed and is not represented in
this agreeing-goal state space.

## Decision impact

The expanded evidence resolves the reproduced unsafe approvals but does not
reverse the existing **narrow / no-productisation** decision:

- no unsafe approval remains in the declared 512-scenario state space;
- no false refusal remains in the agreeing-goal safe slice;
- organizational goal-domain independence and disagreement availability remain
  unmeasured; and
- the result remains a bounded model, not a production reliability estimate.

The experiment supports continued private protocol research only. It does not
justify an actuator, hosted control plane, public release, or safety claim.
