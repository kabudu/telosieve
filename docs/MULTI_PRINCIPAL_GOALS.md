# Multi-Principal Goal Evidence

Date: 2026-07-29

## Problem and acceptance criteria

Certificate v4 had one authenticated goal principal. Under a one-fault model,
suspecting that principal replaced a safe new goal with the observed state (or no
plan under partition). This created 64 false refusals among 256 safe generated
scenarios.

Certificate v5 is accepted only if:

- the independent oracle and all 512 expected decisions remain unchanged;
- unsafe approvals remain zero;
- false refusals fall below the v4 count of 64;
- every suspectable goal issuer has exactly one declared non-empty fault domain;
- authenticated goal disagreement, missing mappings, unknown mappings, and loss
  of every goal domain fail closed;
- hypothesis count remains bounded before checker work; and
- signing-key and domain labels are not represented as proof of organizational
  independence.

## Protocol

Scenarios may carry multiple goal envelopes with distinct issuers. All envelopes
are independently signature-, freshness-, lineage-, subject-, and schema-checked.
Their decoded goal values must agree exactly; disagreement is rejected before
planning.

When goal is suspectable, `goal_fault_domains` maps every current goal issuer to
one domain. A hypothesis excludes every issuer in a suspected domain. Planning
continues only if at least one agreeing goal issuer survives. Unknown, missing,
empty, or inapplicable mappings are configuration errors.

The finite target count now uses goal domains, viability domains, and the
phenotype authority. Work remains bounded by `maximum_hypotheses`; the registered
one-fault profiles require at most five hypotheses.

## Evidence

The fixture generator now signs every goal with `goal-lab` and `goal-review`,
assigned to separate declared domains when goal faults are in scope. This is a
modelled separation only.

The unchanged-oracle generated run reports:

| Measure | Certificate v4 | Certificate v5 |
|---|---:|---:|
| scenarios | 512 | 512 |
| unsafe approvals | 0 | 0 |
| false refusals | 64 | 0 |
| applied safe goals | 192 | 256 |
| refused poisoned goals | 256 | 256 |

Focused adversarial coverage rejects authenticated disagreement by combining two
individually valid, differently valued goal envelopes. It also rejects missing
goal-domain mappings and exercises the expanded 16-hypothesis two-fault bound.

The five-fixture benchmark records p50 latency of 14.0–14.4 ms on this machine.
Goal-suspect scenarios increase from two to three hypotheses, and combined
goal/viability scenarios from four to five. Timing is observational; hypothesis
count is the deterministic cost bound.

Raw evidence is retained in `results/generated-state-space.json` and
`results/multi-principal-goal-benchmark.json`.

## Residual risks

Agreement can be correlated: copied policy, shared authorship, common deployment,
or shared signing custody can make two domains one real failure domain. The
harness cannot attest independence. Divergent valid goals fail closed, so
availability during legitimate rollout disagreement is unmeasured and currently
zero. Third-party organizational reproduction/security review and authorized
deletion semantics remain productisation gates.
