# Productisation Assessment

## Registered claim comparison

| Dimension | Telosieve evidence | Baseline comparison | Gate |
|---|---|---|---|
| Poisoned-goal safety | 0 unsafe approvals; explicit refusal | 2 baseline unsafe approvals | promising |
| Weakened-viability safety | 1 unsafe approval | 3 baseline unsafe approvals | stop-ship |
| False refusal | 0 across four signed fixtures | 0 observed | insufficient sample |
| Decision latency, one hypothesis | p50 21.9–23.0 ms | in-process baselines are materially cheaper | research-only |
| Decision latency, two hypotheses | p50 45.1–45.8 ms | approximately 2× one-hypothesis path | bounded but costly |
| Certificate size | 2,836–3,143 bytes | baseline-only record is smaller | acceptable for harness |
| Operational complexity | Rust planner plus bounded Python process per check | baselines remain single-process | added burden |

## Interpretation

The candidate demonstrates its intended poisoned-goal distinction in one bounded
fixture: it refuses where two baseline decisions are unsafe. That result does not
support productisation because the independently registered weakened-viability
fixture produces an unsafe Telosieve approval. The current fault declaration
excludes that failure, but a real operator cannot assume viability semantics are
incorruptible merely because their envelope is authentic.

Availability cost is not yet adverse in the four fixtures (`false_refusals = 0`),
but the sample is too small to estimate a frontier. Process isolation provides
semantic diversity at measurable latency and operator cost. No production
actuator, durable history service, cross-platform result, or independent
reproduction exists.

The evidence supports continued narrow research into multi-principal viability
and checker amortisation. It does not support an operator product, hosted control
plane, production adapter, or safety claim.
