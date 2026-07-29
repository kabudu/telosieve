# Viability Fault Model

## Registered bound

Each viability principal supplies a separately signed viability envelope under a
distinct issuer key. When `viability` is suspectable, the hypothesis engine treats
each issuer as a separate fault target. `maximum_faults = 1` therefore means that
at most one listed authority principal is semantically faulty, not merely that
one envelope has an invalid signature.

The registered fixtures use `viability-lab` and `viability-review`. The weakened
fixture permits one fault among the goal and either viability issuer, producing
four hypotheses within `maximum_hypotheses = 4`.

## Decision invariant

A transition may be applied only when every bounded hypothesis produces the same
transition and every viability principal surviving that hypothesis independently
approves it. A suspected viability issuer is excluded from checking. If no
viability principal survives, the checker fails closed.

This preserves availability in the registered benign fixture: either viability
issuer may be suspected and the remaining independently signed rules still
approve the update. In the weakened fixture, the strict principal rejects the
unsafe transition when the weakened principal survives, while exclusion of the
strict principal still cannot produce unanimous approval across all hypotheses.

## Bounds and failure behavior

For `n` suspectable targets and fault budget `f`, hypothesis count is
`sum(C(n, i), i=0..f)` and is rejected before checking when it exceeds
`maximum_hypotheses`. One independently implemented Python checker process is
owned by each scenario run. Requests are serialized through an NDJSON boundary
and each response retains its two-second timeout. The number of requests remains
bounded by hypotheses times surviving viability principals plus baseline checks;
a timeout, process exit, malformed response, or pipe failure aborts the run.

The retained batching benchmark is
`results/post-m3-batched-checker-benchmark.json`. On the same development machine,
scenario p50 latency fell from 75.8–151.7 ms to 16.4–16.6 ms while decisions,
hypothesis counts, certificate sizes, and safety metrics remained unchanged.
Timings are observations, not guarantees.

Duplicate viability issuers, missing viability authorities, invalid signatures,
and insufficient hypothesis bounds fail closed.

## Falsifiers and claim limits

This strategy is falsified for the registered scope by:

- any unsafe approval with at most one faulty listed principal;
- a false refusal in the registered benign multi-principal fixture;
- acceptance when all viability principals are excluded;
- unbounded hypothesis or checker work; or
- evidence that the two issuer implementations or operators share a correlated
  semantic failure.

The result does not cover two correlated faulty principals, prove organizational
independence, or establish general safety. The retained post-M3 benchmark removes
the registered unsafe approval while increasing latency and certificate size.
Productisation remains blocked pending broader adversarial evaluation,
availability measurement, and independent reproduction.

Reproduce the follow-up run from the current reviewed revision with:

```sh
cargo run --release --locked --offline --example benchmark -- scenarios/*.json
./scripts/ci-local.sh
```
