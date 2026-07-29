# Stable-Key Safety Kernel

Date: 2026-07-29

## Problem

When every viability fault domain signs the same weakened rule set, provenance
and domain exclusion leave no independent semantic constraint. The retained
cross-domain fixture and 48 generated cases therefore approved goals that
deleted `cluster/epoch`.

The safety oracle has not changed: a goal that omits the registered epoch remains
unsafe. Expected decisions and generated labels are unchanged.

## Invariant

Certificate v4 adds one non-bypassable checker rule:

> A transition must retain every key present on every current replica.

Values may change and new keys may be added. Key deletion through Telosieve is
deliberately unavailable. A separate future protocol would need an explicit,
independently authorized deletion mechanism; treating absence as deletion would
reintroduce this failure.

The invariant is derived from authenticated current phenotype evidence rather
than viability rules. It is implemented independently in the Rust reference
checker (`v1`) and Python checker (`v3`). Empty current state, checker failure,
timeout, or parser disagreement remains fail-closed.

## Bounds and failure model

The check intersects current replica key sets, then verifies those keys on every
post-transition replica. Work is O(R × K), where R is the bounded replica count
and K is the number of keys in the first current replica. It adds no process,
hypothesis, network request, persistent state, or dependency.

The rule covers deletion only when the key is present on every authenticated
current replica. Simultaneous semantic corruption of both goal and phenotype,
malicious omission by every phenotype replica, checker-host compromise, and
arbitrary side effects outside the simulator remain outside the demonstrated
bound.

## Evidence

- The registered all-domains-weakened fixture now refuses with zero unsafe
  approvals.
- All 512 generated scenarios report zero unsafe approvals.
- The existing 64 false refusals among 256 safe goals remain unchanged.
- Explicit tests show deletion refusal and preserve updates/additions.
- Rust and Python return the same safety result and reasons at the deletion
  boundary.
- The five-fixture benchmark retains bounded hypothesis counts and records p50
  latency between 15.2 ms and 16.1 ms on this machine.

Raw evidence is retained in `results/generated-state-space.json` and
`results/stable-key-kernel-benchmark.json`.

Zero observed unsafe approvals is evidence only for the retained finite state
space and fixtures. It is not a proof of general safety or authorization for
productisation.

Certificate v5 subsequently removes the 64 measured safe-case refusals using
multiple agreeing goal domains; see
[MULTI_PRINCIPAL_GOALS](MULTI_PRINCIPAL_GOALS.md).

Certificate v6 retains continuity as the default and permits an exception only
for an exact, separately signed deletion set bound to the goal and phenotype tip.
See [AUTHORIZED_DELETION](AUTHORIZED_DELETION.md).
