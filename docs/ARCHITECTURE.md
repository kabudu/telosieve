# Architecture

## Components

1. **Authority adapters** normalize goal, phenotype, and viability documents.
2. **Provenance verifier** checks identity, signature, lineage, freshness, and
   schema without deciding truth.
3. **Hypothesis engine** enumerates allowed fault sets under the configured budget.
4. **Planner** derives candidate transitions without consuming authorities marked
   suspect in that hypothesis.
5. **Independent checker** validates preconditions, invariants, blast radius, and
   rollbackability from a separately implemented model.
6. **Transactional actuator** applies only certified plans to the test service.
7. **Evidence ledger** records immutable inputs, hypotheses, decisions, and results.

## Trust boundaries

Adapters and the service are untrusted. Keys, schemas, the fault declaration,
checker, and ledger integrity form the initial trusted computing base. Planner and
checker may not share parsing or invariant-evaluation code. Correlated operator,
key, parser, and specification failures remain explicit residual risks.

## Data flow

Authorities → verification → hypotheses → candidate plans → independent checking
→ apply or refuse → outcome evidence. Every transition is content-addressed and
bound to the exact authority versions considered.

## Failure behavior

Malformed, stale, equivocal, over-budget, or unverifiable evidence yields refusal.
Timeouts never degrade to “best effort.” Side effects are restricted to a
simulator until the safety case is supported.

## M0 implementation boundary

M0 is a single-process Rust harness. The service transition is a pure,
content-bound replacement of every named replica, so commit and rollback are
deterministic state values rather than production side effects. Hypothesis work is
bounded by `maximum_hypotheses`; every authority subset up to the declared budget
is enumerated deterministically and rejected before evaluation when the configured
bound is insufficient. M1 invokes a separately implemented Python checker over a
JSON process boundary. Post-M3 batching owns one checker process per scenario and
exchanges bounded NDJSON requests, avoiding per-hypothesis startup without sharing
planner code. Each response has a two-second timeout; failure aborts the run. The
checker independently parses and evaluates the service and viability models, and
differential tests compare it with the Rust reference checker.

The signed-history baseline verifies a maximum of 64 predecessor phenotype
envelopes against an explicit current-tip anchor before planning, then replays the
authenticated predecessor. The harness anchor is trusted configuration; durable
monotonic storage remains outside the implementation boundary.

The anchored CLI path moves the current tip into a crash-synchronized local file
with explicit initialization, monotonic compare-and-advance, atomic replacement,
and fail-closed lock recovery. It remains a single-host prototype rather than a
distributed or hardware-backed trust root.
