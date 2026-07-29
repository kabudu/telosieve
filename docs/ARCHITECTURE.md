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
