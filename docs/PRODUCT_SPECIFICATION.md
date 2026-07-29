# Product Specification

## Problem

Conventional reconcilers assume the desired state is authoritative. If that input
is poisoned, faithfully converging to it can destroy a healthy service. Telosieve
investigates whether repair can remain useful while treating every authority,
including intent, as fallible.

## Research user and job

The initial user is a distributed-systems researcher or platform reliability
engineer evaluating recovery policy. Given a deterministic replicated key-value
service, signed authority inputs, and a bounded fault declaration, they need a
machine-checkable decision: apply a proposed repair, quarantine evidence, or
refuse.

## First vertical

Inputs:

- signed goal snapshot;
- independently collected service phenotype;
- versioned viability invariants;
- provenance and freshness metadata;
- declared fault budget.

Outputs:

- fault hypotheses and evidence weights;
- a repair plan or explicit refusal;
- an independently verified certificate;
- an append-only decision record.

Success means detecting seeded poisoned-goal cases without reducing safety below
the baseline and with measurable availability cost. The system must not claim to
infer human intent, repair arbitrary services, or guarantee correctness outside
the declared model.

## Productisation gate

No operator UI, hosted control plane, or production actuator is justified until
the experiment beats a signed-history reconciler and runtime-invariant baseline on
pre-registered scenarios.

The transactional local reference actuator is evidence for the required adapter
contract, not satisfaction of this production gate. Promotion still requires a
named target service, its native concurrency/transaction model, credentials and
least-privilege design, recovery testing, and independent security review.
