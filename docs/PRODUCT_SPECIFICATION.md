# Product Specification

## Problem

Conventional reconcilers assume the desired state is authoritative. If that input
is poisoned, faithfully converging to it can destroy a healthy service. Telosieve
investigates whether repair can remain useful while treating every authority,
including intent, as fallible.

## Evaluation user and job

The initial product user is a platform reliability engineer or independent
assessor evaluating recovery policy in read-only shadow mode. Given bounded,
authenticated observations from a named platform, signed authority inputs, and
a declared fault model, they need a machine-checkable decision, refusal,
diagnostic record, and assessor-ready evidence without granting Telosieve
mutation authority.

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

## Evaluation and promotion gates

Private evaluation-product engineering is authorized under
[EVALUATION_PRODUCT_DECISION](EVALUATION_PRODUCT_DECISION.md). The first
supported mode is read-only shadow evaluation. Stable interfaces, live
read-only collection, installation and lifecycle procedures, least privilege,
diagnostics, recovery/resource qualification, reproducible private packaging,
and an operator runbook are candidate gates rather than assumed capabilities.

The versioned evaluation CLI, strict configuration, bounded live collector, and
single-host lifecycle manager now satisfy the stable-interface, live-read, and
lifecycle-procedure, and bounded diagnostics/export gates. This does not satisfy
the separate resource/recovery qualification or reproducible private-bundle
gates.

The transactional local reference actuator is evidence for the required adapter
contract, not a supported production adapter. Production promotion still
requires independent assessment of the exact candidate, remediation and
reassessment, a named target's concurrency/transaction model, production
identity/custody design, recovery testing, and a new explicit decision.
