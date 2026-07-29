# Telosieve

**Question the instruction before enforcing it.**

Telosieve is a research project for fail-closed service repair when the desired-state
authority itself may be stale, compromised, or malicious. It separates three
authorities—goal, observed phenotype, and viability constraints—then evaluates
explicit fault hypotheses before permitting a repair.

The first experiment is deliberately narrow: a deterministic replicated key-value
service under a bounded fault model. This repository contains the research and
delivery corpus, not a claim of a finished product.

## Candidate contribution

A provenance-separated repair protocol that can suspect the goal authority,
exclude suspected evidence from planning, require independently checked viability,
and refuse repair when surviving evidence cannot distinguish safe outcomes.

## Status

Research bootstrap complete; implementation is gated by the falsification plan in
[VALIDATION](docs/VALIDATION.md). See [NOVELTY](docs/NOVELTY.md) for claim limits
and [IMPLEMENTATION_PLAN](docs/IMPLEMENTATION_PLAN.md) for the first milestone.

## Repository policy

This is a private local repository. No remote is configured. The default branch is
`master`.
