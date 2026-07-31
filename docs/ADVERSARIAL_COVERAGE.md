# Adversarial Integration Coverage

Date: 2026-07-31

`evaluation/adversarial-coverage.json` is the executable coverage contract for
Telosieve's three read-only evaluation modes. It distinguishes evidence-backed
coverage from justified non-applicability and unresolved research gaps; a prose
claim cannot satisfy a covered cell. Each evidence reference is a bounded
repository-relative regular file plus an exact anchor that the validator must
find.

The current registry contains ten threat classes. Eight required classes have
19 applicable, executable cells. Five cells are inapplicable because the mode
has no relevant credential or transport boundary. Six cells remain explicitly
deferred across two research threats:

- a compromised producer returning internally consistent false observations;
- sustained adversarial evaluation load across process and target boundaries.

Run the contract directly with:

```sh
python3 scripts/validate-adversarial-coverage.py
```

The validator caps the registry at 256 KiB, 64 threat classes, four evidence
references per cell, and 4 MiB per referenced text file. It requires exact
agreement with the three ordered product modes and the read-only authority
boundary. Required applicable cells must be covered; only registered research
gaps may be deferred. Evidence paths cannot be absolute, traverse the repository,
use symlinks, point outside executable/retained-evidence roots, or cite a missing
anchor.

Eleven adversarial mutations prove refusal of omitted or duplicated threat IDs,
unknown modes, missing cells, deferred required coverage, nonexistent and
traversing or non-evidence paths, absent anchors, excessive evidence, and a
weakened authority boundary. The retained aggregate is
`results/adversarial-coverage-validation.json` and authoritative local CI reruns
the validator.

This contract is a coverage inventory, not a proof that implementations or test
oracles are correct. Project-controlled evidence cannot establish independent
operation. The two deferred threats are candidate-hardening work and must not be
described as covered; managed-platform, version-matrix, provider, remote-state,
and independent-environment qualification also remain roadmap work.
