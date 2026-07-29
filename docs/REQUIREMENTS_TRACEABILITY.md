# Requirements Traceability

| ID | Requirement | Design | Verification |
|---|---|---|---|
| SEM-1 | Suspect goal authority | Hypothesis engine | malicious signed-goal E2E |
| SEC-1 | Separate provenance | Authority envelopes/ledger | lineage and contamination tests |
| SEM-2 | Exclude suspect evidence | Planner boundary | taint/ablation test |
| SEM-3 | Preserve viability | Independent checker | exhaustive state exploration |
| SEM-5 | Tolerate one weakened viability principal | Per-issuer hypotheses and surviving-rule intersection | weakened and benign multi-principal fixtures |
| SEM-4 | Refuse ambiguity | protocol acceptance rule | contradictory-authority E2E |
| REL-1 | Reproducible decisions | content addressing | deterministic replay |
| SEC-2 | Fail closed | resource/error policy | timeout and ledger-failure E2E |
| NOV-1 | Compare established baselines | harness adapters | registered benchmark report |

M1 evidence is executable in `tests/m0.rs`: protocol rejection covers stale,
unknown-schema, duplicate, digest/signature-tampered, and over-budget inputs;
public replay covers provenance exclusion, diverse checking, refusal,
determinism, ledger persistence, rollback, and all three baselines.

Post-M3 evidence in `tests/adversarial.rs` and the benign replay verifies
per-issuer viability exclusion, fail-closed checking, zero registered unsafe
approvals, and preservation of benign availability under the one-principal bound.
