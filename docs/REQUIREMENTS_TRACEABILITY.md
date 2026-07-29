# Requirements Traceability

| ID | Requirement | Design | Verification |
|---|---|---|---|
| SEM-1 | Suspect goal authority | Hypothesis engine | malicious signed-goal E2E |
| SEC-1 | Separate provenance | Authority envelopes/ledger | lineage and contamination tests |
| SEM-2 | Exclude suspect evidence | Planner boundary | taint/ablation test |
| SEM-3 | Preserve viability | Independent checker | exhaustive state exploration |
| SEM-5 | Tolerate one weakened viability principal | Per-issuer hypotheses and surviving-rule intersection | weakened and benign multi-principal fixtures |
| SEM-6 | Prevent unanimous viability weakening from authorizing key deletion | Stable-key continuity in independent Rust/Python checkers | cross-domain fixture, differential tests, 512-scenario exploration |
| SEC-3 | Detect signed-history rollback and broken chains | Bounded phenotype chain plus trusted tip anchor | predecessor replay, omitted/forked/old-tip tests |
| SEM-4 | Refuse ambiguity | protocol acceptance rule | contradictory-authority E2E |
| REL-1 | Reproducible decisions | content addressing | deterministic replay |
| SEC-2 | Fail closed | resource/error policy | timeout and ledger-failure E2E |
| NOV-1 | Compare established baselines | harness adapters | registered benchmark report |

M1 evidence is executable in `tests/m0.rs`: protocol rejection covers stale,
unknown-schema, duplicate, digest/signature-tampered, and over-budget inputs;
public replay covers provenance exclusion, diverse checking, refusal,
determinism, ledger persistence, rollback, and all three baselines.

Post-M3 evidence in `tests/adversarial.rs` and the benign replay verifies
fault-domain viability exclusion, fail-closed checking, and preservation of
benign availability. Certificate v4's stable-key kernel additionally refuses the
cross-domain deletion; all retained fixtures and 512 generated scenarios report
zero unsafe approvals.
