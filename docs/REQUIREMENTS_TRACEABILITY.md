# Requirements Traceability

| ID | Requirement | Design | Verification |
|---|---|---|---|
| SEM-1 | Suspect goal authority | Hypothesis engine | malicious signed-goal E2E |
| SEC-1 | Separate provenance | Authority envelopes/ledger | lineage and contamination tests |
| SEM-2 | Exclude suspect evidence | Planner boundary | taint/ablation test |
| SEM-3 | Preserve viability | Independent checker | exhaustive state exploration |
| SEM-4 | Refuse ambiguity | protocol acceptance rule | contradictory-authority E2E |
| REL-1 | Reproducible decisions | content addressing | deterministic replay |
| SEC-2 | Fail closed | resource/error policy | timeout and ledger-failure E2E |
| NOV-1 | Compare established baselines | harness adapters | registered benchmark report |
