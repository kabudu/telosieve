# Requirements Traceability

| ID | Requirement | Design | Verification |
|---|---|---|---|
| SEM-1 | Suspect goal authority | Hypothesis engine | malicious signed-goal E2E |
| SEC-1 | Separate provenance | Authority envelopes/ledger | lineage and contamination tests |
| SEM-2 | Exclude suspect evidence | Planner boundary | taint/ablation test |
| SEM-3 | Preserve viability | Independent checker | exhaustive state exploration |
| SEM-5 | Tolerate one weakened viability principal | Per-issuer hypotheses and surviving-rule intersection | weakened and benign multi-principal fixtures |
| SEM-6 | Prevent unanimous viability weakening from authorizing key deletion | Stable-key continuity in independent Rust/Python checkers | cross-domain fixture, differential tests, 512-scenario exploration |
| SEM-7 | Preserve safe-goal availability while goal domains are suspectable | Multiple agreeing goal principals with domain exclusion | mapping/disagreement adversarial tests, 512-scenario exploration |
| SEM-8 | Permit only explicitly authorized stable-key deletion | Goal/tip-bound deletion principals, domain exclusion, exact checker enforcement | authorized/unauthorized fixtures, replay/overbreadth/shared-domain tests |
| SEM-9 | Consume an applied anchored deletion authorization at most once | Exact signed-envelope identity plus atomic anchor-state consumption ledger | one-shot public-boundary, evidence-failure burn, ledger-bound, legacy-state tests |
| ACT-1 | Apply only a certified transition to current service state | Commit-time observed-state and transition-precondition checks | applied/refused/stale public-boundary and CLI lifecycle tests |
| ACT-2 | Keep service mutation, history, and deletion consumption atomic | Single bounded local actuator state replacement | combined-consumption unit test, post-commit evidence-failure test |
| REC-1 | Recover an interrupted local actuator commit without guessing | Pending/committed witness with exact previous/next generations | deterministic crash-point and forced-termination tests |
| REC-2 | Reject stale or tampered primary-state restore | Content-addressed backup must equal latest surviving witness | stale/tampered/missing-primary restore tests |
| REC-3 | Preserve v1 deletion consumption during recovery upgrade | Explicit witnessed in-place schema upgrade | completed/interrupted upgrade tests |
| REC-4 | Preserve exact-generation recovery across qualified OS/architecture boundaries | Pinned offline Linux arm64/amd64 harness on Docker-managed volumes | nine recovery tests, 16 forced terminations, retained per-platform measurements |
| SEC-3 | Detect signed-history rollback and broken chains | Bounded phenotype chain plus trusted tip anchor | predecessor replay, omitted/forked/old-tip tests |
| SEC-4 | Rotate, expire, revoke, and recover issuer keys without authorizing stale current evidence | Recovery-root-signed bounded lifecycle with trusted tip and issuance/evaluation key checks | rotated fixture; historical, superseded, expiry, revocation, recovery, rollback, equivocation, separation, and bound tests |
| SEC-5 | Reject malformed protocol, integration, and recovery artifacts within bounded work | Deterministic parser corpora with explicit case/byte ceilings and minimized regressions | retained `telosieve.parser-corpora/v1` aggregate and four rejection fixtures |
| SEC-6 | Detect dependency provenance, license, lockfile, and known-advisory drift | Deterministic locked inventory plus freshness-bounded RustSec result | byte-regeneration check; source/checksum/license validation; retained database commit |
| SEC-7 | Refuse enrolled lifecycle evaluation outside a bounded trusted-time assertion | Inclusive maximum-300-second window bound into authority evidence | exact expiry/revocation boundary and rollback/forward/over-wide tests |
| SEC-8 | Fail closed across supported scenario/certificate migrations | Bounded validate-then-regenerate compatibility boundary for legacy/current scenarios and certificates v7–v9 | retained old/new, missing-trust, future-version/field, confused-shape, and oversized vectors |
| SEC-9 | Preserve certificate compatibility through an implementation-diverse consumer and controlled retirement | Dependency-free bounded Python reader plus two-milestone deprecation and explicit major-change removal gates | retained v7/v8/v9 acceptance, nine refusal classes, and zero Rust/Python disagreements |
| SEC-10 | Authenticate exact certificate evidence without rewriting retained artifacts | Detached domain-separated Ed25519 envelope with bounded signer windows and independent verification | old/new rotation acceptance; tamper, substitution, context replay, expiry, key-window, and bound refusals |
| SEC-11 | Prevent post-revocation signer backdating while preserving earlier evidence | Separately signed append-only timestamp chain plus digest-anchored bounded revocation snapshot | historical acceptance; inclusive revocation, rollback, equivocation, stale, tamper, and omission refusals |
| SEC-12 | Preserve exact timestamp/revocation tips across interruption and bounded distribution failure | Atomic dual-tip state, recovery witness, exact-latest backup, and bounded artifact-fetch policy | macOS/Linux recovery and restore; delay, loss, partition, outage, budget, and equivocation matrix |
| SEC-13 | Refuse unsafe witness evidence across external-style transport faults | Separate authenticated immutable HTTP endpoints plus bounded fetch and existing cryptographic verifier | healthy/restart/partition success; timeout, drop, unauthorized, oversize, outage, equivocal, and stale refusal |
| GOV-2 | Prevent project-controlled evidence from being mistaken for independent witness reproduction | Commit-bound operator request, strict bounded return schema, attachment digests, and mandatory out-of-band identity assessment | one synthetic schema acceptance; thirteen policy/integrity refusals; external gate remains unchecked |
| GOV-3 | Productise for private evaluation without silently authorizing production | Machine-checked evaluation contract with explicit authorized work, prohibited actions, candidate gates, and promotion gates | contract validator; local-CI enforcement; roadmap and release boundary audit |
| EVAL-1 | Provide a stable read-only evaluation entrypoint without mutation authority | Versioned strict config and report, bounded file reads and paths, existing shadow verifier, evidence-only outputs | real CLI lifecycle; version/field/mode/path/collision/config/scenario refusals; unchanged inputs |
| EVAL-2 | Collect live Kubernetes evaluation state without mutation authority or incoherent reads | Four fixed bounded `kubectl get` calls, explicit trusted binary/credential paths, pre/post controller equality, ownership/readiness checks, least-privilege RBAC | fake-process CLI success and drift refusal; exact command/no-mutation audit; full local CI |
| EVAL-3 | Install and change private evaluation software without mixed versions, evidence rollback, or unsafe removal | Digest-bound immutable releases, atomic active symlink, verified bounded backup, exact-root uninstall confirmation, evidence preservation | real binary install/backup/upgrade/rollback/uninstall lifecycle; existing-install, tamper, wrong-confirmation, and relative-root refusals |
| EVAL-4 | Diagnose an installation without disclosing platform or application content | Offline fixed allowlist of release/config digests and opaque evidence digest/size records; owner-only 1,000-file/256-MiB bounds | unique secret/path non-disclosure; exact recursive schema; existing-output, symlink, permission, and destination refusals |
| EVAL-5 | Reproduce and recover private candidate assembly under measured resource bounds | Deterministic fixed-input ZIP, per-entry checksums, no-clobber publication, interruption recovery | byte-identical double build, manifest verification, forced termination/no publication, successful same-digest recovery, macOS wall/RSS/output measurements |
| EVAL-6 | Authenticate the exact private candidate without embedding signing authority | Domain-separated Ed25519 envelope, independently supplied bounded trust/time, owner-only single-link key input, create-new signature output | real CLI sign/verify; tamper, context, key, expiry, permission, schema, and resource refusal tests |
| EVAL-7 | Prevent candidate artifacts from becoming detached from reviewed source | Canonical full source commit inside the signed deterministic bundle plus bounded two-custodian ceremony | reproducibility, commit-substitution divergence, malformed-commit no-publication, documented abort paths |
| EVAL-8 | Detect nondeterministic or substituted private-candidate binaries | Two isolated locked/offline non-incremental release builds plus digest/byte comparison and retained provenance | byte-identical same-host builds, altered-binary refusal, toolchain/target/time/RSS/work-size record |
| INT-1 | Evaluate Kubernetes desired/observed state without mutation authority | Bounded exported ConfigMap/StatefulSet snapshot mapped exactly to authenticated authorities | mapping, drift, partial/stale, identity, size, collision, and CLI no-mutation tests |
| OPS-1 | Rehearse registered incident classes without production credentials | Offline seven-drill runner with exact expected outcomes | retained `telosieve.incident-drills/v1` aggregate |
| GOV-1 | Give an external assessor an immutable, claim-bounded reproduction target | Commit-pinned manifest with Git-object SHA-256 checks and clean-clone verifier | retained `telosieve.assessor-verification/v1` result |
| GOV-2 | Rehearse recovery-root approval and abort handling without credentials | Strict-majority fixed-quorum request with exact context/evidence binding and veto | retained credential-free success, exclusion, duplicate, missing, divergence, stale, veto, and compromise tests |
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
