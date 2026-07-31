# Risk Register

| ID | Risk | Likelihood | Impact | Mitigation / trigger |
|---|---|---:|---:|---|
| R1 | Closest work already combines these elements | Medium | High | Claim-by-claim literature/patent update before publication |
| R2 | Poisoned viability authority | Medium | Critical | Multi-principal rules; explicitly test; narrow claim |
| R3 | Correlated planner/checker defects | Medium | Critical | Separate languages/parsers; differential tests |
| R4 | Hypothesis explosion | High | High | Finite model, budgets, refusal; measure scaling |
| R5 | Excess false refusal | High | High | Report availability frontier; compare baselines |
| R6 | Signature mistaken for truth | Medium | Critical | Preserve authenticity/truth distinction |
| R7 | Unsafe actuator partial effects | Medium | Critical | Simulator first; transactional adapter proof |
| R8 | Name/package collision | Low | Medium | Repeat registry/domain/trademark search pre-launch |
| R9 | VM/filesystem tests mistaken for device-level durability | Medium | Critical | Record execution/filesystem metadata; require bare-metal power-loss testing before production claims |
| R10 | Lifecycle recovery root or trusted tip is compromised or rolled back | Medium | Critical | Separate offline roots; bind chains/tips into evidence; require durable quorum or hardware roots before production |
| R11 | Project-controlled Kubernetes collection evidence may not represent a real target cluster | Medium | High | Live v2 binds object identity and pre/post controller equality under least-privilege reads; require real-cluster and independent qualification before candidate promotion |
| R12 | Malformed input reaches an untested parser edge | Medium | High | Bounded deterministic corpora; retain minimized regressions; require deeper independent fuzzing before release |
| R13 | Evaluation label is mistaken for production authorization | Medium | Critical | Read-only supported mode; machine-checked prohibitions; explicit promotion decision |
| R14 | Evaluation collector gains mutation or excess read privileges | Medium | Critical | Least-privilege manifests; no mutation verbs or credentials; fail-closed permission tests |
| R15 | Diagnostic or assessor bundles disclose sensitive platform data | Medium | High | Bounded allowlisted export; redaction and privacy review; telemetry off by default |
| R16 | Private candidate diverges from independently assessed artifacts | Medium | Critical | Commit, checksum, and signature binding; assess exact bundle; reassess material fixes |
| R17 | Upgrade, rollback, or uninstall mixes versions or loses evaluation evidence | Medium | Critical | Atomic digest-bound release activation; verified bounded backup; exact-root removal confirmation; preserve evidence on rollback/uninstall |
| R18 | Diagnostic export discloses sensitive platform or application data | Medium | High | Fixed content-free allowlist; opaque ordinals; file/count bounds; permission checks; unique-secret disclosure regression; encrypted handling |
