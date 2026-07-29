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
| R11 | Exported Kubernetes snapshot is coherent but not live cluster truth | Medium | High | Bind UID/resource versions/time and signed authorities; require independently collected live observations before promotion |
