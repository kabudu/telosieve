# Productisation Assessment

This table records the M3 evidence at the time of the original decision. Later
remediation does not rewrite those observations.

## Registered claim comparison

| Dimension | Telosieve evidence | Baseline comparison | Gate |
|---|---|---|---|
| Poisoned-goal safety | 0 unsafe approvals; explicit refusal | 2 baseline unsafe approvals | promising |
| Weakened-viability safety | 1 unsafe approval | 3 baseline unsafe approvals | stop-ship |
| False refusal | 0 across four signed fixtures | 0 observed | insufficient sample |
| Decision latency, one hypothesis | p50 21.9–23.0 ms | in-process baselines are materially cheaper | research-only |
| Decision latency, two hypotheses | p50 45.1–45.8 ms | approximately 2× one-hypothesis path | bounded but costly |
| Certificate size | 2,836–3,143 bytes | baseline-only record is smaller | acceptable for harness |
| Operational complexity | Rust planner plus bounded Python process per check | baselines remain single-process | added burden |

## Interpretation

The candidate demonstrates its intended poisoned-goal distinction in one bounded
fixture: it refuses where two baseline decisions are unsafe. That result does not
support productisation because the independently registered weakened-viability
fixture produces an unsafe Telosieve approval. The current fault declaration
excludes that failure, but a real operator cannot assume viability semantics are
incorruptible merely because their envelope is authentic.

Availability cost is not yet adverse in the four fixtures (`false_refusals = 0`),
but the sample is too small to estimate a frontier. Process isolation provides
semantic diversity at measurable latency and operator cost. No production
actuator, durable history service, cross-platform result, or independent
reproduction exists.

The evidence supports continued narrow research into multi-principal viability
and checker amortisation. It does not support an operator product, hosted control
plane, production adapter, or safety claim.

The resulting binding decision is documented in
[PRODUCTISATION_DECISION](PRODUCTISATION_DECISION.md).

Post-M3 work now includes authenticated predecessor replay, but the anchor remains
trusted harness configuration rather than a durable rollback-resistant service.
This removes the fixture-level snapshot proxy without satisfying the production
history requirement.

The later durable-anchor prototype provides crash-synchronized single-host
monotonic storage. It improves the harness boundary but does not supply
multi-host, hardware-backed, or independently operated rollback resistance.

Certificate v3 subsequently tolerates two correlated weakened signers inside one
declared domain, but its cross-domain weakened fixture produced one unsafe
approval. That historical result motivated the certificate-v4 remediation below.

The later generated-state-space experiment expands this from fixtures to 512
authenticated scenarios over 32 finite cells. Certificate v3 recorded 48 unsafe
approvals among 256 poisoned goals (18.75%) and 64 false refusals among 256 safe
goals (25%).

Certificate v4 adds stable-key continuity without changing those oracles. The
same 512 scenarios now record zero unsafe approvals and the same 64 false
refusals.

Certificate v5 adds two agreeing declared goal domains. The unchanged 512
scenario oracles now record zero unsafe approvals and zero false refusals.
Authenticated disagreement still fails closed, and declared domains do not prove
organizational independence. The evidence remains bounded rather than a proof or
population estimate, so it does not automatically reverse the narrow decision.
See
[GENERATED_STATE_SPACE](GENERATED_STATE_SPACE.md).

Certificate v6 adds a separately authenticated deletion path without weakening
default continuity. The authorized fixture applies one exact deletion; the same
goal without authorization refuses. This resolves the missing deletion semantics
for the harness. Certificate v7 adds bounded single-host one-shot consumption,
but not production actuation, platform-qualified/multi-host durability, or
organizational independence. See
[AUTHORIZED_DELETION](AUTHORIZED_DELETION.md).

Certificate v8 subsequently supplies a transactional file-backed reference
actuator. It proves commit-time state comparison and atomic local side effects,
but it is not evidence for any named external service, credential boundary,
distributed transaction, or production recovery procedure. See
[LOCAL_REFERENCE_ACTUATOR](LOCAL_REFERENCE_ACTUATOR.md).

Schema-v2 recovery testing removes one narrower uncertainty: on the measured
macOS/aarch64 filesystem, killed local actuator processes recover to an exact
witnessed generation and stale primary backups refuse. The co-located witness
does not protect whole-disk rollback or establish other-platform, multi-host, or
external-service reliability. See [ACTUATOR_RECOVERY](ACTUATOR_RECOVERY.md).
