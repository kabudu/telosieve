# Implementation Plan

## M0 — executable research contract (complete)

- [x] Define the finite service state machine and authority schemas.
- [x] Register fault classes, invariants, metrics, seeds, and baseline behavior.
- [x] Implement only enough simulator and checker to run one benign and one
  poisoned-goal scenario.
- [x] Exit: deterministic replay plus a machine-readable refusal certificate.

Evidence: `scenarios/benign.json`, `scenarios/poisoned-goal.json`, and
`tests/m0.rs`. M0 supports a declared budget of zero or one fault and rejects a
configuration whose finite hypothesis count exceeds `maximum_hypotheses`.

## M1 — hypothesis protocol

- [x] Implement bounded general hypothesis enumeration and provenance exclusion.
- [x] Add signed-history rollback and invariant-gated reconciler baselines.
- [x] Replace shared Rust/Serde planner-checker semantics with a diverse checker
  boundary and demonstrate parser/model differential tests.
- [x] Exit: every protocol requirement has behavioural evidence and all three
  baselines replay through the public harness.

## M2 — adversarial evaluation

- [x] Run malicious/stale goals, omitted/forged observations, weakened invariants,
  partitions, equivocation, parser differential, and correlated-fault probes.
- [x] Measure hypothesis growth, compute cost, recovery latency, unsafe approvals,
  and false refusals against every baseline.
- [x] Exit: retain reproducible raw results and report all negative results.

## M3 — productisation decision

- [x] Compare the registered safety claim with quantified availability and
  complexity costs.
- [x] Refresh novelty, name, security, soundness, and release diligence.
- [x] Exit: explicitly proceed, narrow, or archive the project based on evidence.

Historical decision: **narrow**. Productisation and public release were blocked
at M3. The private evaluation lane was later authorized in Post-M26; production
promotion and public release remain blocked. See
[PRODUCTISATION_DECISION](PRODUCTISATION_DECISION.md).

## Post-M3 — narrowed research (historical scope)

- [x] Define multi-principal or explicitly suspectable viability semantics,
  preregistering the fault model and falsifiers.
- [x] Replace per-hypothesis process spawning with a bounded checker service or
  batch boundary without reducing semantic diversity.
- [x] Implement an authenticated, replayable history baseline rather than the
  current fixture-level proxy.
- [x] Obtain independent environment/toolchain reproduction of the registered
  experiments.

## Post-M4 — evidence expansion

- [ ] Obtain third-party organizational reproduction and security review.
- [x] Test correlated viability-principal faults and document fault-domain
  independence requirements.
- [x] Prototype a durable rollback-resistant history anchor.
- [x] Measure the safety/availability frontier over a larger generated state
  space.

Evidence: 512 authenticated generated scenarios and per-cell results in
[GENERATED_STATE_SPACE](GENERATED_STATE_SPACE.md).

## Post-M5 — reproduced unsafe-approval remediation

- [x] Add a viability-independent stable-key continuity invariant to both
  checker implementations.
- [x] Preserve value updates and additions while refusing implicit key deletion.
- [x] Re-run retained fixtures and the generated state space without changing
  their safety oracles.
- [x] Exit: zero unsafe approvals across retained evidence, quantified refusal
  cost, versioned certificates/checkers, and explicit residual bounds.

Evidence: [STABLE_KEY_SAFETY_KERNEL](STABLE_KEY_SAFETY_KERNEL.md). Productisation
remained blocked at that milestone by finite-model limits, false refusals,
deletion semantics, and independent-review gates.

## Post-M6 — goal-domain availability

- [x] Authenticate multiple agreeing goal principals and declare their fault
  domains when goal faults are in scope.
- [x] Exclude complete goal domains per bounded hypothesis and require a
  surviving goal principal.
- [x] Reject authenticated disagreement and invalid domain mappings before
  planning.
- [x] Exit: unchanged 512-scenario oracle, zero unsafe approvals, zero false
  refusals, quantified hypothesis/latency costs, and explicit independence limits.

Evidence: [MULTI_PRINCIPAL_GOALS](MULTI_PRINCIPAL_GOALS.md). Third-party
organizational reproduction/security review remains unchecked and cannot be
self-certified by this repository.

## Post-M7 — explicit authorized deletion

- [x] Add separately signed deletion evidence bound to the exact goal and
  phenotype tip.
- [x] Require agreeing deletion principals, complete fault-domain mappings, and
  a surviving authorization domain.
- [x] Enforce exact deletion sets independently in Rust and Python and expose
  per-hypothesis authorization in certificate v6.
- [x] Exit: authorized deletion applies, ordinary omission and replay/overbreadth
  refuse, existing 512-case safety/availability remains 0/0, and costs/bounds
  are retained.

Evidence: [AUTHORIZED_DELETION](AUTHORIZED_DELETION.md). Durable one-shot
consumption and third-party organizational review remained unresolved.

## Post-M8 — durable deletion consumption

- [x] Derive an auditable identifier from the exact authenticated deletion
  envelope set and expose it in certificate v7.
- [x] Atomically commit history-anchor advancement and applied deletion
  consumption in one versioned durable state.
- [x] Fail closed on replay, corruption, legacy state, stale locks, history
  conflicts, and the bounded ledger's capacity limit.
- [x] Preserve deterministic stateless research replay and document safe
  authorization burn when later evidence persistence fails.
- [x] Exit: the anchored authorized fixture applies once, its identical replay
  fails before new evidence is emitted, and existing local validation passes.

Evidence: [DURABLE_DELETION_CONSUMPTION](DURABLE_DELETION_CONSUMPTION.md).
Third-party organizational reproduction/security review remains an external
unchecked gate.

## Post-M9 — transactional local reference actuator

- [x] Add explicit initialization from a verified authenticated phenotype.
- [x] Require commit-time equality with observed service state and the certified
  transition precondition.
- [x] Atomically commit service state, authenticated history, and deletion
  consumption in one bounded local store.
- [x] Emit certificate-v8 actuation receipts while preserving certificate-v7
  deterministic research runs.
- [x] Exercise apply, refusal, replay, contention, corrupt/oversized state,
  post-commit evidence failure, and the real CLI lifecycle.
- [x] Exit: the local reference service changes only after an applied certified
  plan and stale retry cannot duplicate the change.

Evidence: [LOCAL_REFERENCE_ACTUATOR](LOCAL_REFERENCE_ACTUATOR.md). Real production
service integration, platform qualification, and external organizational review
remain unresolved.

## Post-M10 — local actuator recovery qualification

- [x] Add monotonic generations and a separate pending/committed recovery
  witness around every actuator mutation.
- [x] Add bounded create-new backup, exact-latest restore, and stale/tampered
  backup rejection.
- [x] Preserve deletion history through an explicit crash-safe schema-v1 upgrade.
- [x] Resolve commit, initialization, and upgrade interruption without guessing.
- [x] Stress concurrent writers and 16 forced terminations, and retain
  50-iteration backup/restore/recovery measurements.
- [x] Exit: each tested interruption recovers to one exact committed generation
  or fails closed; stale restore cannot roll the witness back.

Evidence: [ACTUATOR_RECOVERY](ACTUATOR_RECOVERY.md). At Post-M10, qualification
was limited to the tested macOS/aarch64 single-host filesystem. Whole-disk
rollback, other platforms, external service integration, and independent review
remained open.

## Post-M11 — Linux recovery qualification

- [x] Run recovery-state and forced-termination tests on Linux arm64 and amd64.
- [x] Use a pinned, network-disabled multi-architecture container with the
  repository mounted read-only.
- [x] Put actuator mutations on Docker-managed Linux volumes rather than tmpfs.
- [x] Retain architecture, image, filesystem, object-size, and latency evidence.
- [x] Exit: both architectures recover every tested termination to an exact
  witnessed generation; emulated timing and VM/storage limits remain explicit.

Evidence: [ACTUATOR_RECOVERY](ACTUATOR_RECOVERY.md). This removes the
macOS-only software-path gap for the tested Linux VM/volume boundary. Bare-metal
Linux, power-loss persistence, whole-disk rollback, external service integration,
and independent review remain open.

## Post-M12 — key and identity lifecycle

- [x] Define authority-key rotation, revocation, expiry, and compromised-key
  recovery without invalidating historical certificates.
- [x] Bind lifecycle statements to authority kind, subject, sequence, and
  predecessor state.
- [x] Reject revoked or superseded keys for new transitions while retaining
  deterministic historical verification.
- [x] Exercise stale rotation, rollback, equivocation, partial availability,
  emergency revocation, and bounded state growth.

Evidence: [KEY_LIFECYCLE](KEY_LIFECYCLE.md). Lifecycle state is bounded and
authenticated but its roots and tips remain trusted scenario configuration, not
a durable organizational identity service.

## Post-M13 — shadow-mode external adapter

- [x] Name one external target and define a read-only phenotype/goal mapping
  without mutation credentials.
- [x] Bind observations to resource versions and reject schema or concurrency
  ambiguity.
- [x] Exercise drift, partial reads, stale watches, identity mismatch, and
  bounded observation size.
- [x] Retain shadow decisions and operator-facing refusal reasons without adding
  production actuation.

Evidence: [KUBERNETES_SHADOW](KUBERNETES_SHADOW.md). This is a bounded exported
snapshot adapter, not live Kubernetes access or actuation.

## Post-M14 — incident and recovery exercises

- [x] Define machine-readable drills for corruption, witness loss, full ledgers,
  stale locks, bad upgrades, key compromise, and lifecycle rollback.
- [x] Require explicit expected state, operator action, recovery point, and
  evidence preservation for every drill.
- [x] Execute the drills without production credentials and retain results.

Evidence: [INCIDENT_DRILLS](INCIDENT_DRILLS.md). Seven deterministic local
software drills pass; real infrastructure and organizational response remain
outside this evidence.

## Post-M15 — property and parser robustness

- [x] Add bounded property/fuzz corpora for authority, lifecycle, shadow, and
  recovery parsing.
- [x] Retain minimized regressions for every discovered discrepancy.

Evidence: [PARSER_CORPORA](PARSER_CORPORA.md). Four deterministic corpora pass
within explicit case and byte bounds; four minimized rejection regressions are
retained and the run discovered no additional discrepancy.

## Post-M16 — independent-assessment handoff

- [x] Assemble a self-contained assessor manifest with commit, commands,
  expected digests, claim boundaries, and unresolved release blockers.
- [x] Verify the handoff from a clean local checkout without production
  credentials or hosted CI.

Evidence: [ASSESSOR_HANDOFF](ASSESSOR_HANDOFF.md). The frozen Post-M15 source
commit passes local CI and reproduces the two operational aggregates from a
fresh local clone; this is a handoff package, not independent assessment.

## Post-M17 — dependency provenance and advisory inventory

- [x] Generate a locked dependency and license inventory with exact package
  versions and source/checksum provenance.
- [x] Run a local advisory audit and document unresolved, unavailable, or
  accepted findings without enabling hosted CI.

Evidence: [SUPPLY_CHAIN](SUPPLY_CHAIN.md). The deterministic inventory binds 44
packages to the lockfile; the current RustSec snapshot reports no known
vulnerability or warning and no finding is accepted.

## Post-M18 — trusted-time and recovery-root ceremony

- [x] Model trusted-time rollback/forward failure paths for lifecycle expiry and
  emergency revocation.
- [x] Define and rehearse a credential-free multi-party recovery-root ceremony
  with explicit quorum, evidence, abort, and compromise handling.

Evidence: [RECOVERY_ROOT_CEREMONY](RECOVERY_ROOT_CEREMONY.md). Enrolled
lifecycle evaluation now requires a bounded trusted-time window and the
credential-free 2-of-3 local rehearsal exercises success, exclusion, duplicate,
missing, divergent, stale, veto, and compromised-participant failure paths.
Neither mechanism establishes a production clock, participant identity, private
key custody, or organizational independence.

## Post-M19 — protocol compatibility and migration corpus

- [x] Retain old/new scenario and certificate compatibility vectors across
  supported protocol versions.
- [x] Define fail-closed migration rules for optional-to-required trust fields
  and unknown future versions.

Evidence: [PROTOCOL_COMPATIBILITY](PROTOCOL_COMPATIBILITY.md). Two bounded
integration vectors cover legacy/current/missing-trust scenarios, certificates
v7–v9, future fields/versions, cross-version shape confusion, and oversized
certificate input. Migration validates and regenerates from authoritative input;
it never silently rewrites retained evidence.

## Post-M20 — compatibility consumer qualification

- [x] Exercise the supported certificate boundary in an independent downstream
  reader and retain version-by-version results.
- [x] Define a deprecation window and explicit removal gate for supported
  certificate versions.

Evidence: [PROTOCOL_COMPATIBILITY](PROTOCOL_COMPATIBILITY.md). A dependency-free
Python reader agrees with Rust on three supported versions and nine refusal
classes in 13 bounded cases. Versions v7–v9 remain active; deprecation requires
explicit evidence and approval, and removal requires two later completed
milestones plus zero registered consumers and a major compatibility decision.

## Post-M21 — certificate evidence authenticity

- [x] Define a domain-separated certificate-attestation envelope without
  invalidating retained unsigned research certificates.
- [x] Exercise signer rotation, tampering, cross-context replay, expiry, and
  bounded verification through both supported readers.

Evidence: [CERTIFICATE_ATTESTATION](CERTIFICATE_ATTESTATION.md). Detached
attestation preserves v7–v9 bytes, binds exact certificate/context/time/key
evidence, and passes seven bounded old/new and failure cases with zero
Rust/Python disagreements.

## Post-M22 — attestation timestamp and revocation witnesses

- [x] Prototype an append-only trusted timestamp witness that prevents
  compromised signers from backdating attestations.
- [x] Define bounded signer-revocation distribution and retained historical
  verification semantics across both readers.

Evidence: [ATTESTATION_WITNESSES](ATTESTATION_WITNESSES.md). Separate signed
timestamp chains and digest-anchored revocation snapshots pass seven bounded
historical and refusal cases with zero Rust/Python disagreements. Authorities,
trusted tips, custody, and distribution remain research configuration.

## Post-M23 — witness durability and availability

- [x] Qualify timestamp/revocation trusted-tip persistence across crash,
  backup/restore, and independent-host boundaries.
- [x] Measure bounded witness and revocation distribution availability under
  delay, loss, partition, and authority outage.

Evidence: [WITNESS_DURABILITY](WITNESS_DURABILITY.md). Atomic dual-tip state,
exact recovery/restore, and path-independent copies pass on macOS plus pinned
offline Linux arm64/amd64. Seven deterministic bounded distribution profiles
preserve three available paths and refuse loss, outage, over-budget delay, and
equivocation.

## Post-M24 — isolated external-endpoint harness

- [x] Orchestrate separate authenticated timestamp/revocation HTTP processes
  without adding mutation authority or weakening exact-tip verification.
- [x] Exercise bounded live delay, loss, partition, outage, restart, stale,
  equivocal, unauthorized, and oversized endpoint behavior.

Evidence: [WITNESS_ENDPOINT_HARNESS](WITNESS_ENDPOINT_HARNESS.md). Three
end-to-end success paths and seven live refusal paths pass through real HTTP and
the existing cryptographic verifier within explicit request/resource bounds.

## Post-M25 — independently operated witness reproduction

- [x] Freeze an operator handoff and fail-closed returned-evidence validator
  without manufacturing or self-certifying organizational independence.
- [ ] Integrate one independently administered timestamp/revocation endpoint
  with documented identity, custody, clock, and incident boundaries.
- [ ] Have an independent operator reproduce durability and live network fault
  results without project-controlled credentials or execution.

Preparation evidence: [WITNESS_OPERATOR_HANDOFF](WITNESS_OPERATOR_HANDOFF.md).
The handoff binds the M24 source and required outcomes; its adversarial validator
accepts one synthetic schema fixture and refuses thirteen integrity/policy faults.
No independent record has been returned, so both external gates remain open.

## Post-M26 — private evaluation product authorization

- [x] Authorize a production-shaped private evaluation lane with a
  machine-checked scope and claim boundary.
- [x] Define candidate readiness and production-promotion gates without
  weakening the private-repository local-CI policy.
- [x] Stabilize a versioned evaluation CLI and strictly validated configuration.
- [x] Add a fail-closed, least-privilege live Kubernetes read-only collector.
- [x] Package documented install, upgrade, rollback, backup, and uninstall
  workflows for supported evaluation platforms.
- [x] Add bounded operator diagnostics and privacy-reviewed evidence export.
- [x] Qualify platform resources, interruption, recovery, and private bundle
  reproducibility before proposing an evaluation candidate.

Decision evidence:
[EVALUATION_PRODUCT_DECISION](EVALUATION_PRODUCT_DECISION.md). The authorization
enables implementation and later private candidate packaging; it is not itself
an evaluation release or production promotion.

CLI evidence: [EVALUATION_CLI](EVALUATION_CLI.md). The v1 read-only command and
configuration pass their real process/file lifecycle plus nine fail-closed
configuration and input-bound cases. The v2 live mode adds a four-read,
time/response-bounded `kubectl` collector with pre/post controller consistency,
pod ownership/readiness checks, and a namespace-scoped example RBAC grant. Its
process harness is project-controlled simulation evidence; Post-M30 later adds
a separate real local-cluster qualification.

Lifecycle evidence: [EVALUATION_LIFECYCLE](EVALUATION_LIFECYCLE.md). A bounded
single-host macOS/Linux manager atomically activates digest-bound
binary/configuration releases, verifies owner-only backups, preserves evidence
through rollback and uninstall, and passes the real five-phase lifecycle plus
ten unsafe/tamper refusals. Package-manager, service, power-loss, and
reproducible private-bundle qualification remain later gates.

Diagnostics evidence: [OPERATOR_DIAGNOSTICS](OPERATOR_DIAGNOSTICS.md). The
offline exporter verifies the managed release and owner-only evidence under
1,000-file/256-MiB bounds, emits only an explicit digest/size allowlist, and
passes a unique-secret non-disclosure check plus four fail-closed paths. Digests
remain sensitive correlators; this is not telemetry or independent privacy
assessment.

Bundle evidence: [PRIVATE_BUNDLE](PRIVATE_BUNDLE.md). The current macOS host
records bounded build time and peak child RSS, forced pre-publication
interruption leaves no bundle, recovery succeeds, and two independently built
ZIPs are byte-identical with a verified per-entry checksum manifest. This is
candidate engineering evidence, not signing custody, Linux/Kubernetes resource
qualification, power-loss proof, or independent validation.

## Post-M27 — signed private candidate boundary

- [x] Implement domain-separated Ed25519 signing and independently configured
  verification for the exact private bundle bytes.
- [x] Bound bundle, signature, identity, key-set, and validity-window inputs and
  refuse tamper, substitution, ambiguity, unsafe key files, and stale evidence.
- [ ] Establish an operational release-signing identity and independently
  governed private-key custody.
- [ ] Freeze, sign, and independently assess the exact evaluation candidate.

Protocol evidence: [PRIVATE_BUNDLE](PRIVATE_BUNDLE.md). Tests use an ephemeral
fixture key only. Implementing the signing boundary does not establish custody,
produce a release signature, or satisfy independent assessment.

## Post-M28 — commit-bound candidate ceremony

- [x] Bind the canonical full source commit into the deterministic bundle.
- [x] Prove commit substitution changes the bundle and malformed identities
  refuse without publication.
- [x] Define a two-custodian-ready offline signing, verification, transfer, and
  abort procedure without creating operational credentials.
- [ ] Execute the ceremony with an approved operational identity and custodians.

Evidence: [CANDIDATE_SIGNING](CANDIDATE_SIGNING.md) and
[PRIVATE_BUNDLE](PRIVATE_BUNDLE.md). Project-controlled qualification proves the
mechanism only; it does not satisfy the operational or independent gates.

## Post-M29 — reproducible candidate build provenance

- [x] Rebuild the locked/offline release binary in two isolated target trees and
  require byte identity under explicit time, output, and resource bounds.
- [x] Retain commit, clean-tree, binary, toolchain, target, and resource evidence
  and prove altered-binary detection.
- [x] Require the candidate ceremony to match the bundle binary to a clean-tree
  provenance record for the same commit.
- [ ] Obtain an independent and cross-platform reproducible build.

Evidence: [BUILD_PROVENANCE](BUILD_PROVENANCE.md). The qualification is
same-host and project-controlled; compiler/dependency trust and hermeticity are
not established.

## Post-M30 — real Kubernetes end-to-end qualification

- [x] Exercise the complete evaluation CLI against a disposable real Kubernetes
  API server using namespace-scoped service-account credentials.
- [x] Prove real RBAC permits only required reads and denies mutation and Secret
  access while the target remains unchanged.
- [x] Refuse authority mismatch and real API-server outage without evidence,
  under bounded time/memory and deterministic cluster cleanup.
- [ ] Qualify managed clusters, extended capacity/load, additional versions, and an
  independently operated environment.

Evidence: [KUBERNETES_REAL_CLUSTER](KUBERNETES_REAL_CLUSTER.md). This closes the
real local-cluster gap, not the managed-platform or independent-validation gates.

## Post-M31 — OpenTofu plan evaluation integration

- [x] Evaluate a real saved OpenTofu plan through the stable read-only CLI
  without cloud credentials, external providers, or target mutation.
- [x] Bind the exact bounded plan bytes and version/resource metadata into a
  version-specific certificate extension.
- [x] Refuse destructive, sensitive, unknown, duplicate-replica, malformed,
  oversized, or authority-mismatched plan inputs before evidence persistence.
- [ ] Qualify external providers, remote state, large plans, additional OpenTofu
  versions, and an independently operated environment.

Evidence: [OPENTOFU_PLAN](OPENTOFU_PLAN.md). The real local lifecycle uses only
the built-in `terraform_data` resource and disposable local state. It establishes
plan parsing and evidence binding, not provider correctness or apply safety.

## Post-M32 — evaluation contract and capability reconciliation

- [x] Replace the stale single-mode contract field with an explicit bounded
  schema-to-mode inventory under a no-target-mutation authority boundary.
- [x] Publish the compiled capability inventory through the CLI and require
  exact agreement with the policy contract.
- [x] Refuse uncontracted, missing, mutation-capable, mutation-shaped,
  duplicate-schema, and authority-boundary-weakened variants.

Evidence: [EVALUATION_PRODUCT_DECISION](EVALUATION_PRODUCT_DECISION.md) and
`results/evaluation-contract-validation.json`. Contract v2 reconciles three
implemented read-only modes and passes six adversarial drift refusals. It does
not authorize production actuation, credentials, publication, or promotion.

## Post-M33 — complete three-mode private candidate input

- [x] Package all contracted Kubernetes shadow/live and OpenTofu plan
  configurations plus their operator, threat, example, and test-plan material.
- [x] Bind the supplied binary's bounded capability inventory, contract, source
  commit, and fixed contents into deterministic bundle manifest v3.
- [x] Refuse capability mismatch, malformed or oversized output, and timeout
  without publication; retain signing and independent assessment as explicit
  unsatisfied gates.

Evidence: [PRIVATE_BUNDLE](PRIVATE_BUNDLE.md). The deterministic qualification
reproduces the three-mode unsigned candidate input, validates every relationship,
survives interruption, binds source substitution, and passes four capability
refusals. No operational identity, signature, recipient, transfer, or independent
assessment is manufactured.

## Post-M34 — executable adversarial integration coverage

- [x] Register a bounded threat-by-mode coverage contract for every supported
  evaluation integration.
- [x] Require executable anchored evidence for every applicable required cell
  and explicit reasons for non-applicable or deferred cells.
- [x] Refuse omitted or duplicated threats, mode drift, missing required
  coverage, dishonest evidence references, excessive evidence, and weakened
  authority boundaries.
- [x] Bind the registry, validator, retained result, and open gaps into the
  deterministic private candidate input.
- [ ] Resolve compromised-consistent-producer gaps across the applicable modes.
- [x] Resolve sustained-adversarial-load gaps across the applicable modes.

Evidence: [ADVERSARIAL_COVERAGE](ADVERSARIAL_COVERAGE.md) and
`results/adversarial-coverage-validation.json`. Ten threat classes contain 23
covered cells, two explicit deferred cells, and five justified non-applicable
cells; eleven adversarial registry mutations fail closed. This inventory prevents
coverage overstatement but is not independent validation or a robustness proof.

## Post-M35 — sustained adversarial integration load

- [x] Run 16 one-byte-over-limit attacks per evaluation mode with four-way
  concurrency, per-case deadlines, and no evidence publication.
- [x] Bound total wall time, peak child RSS, diagnostic output, process count,
  input bytes, and retained-result drift.
- [x] Run eight additional real Kubernetes evaluations at four-way concurrency
  with separate evidence paths and verify the target remains unchanged.
- [x] Promote only the three sustained-load cells to covered and retain the
  compromised-consistent-producer cells as explicit gaps.

Evidence: [SUSTAINED_ADVERSARIAL_LOAD](SUSTAINED_ADVERSARIAL_LOAD.md) and
`results/sustained-adversarial-load.json`. The project-controlled bounded sample
is not a capacity forecast, managed-platform result, denial-of-service guarantee,
or independent validation.

## Post-M36 — authenticated observation-quorum primitive

- [x] Domain-separate Ed25519 signatures over exact observation bytes, subject,
  mode, producer identity, fault domain, and bounded validity.
- [x] Require canonical bounded trust/quorum documents and at least two distinct
  authenticated producer domains.
- [x] Exercise all three modes plus substitution, forgery, domain, time,
  identity, canonical-shape, and resource refusals.
- [ ] Make quorum verification mandatory in versioned evaluation schemas and
  bind the verified evidence digest into compatible certificates.
- [ ] Establish independently operated producer domains and key custody.

Evidence: [OBSERVATION_QUORUM](OBSERVATION_QUORUM.md) and focused tests in
`src/observation_quorum.rs`. This is a qualified protocol primitive; M37 applies
it to shadow evaluation while live and OpenTofu integration remain open.

## Post-M37 — corroborated Kubernetes shadow evaluation

- [x] Require a bounded canonical trust document and signed multi-domain quorum
  in the stable Kubernetes shadow evaluation schema v4.
- [x] Authenticate the exact snapshot bytes, subject, mode, signer identities,
  fault domains, and validity window before parsing or evidence persistence.
- [x] Bind the verified quorum evidence digest into certificate v9 while
  retaining readability of historical v9 certificates without the extension.
- [x] Package deterministic synthetic examples and a fixture generator, and
  prove forged quorum refusal without certificate or ledger output.
- [ ] Apply corroborated collection to Kubernetes live and OpenTofu evaluation.
- [ ] Establish independently operated producer domains and operational key
  custody; bundled fixture keys are public test material only.

Evidence: [OBSERVATION_QUORUM](OBSERVATION_QUORUM.md),
[EVALUATION_CLI](EVALUATION_CLI.md), and `tests/evaluation_cli.rs`. This closes
only the shadow-mode compromised-consistent-producer test cell under distinct
configured signing domains. It does not prove that those domains are genuinely
independent or truthful in deployment.

## Post-M38 — observation producer signing boundary

- [x] Expose domain-separated observation signing for exact bounded input bytes
  through a stable CLI command.
- [x] Require an absolute owner-only, single-link Ed25519 seed file and a new,
  non-colliding output path with owner-only atomic publication.
- [x] Expose public-key derivation without disclosing the private seed.
- [x] Prove two independently invoked CLI attestations interoperate with the
  quorum verifier and refuse unsafe keys, oversized input, and output collision.
- [x] Define and integrate bounded independently collecting producer processes
  for Kubernetes-live evaluation.
- [x] Integrate separately invoked bounded renderer/signing producers for
  OpenTofu evaluation; operational independence remains a later gate.

Evidence: [OBSERVATION_QUORUM](OBSERVATION_QUORUM.md) and
`tests/observation_signature_cli.rs`. This establishes producer-side signing
mechanics, not producer independence, truthful collection, or operational key
custody; M41 completes the OpenTofu process integration without promoting an
adversarial coverage cell.

## Post-M39 — corroborated Kubernetes-live producer processes

- [x] Replace live configuration v2 with v5 requiring a bounded trust document
  and two to eight external observation-source commands.
- [x] Require every producer's canonical snapshot to exactly equal the primary
  four-read collector snapshot before multi-domain signature verification.
- [x] Bind the verified quorum digest into certificate v9 and persist no
  evidence on disagreement, forgery, malformed or oversized output, timeout,
  invalid quorum, or path collision.
- [x] Exercise two separately invoked producer collectors against a disposable
  real Kubernetes API server and under concurrent evaluation load.
- [ ] Establish separately operated clusters/control planes, credentials, hosts,
  and key custody for independent validation.
- [ ] Integrate independent OpenTofu plan producers.

Evidence: [KUBERNETES_REAL_CLUSTER](KUBERNETES_REAL_CLUSTER.md),
[OBSERVATION_QUORUM](OBSERVATION_QUORUM.md),
`tests/kubernetes_live_cli.rs`, and
`scripts/kubernetes-observation-producer.py`. M39 detects local collector and
envelope faults but retains the compromised-producer cell because every
qualified process still trusts one API server. External independence and
production custody remain open gates.

## Post-M40 — corroborated OpenTofu plan bytes

- [x] Replace OpenTofu configuration v3 with v6 requiring a bounded trust
  document and two to eight external exact-byte producer envelopes.
- [x] Require every producer plan to match the primary plan byte-for-byte before
  multi-domain signature verification and before plan parsing.
- [x] Bind the verified quorum digest into compatible certificate v10 evidence.
- [x] Refuse forged and disagreeing producer envelopes without certificate or
  ledger persistence while retaining destructive and authority mismatch checks.
- [ ] Establish separately operated provider/state observation paths and
  operational key custody.

Evidence: [OPENTOFU_PLAN](OPENTOFU_PLAN.md),
[OBSERVATION_QUORUM](OBSERVATION_QUORUM.md), and
`scripts/run-opentofu-plan.py`. M40 authenticates exact agreement between
configured producer processes; because the qualified producers consume the same
locally generated plan, the compromised-consistent-producer cell remains
deferred.

## Post-M41 — bounded OpenTofu producer process

- [x] Package a reference producer that independently invokes `tofu show -json`
  on an absolute regular single-link saved plan and signs the exact bytes.
- [x] Bound saved-plan, rendered-plan, attestation, stderr, and subprocess paths
  and refuse unsafe executable, plan, and key shapes.
- [x] Exercise two separately invoked producers through stable evaluation v6 and
  refuse renderer failure/timeout/malformed/oversized output, unsafe keys,
  symlinked plans, forgery, and byte disagreement without evidence publication.
- [x] Include the producer and production-shaped example arguments in the
  private evaluator bundle.
- [ ] Establish separately operated plan generation, provider/state/backend
  access, hosts, clocks, administrators, and operational signing custody.

Evidence: [OPENTOFU_PLAN](OPENTOFU_PLAN.md), [OPERATIONS](OPERATIONS.md),
`scripts/opentofu-observation-producer.py`, and
`scripts/run-opentofu-plan.py`. M41 replaces static success fixtures with real
renderer/signing processes. The local qualification still shares one saved
binary plan and host, so it does not promote the compromised-consistent-producer
coverage cell or satisfy independent validation.
