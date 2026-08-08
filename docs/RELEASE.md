# Release Strategy

There is no production release yet. Private evaluation-product engineering is
authorized by [EVALUATION_PRODUCT_DECISION](EVALUATION_PRODUCT_DECISION.md).
The historical `v0.2.0-rc.1` and `v0.2.0-rc.2` candidates passed their
project-controlled freezes, then were revoked when repository history was
privacy-rewritten. The exact rc.2 evidence is retained in
[RC2_FREEZE_RECORD](RC2_FREEZE_RECORD.md), but neither old tag exists in the
replacement repository and neither candidate is distributable. No public
artifact distribution is authorized by the private evaluation decision alone.
Research or evaluation releases require:

1. frozen protocol and fault model;
2. reproducible harness and locked dependencies;
3. complete baseline and adversarial results;
4. security and soundness review;
5. refreshed novelty/name diligence;
6. explicit limitations and negative results.

Public hosting, packages, telemetry, production adapters, and production claims
are separately gated.

The 2026-07-29 M3 decision narrowed the project after a weakened-viability unsafe
approval. That approval was subsequently removed across the registered fixtures
and finite generated state space. On 2026-07-30, an explicit decision authorized
a private read-only evaluation lane so an operational candidate can be built
before independent validation. It did not authorize a tag, artifact
distribution, public release, production actuation, hosted CI, or safety claim.

Certificate v4's stable-key safety kernel removes the original and cross-domain
unsafe approvals across all retained fixtures and the 512 generated scenarios.
The release block remained in force at certificate v5 because this finite
evidence is not a general safety proof, authenticated disagreement fails closed,
authorized deletion had no protocol, third-party organizational reproduction and
review were missing, domain independence was unverified, and no new explicit
release decision had been made.

Certificate v6 subsequently adds exact context-bound deletion authorization.
Certificate v7 adds bounded, atomic one-shot consumption to the single-host
anchored path. The release block remains because production actuation,
independent review/reproduction, platform-qualified durable storage, and
verified organizational domain separation are still absent.

Certificate v8 adds a transactional file-backed reference actuator and auditable
before/after state digests. It removes the pure-simulation limitation only for
that bounded local backend; external production actuation and its operational
qualification remain blocked.

Actuator schema v2 adds measured macOS/aarch64 recovery, exact-latest backup
restore, and rollback detection against a co-located witness. This does not
qualify whole-disk recovery, other platforms, hostile storage, multiple hosts,
or an external production service, so the release block remains.

Pinned offline Linux arm64 and emulated amd64 containers subsequently reproduce
the recovery-state and forced-termination suites on Docker-managed volumes.
This removes the macOS-only software-path limitation for that VM boundary, but
does not qualify bare-metal power loss, device caches, hostile storage,
multi-host operation, or external actuation. The release block remains.

The bounded authority lifecycle protocol adds recovery-root-authorized rotation,
expiry, revocation, and compromised-operational-key recovery. Its roots and tips
remain trusted scenario configuration without durable organizational custody or
ceremony. It narrows static-key risk but does not satisfy independent review,
production identity, or release gates.

Certificate v9 adds a credential-free exported Kubernetes shadow mapping. It
does not contact or mutate a cluster and therefore does not qualify Kubernetes
authorization, live-watch consistency, admission behavior, or production
actuation. The release block remains.

Seven offline incident drills now pass and are retained. They do not substitute
for independent, infrastructure, or organizational incident exercises, so the
release block remains.

Four bounded parser corpora now pass with retained minimized rejection fixtures.
They are deterministic mutation evidence, not coverage-guided fuzzing,
sanitizer-backed assessment, arbitrary-input proof, or independent review. The
release block remains.

The commit- and digest-bound assessor handoff reproduces local CI plus retained
incident/parser aggregates from a fresh local clone. This makes independent
assessment easier but is not third-party reproduction or review; it does not
change the release decision.

The locked supply-chain inventory records all resolved package versions,
registry checksums, sources, and declared licenses. A current named RustSec
snapshot reports no known finding for the lockfile. This is time-bounded advisory
matching, not dependency or build-system assurance, so the release block
remains.

Bounded trusted-time checks now reject enrolled lifecycle evaluation outside an
explicit maximum-300-second window, and the credential-free recovery-root
rehearsal exercises quorum, exclusion, veto, and malformed-vote paths. These
local controls do not supply an authenticated production clock, participant
identity, private-key custody, organizational independence, or a real ceremony.
They therefore do not remove the independent-assessment or production-identity
release gates.

The compatibility corpus defines fail-closed support for legacy/current
scenarios and certificates v7–v11, with validate-then-regenerate migration.
Unknown future semantics remain intentionally unsupported, and no independent
downstream consumer has yet been qualified. This reduces accidental migration
ambiguity but does not change the release decision.

A separately implemented Python reader now agrees on v7–v11 acceptance and
bounded refusal classes. All five versions remain active. Deprecation requires
an evidenced successor, measured consumer usage, validated migration, two later
completed milestone windows, and explicit approval; removal additionally
requires zero registered consumers and a separately approved major
research-protocol compatibility change. This local qualification is not
third-party assessment and does not authenticate certificate origin.

Detached certificate attestation now authenticates exact v7–v11 evidence bytes
under bounded Ed25519 signer windows, and the Rust/Python qualification has zero
disagreements across rotation and five refusal paths. This removes the purely
unauthenticated-file limitation only when callers explicitly require and verify
an attestation. Production custody, trusted timestamping, revocation,
organizational identity, and independent cryptographic assessment remain absent,
so the release block remains.

Separate timestamp and revocation authorities now constrain post-revocation
backdating when exact trusted tips are independently retained. Rust/Python
qualification agrees across seven historical and refusal cases. Keys, clock,
tips, and distribution remain local fixtures without durable independent
operation or availability qualification, so the release block remains.

Trusted tips now have transactional local persistence, exact-latest restore, and
pinned offline Linux arm64/amd64 filesystem qualification. A deterministic
three-attempt, 250 ms distribution model records availability under bounded
delay and one-sided partition while refusing loss, outage, over-budget response,
and equivocation. No independently operated service, custody, real-network
measurement, or power-loss qualification exists, so the release block remains.

An isolated loopback HTTP harness now exercises separate authenticated timestamp
and revocation processes through ten live success/fault paths before the existing
cryptographic verifier. This adds transport-shaped evidence without granting
endpoint mutation authority. All processes, credentials, keys, and execution
remain project-controlled and TLS/live-network/independent-operator evidence is
absent, so the release block remains.

A commit- and digest-bound Post-M25 operator request plus strict returned-record
validator now prepares the independent witness exercise. The validator refuses
thirteen policy, origin, freshness, path, schema, and digest faults but cannot
verify real identity or organizational independence. No independently signed
record or raw operator evidence has been returned, so the release block remains.

The machine-checked evaluation contract authorizes stable interfaces, live
read-only observation, lifecycle packaging, diagnostics, and private candidate
preparation. Candidate readiness has eight separate gates. Production promotion
has six further gates, including independent assessment of the exact candidate,
remediation, production adapter evidence, identity/custody design, and a new
explicit decision. Until those gates pass, Telosieve remains evaluation software
with no production mutation authority.

Contract v2 now enumerates the three implemented read-only configuration modes
and binds them to the capability inventory emitted by the compiled CLI. Six
adversarial mutations prove uncontracted, missing, mutation-capable,
mutation-shaped, duplicate-schema, and weakened-boundary variants refuse. This
reconciles policy with Kubernetes shadow/live and OpenTofu plan evaluation; it
does not expand the no-target-mutation authority boundary.

The stable `evaluate` command accepts the exported-snapshot v1, live read-only
Kubernetes v5, and saved OpenTofu plan v6 configurations, and emits
`telosieve.evaluation-report/v1` after persisted read-only shadow evidence.
Unknown versions, mutation modes, oversized files, invalid paths, and output
collisions refuse. Live collection performs four bounded `kubectl get` calls,
checks controller stability plus Pod ownership/readiness, and ships a
least-privilege example Role. Its fake-process evidence is now supplemented by
the Post-M30 disposable real-cluster qualification. This completes candidate
engineering gates, not a managed or independently operated cluster and not a
candidate release.

OpenTofu v6 now packages a bounded reference producer that separately invokes
`tofu show -json` for a saved binary plan and signs the exact rendered bytes.
The real local harness exercises two producer processes and fail-closed renderer,
timeout, unsafe-key, symlink, forgery, and disagreement faults. Both processes
still share one host and saved plan, so this is integration evidence rather than
independent provider/state/backend or signing-custody evidence.

The private bundle now includes an authenticated Unix relay/client and hardened
systemd template for running each observation producer under a separate Linux
identity without granting its keys or platform credentials to the evaluator.
Local qualification covers relay authentication, bounds, cleanup, and unit
drift under one UID. Real systemd, multi-UID, multi-host, credential-custody, and
independent-operation evidence remain required.

The private lifecycle manager now packages a caller-supplied local binary and
strict evaluation configuration as an immutable digest-bound release. It
atomically activates install, upgrade, and verified rollback; creates a bounded
checksummed backup including evidence; and uninstalls managed software only
after exact canonical-root confirmation while preserving evidence. The real
local lifecycle and ten refusal paths pass in authoritative local CI. This
completes the lifecycle procedure gate, but is not a package, distributed
artifact, service installation, power-loss qualification, or candidate release.

The offline operator-diagnostics tool now verifies a managed installation and
exports only release/configuration digests plus opaque evidence digest/size
records under 1,000-file and 256-MiB bounds. A unique-secret regression proves
zero direct content/path disclosure and four unsafe export paths refuse.
Digests remain sensitive correlators, and this does not provide telemetry,
raw-evidence packaging, or independent privacy assessment.

Deterministic private bundle assembly now fixes entry selection, ordering,
timestamps, modes, and compression and binds every file by SHA-256. Manifest v3
adds all four contracted modes, exact binary capability/contract/config/test
plan agreement, and an unsigned candidate profile. Two builds are byte-identical;
four capability faults and forced pre-publication termination leave no output,
and a retry recovers the same digest under measured local resource bounds. The
bundle is not operationally signed or released, and cross-platform plus
independent qualification remain required.

## CI and delivery policy

Telosieve is private, so local CI is the sole authoritative quality gate:

```sh
./scripts/ci-local.sh
```

Every milestone is developed on a scoped feature branch, validated with that
command, pushed, reviewed through a pull request, and squash-merged. The command
must pass again at the final reviewed head. Its result is recorded in the pull
request. Absent hosted checks are policy-compliant and must never be represented
as passing hosted CI.

Hosted CI is disabled by policy. It may be introduced only at a documented
public-opening or research-release gate with explicit user approval and a review
of workflow permissions, secrets, cost, dependency provenance, and untrusted
pull-request behavior. A visibility change alone does not authorize hosted CI.

The bundle-signature protocol authenticates exact candidate bytes against a
separately supplied context, time, signer, key identifier, and public key. Test
keys are ephemeral. Promotion still requires approved operational signing
identity and custody, a frozen signed candidate, and independent assessment;
protocol availability must not be described as a signed release.

Candidate bundles use manifest version 3 and bind the canonical full source
commit. Follow [CANDIDATE_SIGNING](CANDIDATE_SIGNING.md); an executed ceremony
requires explicit operational identity/custody approval and does not waive the
independent assessment gates.

Candidate signing additionally requires a clean-tree same-commit reproducible
build record and exact bundled-binary digest match. Same-host qualification does
not satisfy the independent rebuild or toolchain-trust gates.

The live Kubernetes evaluator now passes a real disposable v1.36.1 API-server
and RBAC lifecycle through two authenticated producer relays, including
authority-mismatch, API-outage, and relay-outage refusal. This does
not qualify managed clusters, production-scale load, production credentials, or
independent operation.

The observation relay now passes a pinned offline Linux qualification with two
real non-root producer UIDs, distinct client groups, authorized evaluator
access, and cross-identity refusal. This closes the local kernel-identity gap,
not the systemd, multi-host, credential-custody, producer-truth, or independent
operation gates.

The candidate pre-freeze manifest now binds all eight readiness gates to
concrete packaged evidence and authoritative local-CI commands. Seven gates are
locally verified; exact-byte signing remains explicitly pending candidate
freeze. The manifest cannot be used to claim that an unsigned bundle is a
release candidate.

Version `0.2.0-rc.1` adds an atomic private freeze workflow that requires clean
reviewed `master`, an exact reproducible binary digest, an owner-only external
key, and a maximum 30-day signature window. It emits a seven-file handoff with
bundle, detached signature, public trust, release notes, candidate manifest, and
checksums plus a checksum-bound offline verifier. The reviewed commit
`3c5dea314eb849cbf441f9baa8c589a6d83bd412` was frozen and tagged
`v0.2.0-rc.1` as a signed private evaluation candidate. This authenticates the
candidate bytes but does not satisfy independent assessment, production
promotion, public release, or operational identity-custody gates. Assessors must
follow [EXTERNAL_ASSESSMENT](EXTERNAL_ASSESSMENT.md), including independent
authentication of the trust record before signature verification.

The immutable signed `v0.2.0-rc.1` handoff remains historical. Current source
targets `v0.2.0-rc.2`, incorporating the standardized integration contract,
configuration v7, certificate v11, concrete read-only integrations, PKI
qualification, mandatory quorum capability declarations, and corroborated
Kubernetes/OpenTofu evidence. None of that post-rc.1 work becomes candidate
evidence until the exact rc.2 commit is separately frozen and signed. The
generic conformance suite does not qualify arbitrary integrations or authorize actuation.

Post-candidate Redis integration now supplies the first concrete Contract v1
collector and a pinned disposable Redis 8.8 qualification. Three distinct ACL
users are technically restricted to reads, including explicit denied mutation
attempts, and two producers corroborate the primary response under bounded
concurrent load. All identities still share one project-controlled Redis server
and host; this is not independent evidence, production credential custody, or a
new signed candidate.

Post-candidate PostgreSQL integration adds a bounded `psql` collector, pinned
real PostgreSQL 18.4 qualification, three SELECT-only roles, atomic read-only
snapshots and concurrent-writer evidence. It is not part of `v0.2.0-rc.1`; all
qualified readers share one project-controlled database and host.

Post-candidate HTTP/JSON integration adds a fixed-GET adapter and an orchestrated
loopback endpoint qualification. It is not part of `v0.2.0-rc.1`, does not
qualify TLS or public-network deployment, and is not independent evidence.

Post-M52 extends that post-candidate integration with locally qualified TLS 1.3
mutual authentication and downgrade refusal. It does not change or re-sign the
frozen candidate and does not claim operational PKI or external endpoints.

Post-M53 adds post-candidate CRL enforcement plus local certificate rotation and
revocation qualification. It remains project-controlled PKI evidence only.

Post-M54 adds a post-candidate offline PKI readiness command; it does not alter
the frozen candidate or establish external monitoring.

Post-M55 packages scheduler-neutral PKI monitoring and hardened systemd units.
It does not claim an independently operated alerting destination.

Post-M56 packages a fail-closed Prometheus textfile publication boundary. It
does not claim independently operated scraping, routing, retention or response.

Post-M57 makes mandatory quorum and compatible certificate bindings explicit in
compiled capabilities and product contract v3. It preserves historical
certificate readability and does not claim independent producer operation.

Post-M58 explicitly qualifies quorum digest binding in every successful real
Kubernetes certificate and in direct and relayed OpenTofu certificates. It does
not establish independent producer administration or platform truth.

The 2026-08-08 public-opening decision authorizes Apache-2.0 source publication
only after productisation, a successor-candidate freeze from the sanitized
graph, and a final bounded history audit pass. The history migration and audit
are complete; the successor freeze remains pending. It does not authorize hosted
CI, package or container publication, telemetry, production deployment, or stronger claims. Hosted CI
still requires every approval and review listed in the private-repository policy.

The 2026-08-08 productisation decision approves enduring brand identity `2.0.0`.
Evaluation and release-candidate status are separate maturity overlays rather
than variants of the canonical product identity. The
asset manifest, canonical SVGs, design tokens, channel templates, deterministic
exports, accessibility checks, and prohibited-claim scan travel with the successor candidate.
Product identity does not close independent assessment, operational identity,
legal name/mark clearance, raster cross-platform equivalence, or production gates.

The historical `v0.2.0-rc.2` evaluation freeze was authorized by
[RC2_EVALUATION_RELEASE_DECISION](RC2_EVALUATION_RELEASE_DECISION.md) only for
the named project-controlled signer, maximum 30-day window, approved evaluator
recipients, private create-new handoff, and separately authenticated trust
digest. The reviewed clean commit, local CI, reproducible binary, signed handoff,
offline verification, and annotated tag must all agree or the ceremony aborts.
