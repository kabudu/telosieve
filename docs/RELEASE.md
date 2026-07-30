# Release Strategy

There is no product release yet. Research releases require:

1. frozen protocol and fault model;
2. reproducible harness and locked dependencies;
3. complete baseline and adversarial results;
4. security and soundness review;
5. refreshed novelty/name diligence;
6. explicit limitations and negative results.

Version `0.1.0-research` may tag the first reproducible artifact. Public hosting,
packages, telemetry, production adapters, and claims are separately gated.

The M3 decision is to narrow the project to private research. The observed
weakened-viability unsafe approval blocks `0.1.0-research`, any public release,
and productisation. A tag or release requires a new explicit decision after the
reopening conditions in
[PRODUCTISATION_DECISION](PRODUCTISATION_DECISION.md) are satisfied.

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
scenarios and certificates v7–v9, with validate-then-regenerate migration.
Unknown future semantics remain intentionally unsupported, and no independent
downstream consumer has yet been qualified. This reduces accidental migration
ambiguity but does not change the release decision.

A separately implemented Python reader now agrees on v7–v9 acceptance and nine
bounded refusal classes. All three versions remain active. Deprecation requires
an evidenced successor, measured consumer usage, validated migration, two later
completed milestone windows, and explicit approval; removal additionally
requires zero registered consumers and a separately approved major
research-protocol compatibility change. This local qualification is not
third-party assessment and does not authenticate certificate origin.

Detached certificate attestation now authenticates exact v7–v9 evidence bytes
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
