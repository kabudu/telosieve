# Threat Model

Assets are service viability, data integrity, authority history, signing keys,
decision integrity, and audit evidence.

Adversaries may control one declared authority principal, replay signed history, equivocate,
forge observations through an adapter, delay messages, trigger partitions, exploit
parser differences, or exhaust hypothesis computation. They may be an insider with
a valid signing key.

Initial exclusions are simultaneous compromise beyond the declared budget,
hardware/OS compromise of the checker, cryptographic breaks, arbitrary side
effects outside the simulator, correlated viability-principal semantics, and a
malicious viability specification signed by all trusted principals.

Controls include canonical encoding, domain-separated signatures, key rotation,
freshness/lineage checks, resource bounds, independent implementations,
transactional simulation, least privilege, append-only evidence, and fail-closed
timeouts.

The post-M3 fault model authenticates distinct viability issuers and excludes one
issuer per bounded hypothesis. Distinct keys establish principal identity, not
organizational or implementation independence.

Certificate v3 groups viability issuers by declared fault domain. Correlated
failure inside one domain is covered; shared failure across every surviving
domain produced a retained unsafe approval in the v3 experiment.

Certificate v4 adds a viability-independent stable-key continuity kernel:
transitions cannot delete keys present on every authenticated current replica.
This removes the reproduced cross-domain unsafe approvals. It does not cover a
key omitted by every malicious phenotype replica, combined goal/phenotype
corruption beyond the declared bound, or an authorized-deletion use case.

Certificate v5 authenticates multiple goal issuers and excludes declared goal
fault domains. Goal values must agree exactly before planning; disagreement is
fail-closed. Separate keys and domain labels do not establish independent policy
authorship, custody, implementation, or deployment.

Certificate v6 authenticates separate deletion issuers and binds their exact key
set to the goal digest and phenotype tip. Cross-context replay, divergent
authorization, missing domains, and authorization overbreadth fail closed.
Certificate v7 derives an identifier from the exact signed deletion-envelope set
and consumes it atomically with the history anchor in the anchored path.
Stateless replay, organizational independence, and production side effects
remain outside scope.

Authenticated phenotype history rejects chain and anchor rollback within a
64-record bound. The trusted anchor is configuration in this harness; compromise
or rollback of that trust root remains outside the demonstrated protection.

The durable-anchor prototype detects store-level sequence rollback and conflict
under a trusted local filesystem. Filesystem compromise, malicious lock recovery,
disk firmware rollback, and multi-host split brain remain outside its protection.
The consumption ledger is bounded at 4,096 validated identifiers and its state
file at 512 KiB; either limit fails closed. Evidence failure after durable
consumption can burn an authorization; this is a deliberate availability loss
rather than permitting an uncertain replay.

The certificate-v8 local actuator prevents stale or concurrent evaluation from
committing by rechecking authenticated observed state and the transition
precondition under its lock. Its service state, history anchor, and deletion
ledger are one atomic file replacement. Local operator compromise, filesystem or
firmware rollback, unauthorized file access, and non-transactional external
adapters remain outside the demonstrated protection.

The schema-v2 recovery witness detects accidental stale primary-state restore and
resolves process termination before or after atomic replacement. It does not
resist rollback of both state and witness, witness deletion, forged local files,
or violated filesystem `fsync`/rename semantics. Exact-latest restore fails
closed if the co-located witness is lost.

Operational issuer keys may be rotated, expired, or revoked through bounded
recovery-root-signed chains. A compromised operational key cannot sign its own
recovery because roots must be distinct and are never operational. Recovery-root
compromise remains critical: it can authorize arbitrary future keys. Lifecycle
roots, trusted tips, evaluation time, and the bounded trusted-time assertion are
scenario configuration. Local rollback, forward-jump, and maximum-window checks
do not provide an independent clock; coordinated rollback of that configuration
remains outside the detected boundary.

The recovery-root ceremony model binds a strict-majority quorum to exact request
and evidence digests, retains the original quorum after exclusion, and treats
any veto as an abort. Its participant names and votes are unsigned local data.
It therefore demonstrates deterministic protocol behavior but not participant
identity, organizational independence, protected root-key custody, coercion
resistance, or a real authorization act.

The certificate compatibility boundary prevents unknown future versions,
unknown top-level fields, oversized inputs, and cross-version extension
relabelling from being treated as supported evidence. It does not authenticate
certificates, infer unknown future semantics, or protect a downstream consumer
that bypasses the boundary and deserializes the public structure directly.
Validate-then-regenerate avoids mutating historical evidence but cannot recover
missing authoritative inputs.

The Python reader reduces common-parser risk for version and top-level shape
decisions. Both implementations still follow one project-owned specification
and run on the same host, and the Python reader deliberately does not reproduce
all nested Rust types. A malicious certificate may therefore pass the envelope
reader yet fail later semantic processing. Neither reader authenticates who
created a certificate.

Detached Ed25519 attestation detects exact-byte tampering, certificate
substitution, cross-context replay, unknown signers, invalid signing windows,
and expiry. Key identifiers permit bounded rotation without rewriting historical
certificates. Compromise of a trusted private key remains critical: without an
external trusted timestamp or append-only witness, an attacker can backdate a
forged attestation inside that key’s declared window. Trust configuration,
evaluation time, signer identity, key custody, and revocation distribution
remain external.

The Python Ed25519 verifier is independently implemented for differential
qualification but is project-controlled and unaudited. Rust `ed25519-dalek`
strict verification remains the primary research implementation; neither
constitutes production HSM or organizational assurance.

The Post-M22 witness prototype bounds backdating after revocation by requiring a
separate signed timestamp observed before the inclusive revocation boundary.
Exact timestamp and revocation digests detect rollback and equivocation relative
to independently retained tips. Joint authority/tip compromise, malicious
clocks, unavailable distribution, and non-durable local tip configuration remain.

The Kubernetes shadow adapter has no client or cluster credentials. It rejects
resource-version/UID drift, partial or stale controller observations, oversized
exports, and output/input aliasing. A malicious or incoherent exporter that
fabricates a self-consistent snapshot remains outside the boundary; exact
agreement with signed Telosieve authorities is required but does not prove live
cluster truth.

Incident drills validate deterministic software responses, not operator timing,
hardware failure, hostile administrators, or multi-host disaster recovery.

Deterministic parser corpora bound test-case count and input bytes while
exercising malformed structures across four trust boundaries. They do not
replace coverage-guided fuzzing, sanitizers, arbitrary-input proofs, dependency
audits, or independent parser implementations.

The assessor handoff detects manifest drift, missing Git objects, artifact
digest changes, hosted workflow presence, dirty clean-checkout state, local-CI
failure, and operational-result divergence. It does not establish independence:
the repository, machine, dependency cache, and verifier are still controlled by
the project.

Locked dependency inventory detects package, source, checksum, and declared
license drift. RustSec matching detects only published advisories in the retained
database snapshot; it cannot detect unknown vulnerabilities, compromised
upstream releases or registries, malicious build scripts, license-text mismatch,
or toolchain compromise.
