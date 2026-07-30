# Architecture

## Components

1. **Authority adapters** normalize goal, phenotype, and viability documents,
   including multiple goal and viability principals.
2. **Provenance verifier** checks identity, signature, lineage, freshness, and
   schema without deciding truth.
3. **Hypothesis engine** enumerates allowed fault sets under the configured budget.
4. **Planner** derives candidate transitions without consuming authorities marked
   suspect in that hypothesis.
5. **Independent checker** validates preconditions, stable-key continuity,
   viability invariants, blast radius, and rollbackability from a separately
   implemented model.
6. **Transactional actuator** applies only certified plans to the test service.
7. **Evidence ledger** records immutable inputs, hypotheses, decisions, and results.

## Trust boundaries

Adapters and the service are untrusted. Keys, schemas, the fault declaration,
checker, and ledger integrity form the initial trusted computing base. Planner and
checker may not share parsing or invariant-evaluation code. Correlated operator,
key, parser, and specification failures remain explicit residual risks.

## Data flow

Authorities → verification → hypotheses → candidate plans → independent checking
→ apply or refuse → outcome evidence. Every transition is content-addressed and
bound to the exact authority versions considered.

Verification optionally resolves an enrolled issuer through a bounded
recovery-root-signed key lifecycle before accepting its envelope. Historical
phenotype records use issuance-time keys; current evidence must still use the
evaluation-time active key. Lifecycle roots, statements, and trusted tips are
included in the certificate evidence digest map.
Enrolled lifecycle evaluation also requires a content-bound trusted-time window
containing the evaluation instant and no wider than 300 seconds. This bounds
local rollback/forward mistakes but does not create an independent clock.

Retained certificates cross a separate bounded compatibility boundary.
Certificate v7 accepts no execution extension, v8 requires actuation only, and
v9 requires shadow evidence only. Unknown versions, unknown top-level fields,
cross-version extension shapes, and inputs over 2 MiB fail closed. Migration
regenerates evidence from verified authoritative input rather than rewriting an
existing certificate.

The qualified downstream boundary is separately implemented in dependency-free
Python. It independently rejects duplicate/unknown/missing fields, invalid
top-level types, unsupported versions, confused extensions, malformed JSON, and
oversized input. This provides parser diversity for the compatibility envelope,
not full nested semantic or organizational independence.

Certificate authenticity is a detached trust boundary. A domain-separated
Ed25519 envelope signs the exact certificate-byte SHA-256 digest, context,
signer/key identity, issuance, and expiry without changing certificate v7–v9.
Verification is bounded by certificate/attestation bytes and at most eight
trusted keys. Both Rust and the independent Python reader implement the envelope
and signature checks.

Stronger authenticity adds two detached authorities without changing certificate
or attestation bytes: a signed hash-chained timestamp log anchored by an exact
trusted tip, and a signed revocation snapshot anchored by sequence and digest.
Historical evidence remains valid only when witnessed before revocation.

The Kubernetes shadow adapter is a pre-verification mapping gate for exported
ConfigMap/StatefulSet JSON. It requires exact equality with authenticated
goal/phenotype content and adds resource identity/version evidence to certificate
v9; it has no cluster client or actuation path.

## Failure behavior

Malformed, stale, equivocal, over-budget, or unverifiable evidence yields refusal.
Timeouts never degrade to “best effort.” Side effects are restricted to a
simulator until the safety case is supported.

## M0 implementation boundary

M0 is a single-process Rust harness. The service transition is a pure,
content-bound replacement of every named replica, so commit and rollback are
deterministic state values rather than production side effects. Hypothesis work is
bounded by `maximum_hypotheses`; every authority subset up to the declared budget
is enumerated deterministically and rejected before evaluation when the configured
bound is insufficient. M1 invokes a separately implemented Python checker over a
JSON process boundary. Post-M3 batching owns one checker process per scenario and
exchanges bounded NDJSON requests, avoiding per-hypothesis startup without sharing
planner code. Each response has a two-second timeout; failure aborts the run. The
checker independently parses and evaluates the service and viability models, and
differential tests compare it with the Rust reference checker.

Certificate v4 makes stable-key continuity intrinsic to both checker
implementations: every key present on every current replica must remain present
after transition. The bounded O(R × K) check is independent of viability
authority content; updates and additions remain allowed, while deletion requires
a future separately authorized protocol.

Certificate v5 requires exact agreement across authenticated goal principals.
Bounded hypotheses exclude complete declared goal domains; planning fails closed
if none survives. The harness validates mapping completeness but cannot attest
that labelled domains are operationally independent.

Certificate v6 adds deletion principals as a separate trust boundary. Their
agreed key set is bound to the exact goal and phenotype tip, excluded by declared
domains, and passed to both checker implementations. Each checker requires exact
equality with stable keys actually removed; no surviving deletion principal means
an empty authorization and refusal.

Certificate v7 derives a domain-separated identifier from the exact signed
deletion-envelope set. The anchored execution path evaluates first, then commits
the applied identifier and phenotype anchor together in the existing locked,
fsync-and-rename durable state. The stateless research path does not consume it.

The signed-history baseline verifies a maximum of 64 predecessor phenotype
envelopes against an explicit current-tip anchor before planning, then replays the
authenticated predecessor. The stateless harness anchor remains trusted
configuration; durable monotonic storage is provided only by the anchored path.

The anchored CLI path moves the current tip into a crash-synchronized local file
with explicit initialization, monotonic compare-and-advance, atomic replacement,
and fail-closed lock recovery. It remains a single-host prototype rather than a
distributed or hardware-backed trust root.

Certificate v8 adds an actuation receipt only to `apply-local` results. The local
reference actuator repeats observed-state and transition-precondition checks at
commit time, then atomically replaces service state, history anchor, and deletion
consumption under one lock. Refusal can advance history but cannot change service
values. This validates an adapter transaction contract, not an external service.

Actuator schema v2 wraps each state replacement with a separate
pending/committed witness containing the exact previous and next generation and
state digest. Recovery accepts only one of those states. Backups carry the typed
state and digest, while restore requires equality with the latest witness; the
witness itself is deliberately not restored from backup.
