# Authority Key and Identity Lifecycle

Date: 2026-07-30

## Contract

Key lifecycle is opt-in per issuer. An enrolled issuer has:

- one existing bootstrap operational key in `public_keys`;
- one distinct offline recovery-root public key;
- a contiguous recovery-root-signed lifecycle chain;
- a trusted anchor containing the exact chain sequence and tip digest; and
- a trusted-time window no wider than 300 seconds containing the evaluation
  time; and
- one authority kind and subject for the lifetime of the chain.

Every signed statement is domain-separated by
`telosieve.key-lifecycle/v1`. An `activate` statement names a fresh canonical
Ed25519 public key, its effective time, and an exclusive expiry. A `revoke`
statement names the digest of the currently active operational key. The recovery
root can activate a fresh key after revocation, so recovery does not depend on a
compromised operational key.

Recovery roots cannot be operational keys, be activated later, or be shared by
two enrolled issuers in one scenario. Operational keys cannot be reused after
rotation or revocation. Public keys use canonical lowercase hexadecimal
encoding, preventing alternate encodings from bypassing reuse detection.

## Verification semantics

Historical phenotype records are verified with the operational key active at
their `issued_at` time. Later rotation, expiry, or revocation therefore does not
erase valid historical evidence.

Current goal, phenotype, viability, and deletion evidence must satisfy both:

1. its signature verifies with the key active at issuance; and
2. that same key remains active and unexpired at `evaluation_time`.

Evidence signed by a superseded, expired, or revoked key cannot authorize a new
transition. Missing roots or anchors, lifecycle rollback, broken parents,
duplicate sequences, non-increasing effective times, kind/subject changes,
future statements, invalid signatures, wrong-key revocation, key reuse, and
non-canonical keys fail before planning or checker startup.

For any enrolled issuer, `evaluation_time` must lie within the inclusive
`trusted_time.not_before..=trusted_time.not_after` interval. The interval must be
ordered, no wider than 300 seconds, and name a non-empty bounded source. An
activation remains valid immediately before its exclusive expiry and is invalid
at the expiry. A revocation takes effect at its inclusive effective time.
Evaluation below the trusted lower bound, above the upper bound, or with an
over-wide interval refuses before authority verification.

The certificate authority-digest map binds every lifecycle statement, recovery
root, trusted anchor, and trusted-time assertion used for the decision.

## Bounds and failure policy

At most 64 lifecycle statements are accepted across a scenario. Verification is
bounded by the statement count plus envelope lookups over those statements; no
network or key-service call occurs. Lifecycle failure refuses the entire
scenario. There is no fallback to a superseded bootstrap key.

The bootstrap keys, recovery roots, lifecycle anchors, trusted-time assertion,
evaluation time, and issuer-to-organization assignment remain trusted scenario
configuration. The implementation checks local consistency and a maximum
window; it does not obtain time from an independent clock. Rolling the evaluation
time, window, roots, and tips back together is not detected. Recovery-root
compromise can authorize arbitrary future keys for that issuer. Hardware-backed
roots, durable multi-host lifecycle anchors, authenticated time, and real
organizational custody remain outside this research implementation.

## Evidence

The retained `scenarios/rotated-goal-key.json` fixture applies with a rotated
goal key and binds its lifecycle evidence into the deterministic certificate.
Protocol tests cover:

- rotation with old-key historical phenotype verification;
- rejection of superseded, expired, and revoked current keys;
- continued evaluation through another agreeing goal principal when revoked
  issuer evidence is absent;
- fresh-key activation after emergency revocation;
- exact expiry and revocation boundaries plus rollback, forward-jump, and
  over-wide trusted-time refusal;
- trusted-tip rollback, duplicate sequence/equivocation, signature tampering,
  kind mismatch, partial configuration, non-canonical encoding, self-recovery,
  and the 64-record bound.

All pre-lifecycle fixtures and the 512-scenario safety/availability oracle remain
unchanged because unenrolled issuers retain the legacy static-key behavior.
Previously serialized enrolled scenarios without `trusted_time` still parse but
now fail closed during verification; this intentional compatibility boundary
prevents silent use of an unbounded evaluation clock.
