# Attestation timestamp and revocation witnesses

Date: 2026-07-30

## Contract

`telosieve.attestation-timestamp/v1` is a separate-authority, Ed25519-signed
append-only record. It binds the exact attestation-byte digest, context,
observation time, monotonic sequence, and predecessor digest. Verification reads
the complete 1–64 record chain and requires its final sequence and digest to
equal an independently retained trusted tip. Omission, insertion, reordering,
rollback, and same-sequence replacement therefore refuse relative to that tip.

`telosieve.signer-revocations/v1` is a signed, 30-day-maximum snapshot containing
at most 64 unique `(signer, key_id, revoked_at)` entries. Trust binds both its
sequence and exact digest, preventing old-snapshot rollback and same-sequence
equivocation. Evaluation requires a currently valid snapshot.

An attestation remains historically verifiable when its timestamp observation
strictly precedes the inclusive revocation boundary. Observation at or after
`revoked_at` refuses. This prevents a compromised signer from creating newly
acceptable backdated evidence after revocation unless the independent timestamp
authority or its trusted tip is also compromised.

## Bounds and qualification

Each attestation, timestamp-chain, revocation, and trust file is capped at 64
KiB; timestamp and revocation collections are capped at 64 entries; the Python
reader has a two-second deadline. Both readers require all witness inputs
together and never fall back to attestation-only verification after witness
verification is requested.

Run `./scripts/run-witness-qualification.sh`. The retained seven cases cover
pre-revocation history plus inclusive revocation, tip rollback, revocation
equivocation, stale distribution, signature tampering, and omitted-chain
refusal with zero Rust/Python disagreements.

## Residual limits

All private keys are deterministic test fixtures. The trusted timestamp and
revocation tips are supplied configuration, not a durable external service.
There is no HSM custody, secure clock, gossip, multi-party log, availability
service, organizational identity, or independent implementation ownership.
Compromise or rollback of both a witness authority and its externally retained
tip defeats the corresponding protection.

Post-M23 adds optional local durable storage and bounded availability
qualification for these tips. See [WITNESS_DURABILITY](WITNESS_DURABILITY.md).
It does not turn the local fixture authorities into independent services.
