# Certificate Evidence Attestation

Date: 2026-07-30

## Contract

Certificate authenticity is an optional detached envelope. Existing unsigned
certificate v7–v9 bytes and compatibility behavior remain unchanged.

`telosieve.certificate-attestation/v1` contains:

- a canonical research context;
- the exact certificate-byte SHA-256 digest;
- signer and key identifiers;
- issuance and exclusive expiry times; and
- an Ed25519 signature.

Signing bytes are the ASCII schema string, one zero byte, and compact canonical
JSON containing every envelope field except `signature` in declared field order.
Context, signer, and key identifiers are limited to 128 ASCII characters from
letters, digits, `.`, `_`, `:`, `/`, and `-`. The signature cannot be replayed
under another context or against another certificate byte representation.

## Trust and rotation

Verification receives an explicit context, evaluation time, and 1–8 trusted
signer keys. Every `(signer, key_id)` pair must be unique. Public keys and
signatures use canonical lowercase hexadecimal Ed25519 encodings.

An attestation must be issued inside its selected key’s
`not_before..not_after` signing window. Evaluation must occur from issuance
through immediately before the attestation’s expiry. Attestation lifetime is
limited to 30 days.

Rotation retains old and new public keys with non-ambiguous key identifiers.
An old attestation remains verifiable after its signing key’s issuance window
closes, provided the attestation itself remains unexpired and the old public key
remains in the trust set. This preserves historical evidence without permitting
an envelope whose claimed issuance is after the old key’s declared window. A
compromised key can still backdate, as described under residual limits.

## Bounds and failure policy

Certificate input is capped at 2 MiB, attestation input at 64 KiB, trusted keys
at eight, attestation lifetime at 2,592,000 seconds, and each independent-reader
process at two seconds. Malformed or oversized input, invalid trust, unknown or
duplicate keys, digest mismatch, cross-context replay, invalid timing,
non-canonical material, or signature failure refuses. There is no unsigned
fallback when attestation verification was requested.

Run:

```sh
./scripts/run-attestation-qualification.sh
```

The retained result covers old/new rotation acceptance plus tampered signature,
wrong certificate, cross-context replay, expiry, and outside-key-window refusal
with zero Rust/Python disagreements. Rust uses `ed25519-dalek` strict
verification. The dependency-free Python reader v3 independently implements
canonical parsing, lifecycle checks, prime-subgroup point checks, and Ed25519
verification for qualification.

## Residual limits

The repository contains only deterministic test private keys. Post-M22 adds an
optional local timestamp/revocation witness prototype, but no production key
generation, custody, HSM integration, secure time, durable distribution,
transparency service, or organizational signer identity. A compromised key can
backdate within its declared window unless callers require the separately
anchored witness contract.

The pure-Python verifier provides implementation diversity but has not received
independent cryptographic review and is not presented as a production crypto
library. Certificate attestation authenticates exact evidence bytes; it does not
prove the truth of the certificate’s authorities, the safety of its decision, or
the identity independence of its signer.
