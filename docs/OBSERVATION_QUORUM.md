# Authenticated Observation Quorum

Date: 2026-07-31

Post-M36 implements the reusable cryptographic prerequisite for detecting one
internally consistent but false observation producer. The verifier accepts exact
input bytes only when at least two authenticated producers in distinct configured
fault domains sign the same subject, evaluation mode, SHA-256 digest, and bounded
validity window.

The protocol supports `kubernetes-shadow`, `kubernetes-live`, and
`opentofu-plan`. Trust and quorum documents are canonical compact JSON with exact
schemas. Ed25519 signatures are domain-separated from every other Telosieve
signature context. Trust binds each producer and key ID to one fault domain and
key-validity window; a quorum statement cannot relabel its domain. The returned
evidence digest binds the exact trust and quorum bytes for later certificate
integration.

Resource and failure bounds are fixed in `src/observation_quorum.rs`: observation
input is at most 4 MiB, each trust/quorum document at most 64 KiB, two to eight
participants, identifiers at most 128 ASCII characters, and an attestation
window at most 300 seconds. Every listed attestation must be valid. Unknown or
duplicate producers, ambiguous keys, shared or insufficient domains, stale or
future time, forgery, input/context substitution, unsupported modes,
non-canonical JSON, unknown fields, and resource excess fail closed.

Focused Rust tests accept two-domain corroboration for all three modes and refuse
input/subject substitution, signature tampering, domain relabelling, stale time,
unknown and duplicate identities, non-canonical documents, and oversized input.

This milestone does not yet resolve the registered compromised-producer cells.
The current evaluation schemas do not require quorum files, live collection does
not yet canonicalize its snapshot for quorum verification, and certificates do
not yet bind the returned evidence digest. A later migration must make those
steps mandatory before evidence persistence. Configured domain labels and test
keys do not establish real organizational independence, protected custody, or
truth when every participating domain colludes.
