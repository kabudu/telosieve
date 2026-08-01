# Authenticated Observation Quorum

Date: 2026-07-31

Post-M36 implements the reusable cryptographic prerequisite for detecting one
internally consistent but false observation producer. The verifier accepts exact
input bytes only when at least two authenticated producers in distinct configured
fault domains sign the same subject, evaluation mode, SHA-256 digest, and bounded
validity window.

The protocol supports `kubernetes-shadow`, `kubernetes-live`, and
`opentofu-plan`. Trust and quorum documents are canonical compact JSON (with an
optional final newline) with exact
schemas. Ed25519 signatures are domain-separated from every other Telosieve
signature context. Trust binds each producer and key ID to one fault domain and
key-validity window; a quorum statement cannot relabel its domain. The returned
evidence digest binds the canonical trust and quorum content.

Resource and failure bounds are fixed in `src/observation_quorum.rs`: observation
input is at most 4 MiB, each trust/quorum document at most 64 KiB, two to eight
participants, identifiers at most 128 ASCII characters, and an attestation
window at most 300 seconds. Every listed attestation must be valid. Unknown or
duplicate producers, ambiguous keys, shared or insufficient domains, stale or
future time, forgery, input/context substitution, unsupported modes,
non-canonical JSON, unknown fields, and resource excess fail closed.

Focused Rust tests accept two-domain corroboration for all four modes and refuse
input/subject substitution, signature tampering, domain relabelling, stale time,
unknown and duplicate identities, non-canonical documents, and oversized input.

Post-M37 makes the control mandatory for stable Kubernetes shadow evaluation
configuration v4 and binds the verified evidence digest into certificate v9.
`evaluation/observation-*.example.json` and the fixture generator use published,
deterministic test keys and must never be treated as operational credentials.
Post-M39 applies the protocol to Kubernetes-live through bounded external
producer processes, and Post-M40 applies exact-byte producer envelopes to
OpenTofu plans. Post-M41 packages the bounded producer that renders a saved
binary plan through OpenTofu before signing. Configured
domain labels do not establish real organizational independence, protected
custody, or truth when every participating domain colludes.

## Producer signing commands

Post-M38 adds the producer-side CLI boundary needed for later live integration:

```sh
telosieve observation-public-key /absolute/private-key.hex
telosieve observation-sign /absolute/observation.json \
  /absolute/private-key.hex kv/research kubernetes-live producer-a key-a \
  api-reader-a 1788000000 1788000300 /absolute/attestation.json
```

The private key must be a single-link, owner-only regular file containing a
32-byte hexadecimal Ed25519 seed. Input is an absolute regular file bounded to
4 MiB. The output must be a new absolute path distinct from input and key; it is
created through an owner-only temporary file and hard-link publication. The
command signs the exact input bytes and prints the same compact attestation
written to the output. Identifiers, supported modes, and the 300-second maximum
validity window use the verifier's existing bounds.

Each producer must execute this command in its own collection and key-custody
domain. Central generation of multiple attestations over a single collector's
bytes does not provide independent observation. The command deliberately emits
one attestation rather than asserting or assembling a quorum; the evaluator
compares independently obtained observations and verifies the combined quorum.
M38 proves CLI/library interoperability plus unsafe-key, oversized-input, and
output-collision refusal; M39 and M40 integrate bounded producer processes into
Kubernetes-live and OpenTofu evaluation respectively.
