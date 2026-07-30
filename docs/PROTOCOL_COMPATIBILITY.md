# Protocol Compatibility and Migration

Date: 2026-07-30

## Support matrix

Telosieve retains one bounded compatibility corpus for the currently supported
research artifacts:

| Artifact | Accepted form | Required behavior |
|---|---|---|
| Legacy unenrolled scenario | No lifecycle or trusted-time fields | Parse and verify with static issuer keys |
| Current enrolled scenario | Lifecycle v1 plus bounded `trusted_time` | Parse, verify, and bind trusted time into authority evidence |
| Transitional enrolled scenario | Lifecycle v1 without `trusted_time` | Parse for diagnosis, then refuse verification |
| Certificate v7 | No actuation or shadow extension | Parse through the supported-certificate boundary |
| Certificate v8 | Actuation extension only | Parse through the supported-certificate boundary |
| Certificate v9 | Shadow extension only | Parse through the supported-certificate boundary |

Scenario objects reject unknown top-level fields. Authority and lifecycle
verification rejects unknown schema versions. The certificate compatibility
boundary rejects unknown top-level fields, versions other than v7–v9, and
extension shapes that do not match their version. A certificate is limited to
2 MiB before parsing.

This support statement covers retained serialized research artifacts, not a
promise that every historical development snapshot is accepted.

## Migration rule

Migration is **validate, then regenerate**. Telosieve does not rewrite signed
authorities, lifecycle statements, certificates, or evidence ledgers:

1. Preserve the source bytes and identify their schema/version.
2. Parse through the applicable bounded compatibility boundary.
3. Verify all original signatures, anchors, trust fields, and version-specific
   invariants.
4. If the artifact is supported, regenerate new decision evidence from the
   authoritative scenario and current execution boundary.
5. If a required trust field is absent or a future version/field is unknown,
   stop and obtain explicit migration logic through a reviewed protocol change.

Relabelling a certificate, dropping an unknown field, inventing trusted time, or
copying extensions between versions is not migration and fails closed. Historical
certificates remain immutable evidence; regenerated certificates are separate
artifacts and must not replace their originals in an append-only ledger.

## Bounds and evidence

Run:

```sh
./scripts/run-compatibility-corpus.sh
```

The corpus permits at most 16 cases, 2 MiB total bytes per vector group, and
2 MiB per certificate input. It runs two exact integration tests and emits
`results/compatibility-corpus.json` only after both pass. The full local CI gate
also runs these integration tests through `cargo test --all-targets`.

The v7 and v8 vectors are generated through their actual stateless and local
actuator boundaries. The v9 vector is the retained Kubernetes shadow
certificate. The scenario vectors use the retained legacy benign and current
enrolled fixtures plus deterministic mutations.

## Residual limits

The corpus detects known compatibility regressions; it is not a general schema
evolution proof. It does not validate certificate signatures because
certificates are deterministic evidence records rather than signed envelopes.
It does not migrate durable actuator schemas, external consumer databases, or
unknown future protocol semantics. Adding another supported version requires
explicit invariants, retained vectors, documentation, and a reviewed milestone.
