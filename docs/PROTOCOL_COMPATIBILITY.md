# Protocol Compatibility and Migration

Date: 2026-07-30

The evaluation product adds a separate
`telosieve.evaluation-config/v1`/`telosieve.evaluation-report/v1` boundary.
Unknown configuration versions and modes refuse, and no automatic migration is
performed. Existing research CLI commands and certificate v7–v9 support remain
unchanged. See [EVALUATION_CLI](EVALUATION_CLI.md).

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

## Independent downstream reader

`scripts/certificate-reader.py` v3 is a dependency-free Python consumer. It shares
no Rust, Serde, certificate type, or parsing helper with the producer. It reads
at most 2 MiB from standard input, rejects duplicate JSON keys, validates the
complete top-level field set and version-specific extension, and emits only a
version, scenario identifier, input SHA-256 digest, implementation identifier,
and acceptance status. Qualification terminates each reader process after two
seconds.

Run:

```sh
./scripts/run-reader-qualification.sh
```

The differential test passes actual v7 stateless, v8 local-actuator, and retained
v9 shadow certificates through both readers. It also requires agreement on
future-version, unknown-field, missing-field, wrong-type, out-of-range integer,
confused-extension, duplicate-field, malformed-JSON, and oversized refusals. The
bounded aggregate is retained in `results/reader-qualification.json`.

This is implementation diversity on one project-controlled machine, not
third-party or organizational independence. The Python reader validates the
compatibility envelope and execution extension, not every nested semantic
invariant. When an attestation and trust file are explicitly supplied together,
v3 also independently verifies the detached
`telosieve.certificate-attestation/v1` envelope. Unsigned v7–v9 reading remains
available for historical compatibility and is never silently promoted to
authenticated evidence.

Reader v3 optionally accepts the all-or-nothing timestamp-chain,
revocation-snapshot, and witness-trust inputs. These detached schemas do not
alter certificate or attestation bytes; requesting witness verification never
falls back when any witness input fails.

## Deprecation and removal policy

Versions v7, v8, and v9 are **active**; none is deprecated. A version may become
deprecated only in a reviewed milestone that satisfies all of:

1. a supported successor exists with Rust and independent-reader vectors;
2. registered consumer and retained-artifact usage has been measured;
3. migration and rollback instructions are executable and locally validated;
4. the release, operations, compatibility, and threat-model documents announce
   the deprecation and its exact earliest removal milestone; and
5. the user explicitly approves the compatibility-policy change.

A deprecated version remains readable for at least two subsequently completed
roadmap milestones. Deprecation does not permit evidence rewriting.

Removal is a separate compatibility-breaking decision. It requires zero
registered active consumers, preserved access to the historical reader and
vectors, successful migration evidence for every registered retained artifact,
updates to both reader implementations and the compatibility corpus, explicit
user approval in the authorizing pull request, and classification as a major
research-protocol compatibility change in `docs/RELEASE.md`. A calendar date,
repository visibility change, or new version alone cannot trigger removal.
