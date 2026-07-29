# Authority Protocol v0

An authority envelope contains `kind`, `subject`, `schema_version`, `issued_at`,
`expires_at`, `issuer`, `sequence`, `content_digest`, `parent_digests`, and
`signature`. Kinds are `goal`, `phenotype`, and `viability`.

A decision binds:

- the complete envelope digest set;
- the declared maximum number and classes of faulty authorities;
- each enumerated hypothesis;
- evidence excluded under that hypothesis;
- proposed transition and rollback;
- checker implementation identity and verdict;
- refusal reason when no uniquely safe plan exists.

Two valid envelopes from one issuer with the same sequence and different content
are equivocation evidence. Unknown schemas, broken lineage, expired evidence, and
missing independence metadata are invalid. Acceptance requires at least one plan
safe under every non-eliminated hypothesis; disagreement or underdetermination
requires refusal.

The harness implements the fields above, Ed25519 authentication, subject and
validity checks, SHA-256 content binding, exact-one cardinality for goal and
phenotype, and one-or-more viability envelopes with unique issuers. When viability
is suspectable, hypotheses exclude individual viability issuers and bind those
issuer exclusions into certificate v1. All surviving viability rules must approve
the common transition.

Signed bytes use deterministic serialization of typed fields and ordered maps.
The harness does not yet maintain issuer history, detect equivocation across runs,
validate organizational independence, rotate keys, or use a standardized
cross-language canonical JSON format.

Phenotype history is the first exception: certificate v2 verifies a bounded
single-issuer chain against a trusted monotonic tip anchor and exposes every
retained digest. See [AUTHENTICATED_HISTORY](AUTHENTICATED_HISTORY.md). The anchor
remains research configuration rather than a durable production checkpoint.
