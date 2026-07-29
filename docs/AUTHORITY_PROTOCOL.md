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

M0 implements the fields above, Ed25519 authentication, subject and validity
checks, SHA-256 content binding, and exact-one envelope cardinality for each
authority kind. Its signed bytes are deterministic serialization of typed fields
and ordered maps. M0 does not yet maintain issuer history, detect equivocation
across runs, validate non-empty lineage, rotate keys, or use a standardized
cross-language canonical JSON format; those remain M1 protocol obligations.
