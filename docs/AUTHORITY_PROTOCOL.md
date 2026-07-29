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
validity checks, SHA-256 content binding, exact-one cardinality for phenotype,
and one-or-more goal and viability envelopes with unique issuers. Goal principals
must agree exactly. When goal or viability is suspectable, hypotheses exclude
complete declared fault domains and bind their domains and issuer exclusions
into the certificate. At least one agreeing goal issuer and one viability issuer
must survive their respective exclusions; all surviving viability rules must
approve the common transition.

Signed bytes use deterministic serialization of typed fields and ordered maps.
The harness does not yet maintain issuer history, detect equivocation across runs,
validate organizational independence, rotate keys, or use a standardized
cross-language canonical JSON format.

Phenotype history is the first exception: certificate v2 verifies a bounded
single-issuer chain against a trusted monotonic tip anchor and exposes every
retained digest. See [AUTHENTICATED_HISTORY](AUTHENTICATED_HISTORY.md). The anchor
remains research configuration rather than a durable production checkpoint.

Certificate v3 binds viability fault-domain exclusions as well as issuer
exclusions. Domain mappings are trusted scenario configuration and are validated
before bounded enumeration. See [CORRELATED_FAULTS](CORRELATED_FAULTS.md).

Certificate v5 adds goal fault-domain exclusions. Missing, empty, unknown, or
inapplicable goal mappings and authenticated goal disagreement fail closed before
checker work. See [MULTI_PRINCIPAL_GOALS](MULTI_PRINCIPAL_GOALS.md).
