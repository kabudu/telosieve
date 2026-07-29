# Threat Model

Assets are service viability, data integrity, authority history, signing keys,
decision integrity, and audit evidence.

Adversaries may control one declared authority principal, replay signed history, equivocate,
forge observations through an adapter, delay messages, trigger partitions, exploit
parser differences, or exhaust hypothesis computation. They may be an insider with
a valid signing key.

Initial exclusions are simultaneous compromise beyond the declared budget,
hardware/OS compromise of the checker, cryptographic breaks, arbitrary side
effects outside the simulator, correlated viability-principal semantics, and a
malicious viability specification signed by all trusted principals.

Controls include canonical encoding, domain-separated signatures, key rotation,
freshness/lineage checks, resource bounds, independent implementations,
transactional simulation, least privilege, append-only evidence, and fail-closed
timeouts.

The post-M3 fault model authenticates distinct viability issuers and excludes one
issuer per bounded hypothesis. Distinct keys establish principal identity, not
organizational or implementation independence.

Certificate v3 groups viability issuers by declared fault domain. Correlated
failure inside one domain is covered; shared failure across every surviving
domain remains outside the bound and produces a retained unsafe approval.

Authenticated phenotype history rejects chain and anchor rollback within a
64-record bound. The trusted anchor is configuration in this harness; compromise
or rollback of that trust root remains outside the demonstrated protection.

The durable-anchor prototype detects store-level sequence rollback and conflict
under a trusted local filesystem. Filesystem compromise, malicious lock recovery,
disk firmware rollback, and multi-host split brain remain outside its protection.
