# Threat Model

Assets are service viability, data integrity, authority history, signing keys,
decision integrity, and audit evidence.

Adversaries may control one declared authority, replay signed history, equivocate,
forge observations through an adapter, delay messages, trigger partitions, exploit
parser differences, or exhaust hypothesis computation. They may be an insider with
a valid signing key.

Initial exclusions are simultaneous compromise beyond the declared budget,
hardware/OS compromise of the checker, cryptographic breaks, arbitrary side
effects outside the simulator, and a malicious viability specification signed by
all trusted principals.

Controls include canonical encoding, domain-separated signatures, key rotation,
freshness/lineage checks, resource bounds, independent implementations,
transactional simulation, least privilege, append-only evidence, and fail-closed
timeouts.
