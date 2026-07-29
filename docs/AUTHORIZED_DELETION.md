# Explicit Authorized Deletion

Date: 2026-07-29

## Safety contract

Certificate v6 preserves the rule that absence is not deletion authorization.
A goal may remove a stable key only when separate deletion principals sign the
exact key set for the exact goal content and authenticated phenotype tip.

The acceptance criteria are:

- ordinary omission still refuses;
- authorized deletion applies only when authorization exactly equals the keys
  actually removed;
- authorization is signed by distinct issuers and mapped to declared fault
  domains;
- all deletion principals agree;
- a surviving authorization domain is required under every hypothesis;
- replay against another goal or phenotype tip, missing/unknown mappings,
  overbroad authorization, and fully excluded authorization fail closed;
- certificate evidence records the authorization used by each hypothesis; and
- existing generated oracles remain zero unsafe approvals and zero false
  refusals.

## Protocol and binding

`deletion` authority envelopes contain:

- `keys`: a non-empty ordered key set;
- `goal_digest`: SHA-256 binding to the decoded agreed goal; and
- `phenotype_tip_digest`: binding to the authenticated current phenotype tip.

Deletion evidence must be explicitly suspectable and every issuer must have one
non-empty `deletion_fault_domains` entry. The finite hypothesis engine excludes
complete deletion domains. If no deletion issuer survives, the authorized set is
empty and stable-key continuity refuses the transition.

Deletion issuers must be distinct from goal and viability issuers, and deletion
domain labels may not overlap goal or viability domain labels.

Both checker implementations independently derive the stable keys actually
removed. The supplied authorization must equal that set: missing keys violate
continuity and extra keys are rejected as non-exact. Certificate v6 records
`authorized_deletions` per hypothesis.

Envelope expiry and exact goal/tip binding prevent cross-context replay.
Certificate v7 subsequently adds single-host one-shot consumption for applied
deletions on the anchored path; see
[DURABLE_DELETION_CONSUMPTION](DURABLE_DELETION_CONSUMPTION.md). Stateless
research runs intentionally remain replayable.

## Evidence and bounds

The signed `authorized-deletion` fixture removes `user/message` and applies with
zero unsafe approvals. The identical goal in `unauthorized-deletion` refuses.
Tests also cover valid authorization replayed against a different goal,
overbreadth, missing mappings, and a shared domain whose exclusion removes every
authorization issuer.

The registered authorized path has five hypotheses and a 6,293-byte certificate.
The seven-fixture benchmark observed 14.8 ms p50 and 35.1 ms p95 for authorized
deletion on this machine. Work added by exactness checking is O(R × K + D), where
R is replica count, K is stable current keys, and D is authorized deletion keys.

Raw evidence is retained in `results/authorized-deletion-benchmark.json`.

## Residual risks

Distinct keys and labels do not prove organizational independence. The protocol
does not authorize deleting a key absent from any current replica, support
partial per-replica deletion, attest signer separation, qualify the local durable
store for multiple hosts or hostile storage, or actuate a production service.
Third-party reproduction/security review remains the next external gate.
