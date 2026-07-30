# Witness Operator Handoff

## Purpose

Post-M25 requires evidence from an independently administered timestamp and
revocation service. The repository cannot create that independence itself.
`assessment/witness-operator-request.json` freezes the M24 source commit,
commands, source artifacts, expected outcomes, and resource limits that an
external operator must use. It contains no credentials or endpoint secrets.

The request deliberately targets commit
`c8b18a748204c8b617230ccfc18a793550055956`. The later handoff wrapper cannot
include its own Git object ID without becoming self-referential.

## Operator procedure

The operator must receive the private source through an approved read-only
channel, verify the request with the repository validator, and use
operator-generated credentials on operator-administered infrastructure. The
operator then:

1. checks out the exact requested commit with locked dependencies;
2. runs the three commands in the declared order, using local CI only;
3. integrates distinct HTTPS timestamp and revocation origins;
4. exercises all three success and seven fail-closed cases;
5. records identity, conflicts, custody, clock, network, host, and incident
   ownership;
6. returns a record plus sorted, digest-bound attachments below the declared
   count and byte limits; and
7. includes a digest-bound detached signature and its format, signer identity,
   and key fingerprint, using a verification channel agreed with the assessor.

The repository does not prescribe a signature format because the assessor, not
the project, must choose and verify the operator identity root. A self-asserted
key bundled with the record is not evidence of independence.

Validate the returned record from the directory containing its attachments:

```sh
python3 scripts/witness_operator_record.py /path/to/record.json
```

The validator checks the frozen Git objects, exact request digest, strict schema,
time ordering, explicit independence assertions, private-repository CI policy,
two distinct HTTPS origins, exact outcome sets, attachment containment, byte
bounds, SHA-256 digests, and binding of detached-signature metadata to a listed
attachment. It rejects unknown fields.

## Acceptance boundary

A structurally valid record is necessary but not sufficient for Post-M25. Before
checking either Post-M25 item, a human assessor must independently verify:

- the operator's real identity and organizational separation;
- custody of endpoint credentials and returned evidence;
- endpoint administration, clock source, network path, and incident owner;
- the detached signature through a separately trusted channel; and
- that raw attachments substantiate every declared result.

Project members must not populate a record and describe it as independent. The
synthetic qualification record exists only in a temporary directory and is
labelled non-independent.

## Failure and resource bounds

Records are capped at 64 KiB. At most 16 attachments of at most 1 MiB each are
accepted. Execution may span at most 24 hours and the operator must complete the
record within seven days. Paths are relative, unique, sorted, and unable to
escape the record directory. No network request, secret handling, endpoint
mutation, or automatic trust decision occurs during validation.

`scripts/qualify-witness-operator-record.py` accepts one conforming synthetic
record and refuses wrong-request, project-controlled, same-origin, insecure,
missing-fault, hosted-CI, digest-mismatch, path-traversal, stale-completion,
unknown-field, oversized-attachment, symbolic-link, and unbound-signature
variants. Its retained result is
`results/witness-operator-record-qualification.json` and explicitly records
that it is not independent evidence.
