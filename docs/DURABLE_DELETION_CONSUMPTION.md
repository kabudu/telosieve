# Durable Deletion Consumption

Date: 2026-07-29

## Safety contract

Certificate v7 adds single-host one-shot semantics to applied authorized
deletions on `run-anchored`. The stateless `run` command remains deliberately
replayable for reproducible research.

The durable invariant is: one exact authenticated deletion-envelope set can
produce at most one successful anchored apply result from one uncompromised
anchor store. Verification and bounded checking happen first. When the decision
is `applied`, history advancement and authorization consumption are committed
together under one lock and one atomic file replacement. A replay returns an
anchor error and emits no additional certificate or ledger record.

## Identity and transaction

The authorization identifier is a domain-separated SHA-256 digest of the sorted
digests of every agreeing deletion envelope. It therefore binds issuer,
sequence, timestamps, content, lineage, and signature, not merely the requested
key set. A genuinely reissued signed authorization has a different identity;
the unchanged envelope set does not.

The versioned state contains:

- the authenticated phenotype history anchor; and
- an ordered set of consumed deletion-authorization identifiers.

The store retains the existing same-directory atomic lock, create-new temporary
file, file `sync_all`, rename, and parent-directory `sync_all` protocol.
Concurrent evaluators may both finish checking, but only the lock holder can
commit; the second observes the consumed identifier and fails closed.

## Failure and compatibility behavior

- corrupt, missing, locked, rollback, conflict, gap, or issuer-changing state
  fails closed;
- pre-v2 raw anchor files fail closed because their prior consumption history is
  unknowable; operators must preserve them for audit and explicitly initialize
  a new store from verified current state;
- the ledger is limited to 4,096 validated SHA-256 identifiers and the entire
  state file to 512 KiB; either bound fails without advancing history;
- if durable commit succeeds but certificate or JSONL persistence fails, the
  authorization remains consumed. This can require a newly signed authorization
  after incident review, but it prevents uncertain duplicate use; and
- storage compromise, firmware rollback, malicious lock recovery, multi-host
  split brain, and production actuation remain outside the demonstrated bound.

## Evidence

Unit tests cover atomic insertion, exact replay refusal, monotonic history,
capacity exhaustion without anchor advancement, corrupt and legacy state, and
lock refusal. Public-boundary tests show one anchored authorized deletion emits
one ledger record, identical replay emits none, and post-commit evidence failure
burns the authorization safely. The authoritative project gate remains
`./scripts/ci-local.sh`.
