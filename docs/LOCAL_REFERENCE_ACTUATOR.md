# Transactional Local Reference Actuator

Date: 2026-07-29

## Purpose and boundary

The local reference actuator closes the research harness's pure-simulation gap
without claiming integration with a production service. It is a file-backed
replicated key-value target whose entire service state, authenticated history
anchor, and consumed deletion identifiers share one atomic transaction.

This establishes the minimum adapter contract that a future production backend
must preserve:

- initialize only from a verified authenticated phenotype;
- compare the stored state with the authenticated observation at commit time;
- reject a transition whose `before_digest` does not match that state;
- mutate service values only for an `Applied` certificate;
- atomically commit service values, history advancement, and deletion
  consumption; and
- fail closed on stale state, replay, contention, corruption, or capacity.

## Operator lifecycle

Initialization is explicit and refuses replacement:

```sh
cargo run -- local-init scenarios/benign.json out/local-actuator.json
```

Evaluation and transactional application use the normal certificate and evidence
outputs:

```sh
cargo run -- apply-local scenarios/benign.json \
  out/certificate.json out/ledger.jsonl out/local-actuator.json
```

The committed service state is read through the operator boundary:

```sh
cargo run -- local-show out/local-actuator.json
```

`apply-local` emits certificate v8 with an `actuation` record containing the
adapter schema, a domain-separated operation digest, and before/after
service-state digests. The same last-committed receipt is stored atomically and
returned by `local-show`. Stateless and anchor-only runs remain certificate v7
and byte-deterministic.

## Transaction and failures

The actuator uses an atomic same-directory lock, create-new temporary file,
file `sync_all`, rename, and parent-directory `sync_all`. The stored JSON is
limited to 1 MiB and deletion history to 4,096 validated SHA-256 identifiers.
The lock is never automatically broken.

Verification and checking occur before the lock is acquired. At commit time the
store repeats the critical state and transition-precondition checks, preventing
a concurrent or stale evaluation from applying. Refusal may advance authenticated
history but leaves service values unchanged.

The durable commit precedes certificate and JSONL persistence. If evidence output
then fails, the service change remains committed and retry with the stale
phenotype fails. Operators must inspect the durable last-actuation receipt and
incident artifacts, obtain a newly authenticated phenotype, and produce new
evidence; automatic retry is unsafe.

## Evidence and residual limits

Unit tests cover atomic application, combined deletion consumption, bounded
ledger exhaustion, refusal, stale observation, corrupt/oversized state, and lock
contention. Public-boundary tests cover apply-once, refusal, post-commit evidence
failure, and the real
`local-init` → `apply-local` → `local-show` CLI lifecycle.

This is a single-host reference backend, not a production actuator. It does not
provide external service transactions, authentication or authorization for local
operators, hostile-storage rollback protection, multi-host consensus, backup and
restore qualification, or incident-tested integration with Kubernetes, GitOps,
or a database.
