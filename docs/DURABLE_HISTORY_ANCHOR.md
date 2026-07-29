# Durable History Anchor

## Operator workflow

Initialization is an explicit trust-root ceremony:

```sh
cargo run -- anchor-init scenarios/benign.json out/phenotype-anchor.json
```

Anchored evaluation then requires the existing store:

```sh
cargo run -- run-anchored scenarios/benign.json \
  out/certificate.json out/ledger.jsonl out/phenotype-anchor.json
```

The original `run` command remains available for deterministic research replay,
but it does not claim durable rollback protection.

## Invariants

The store accepts only:

- an idempotent replay of the exact stored issuer, sequence, and digest; or
- the same issuer at exactly the next sequence.

Lower sequences, same-sequence digest conflicts, issuer changes, sequence gaps,
missing/corrupt stores, and concurrent or crash-stale locks fail closed.
Initialization refuses to replace an existing store.

## Persistence protocol

The store acquires a same-directory lock using atomic directory creation, writes a
same-directory temporary file with create-new semantics, calls `sync_all` on the
file, atomically renames it over the anchor, and calls `sync_all` on the parent
directory. The lock is removed only on normal scope exit.

A process crash may leave the lock directory behind. Telosieve never guesses that
such a lock is stale or automatically breaks it. An operator must verify no writer
is live, preserve the store and temporary file for incident analysis, and remove
only the lock directory before retrying.

Protocol verification and fault-declaration bounds complete before the durable
anchor advances. Checker or evidence-output failure after that point may leave the
valid observed tip anchored without a completed decision artifact. The anchor
tracks authenticated observed history, not decision commit.

## Evidence and limits

Unit tests cover initialization, idempotence, next-sequence advancement, rollback,
conflict, gaps, missing/corrupt state, and lock contention. The public anchored
file-boundary test proves uninitialized refusal occurs before certificate or
ledger output, followed by successful explicit initialization and evaluation.

This is a Unix-filesystem research prototype. Filesystem and directory-fsync
semantics, local storage integrity, operator lock recovery, and the initialization
ceremony remain trusted. Production deployment would still require platform
qualification, access control, backup/restore drills, multi-host consensus or
hardware rollback resistance, and incident procedures.

