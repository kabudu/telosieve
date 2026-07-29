# Authenticated Phenotype History

## Contract

The signed-history baseline now replays an authenticated predecessor rather than
inferring rollback state from the current snapshot. Each scenario carries:

- a bounded ordered chain of signed phenotype envelopes;
- a current signed phenotype envelope extending the retained tip; and
- a trusted anchor naming the issuer, current sequence, and current envelope
  digest.

The verifier permits at most 64 retained records. It requires one issuer,
contiguous sequences beginning at one, exactly one parent digest per non-genesis
record, exact digest linkage, valid signatures and content digests, and an exact
match between the current envelope and trusted anchor. Verification completes
before hypothesis enumeration or checker startup.

The `signed-history-replay/v1` baseline proposes the consensus state from the
authenticated predecessor. With no retained predecessor it refuses; it never
falls back to the current snapshot.

## Failure and trust boundaries

Missing links, duplicate/forked records, reordering, foreign issuers or kinds,
invalid signatures, invalid or future-dated validity intervals, current-envelope
expiry, anchor rollback, and histories beyond the record bound fail closed.
Historical records may have expired after issuance; expiry does not invalidate
past authenticated state.

The anchor is trusted scenario configuration in this research harness. A
subsequent prototype adds a local durable monotonic store, documented in
[DURABLE_HISTORY_ANCHOR](DURABLE_HISTORY_ANCHOR.md). Rollback-resistant hardware
or quorum checkpointing, retention policy, cross-host recovery, and key rotation
remain production requirements.

## Evidence

`authenticated_history_replays_predecessor_and_rejects_rollback` verifies replay
of a state that differs from the current snapshot and rejects omitted history,
an older anchored tip, and a duplicated/forked record. Deterministic replay and
the public harness tests cover certificate stability and baseline reporting.

The retained run in `results/post-m3-history-benchmark.json` records 20 iterations
per scenario. Decisions and safety metrics remain unchanged; certificates are
3,646–4,593 bytes with one retained predecessor.

## Compression decision

[QATQ](https://github.com/kabudu/qatq) is an exact Rust codec designed for
structured numeric tensor streams. Telosieve history is currently small,
canonical JSON authority evidence rather than tensor data. Adding QATQ now would
not match the payload shape and would expand the trusted dependency surface.
Compression is deferred until retained-history measurements demonstrate a
material storage or transfer bound; any future codec must be lossless and the
uncompressed canonical bytes must remain the signature and digest domain.
