# Local Actuator Recovery Qualification

Date: 2026-07-29

## Qualified boundary

This milestone qualifies the file-backed reference actuator's recovery protocol
on macOS/aarch64 with the local filesystem used by the test environment. It does
not qualify other operating systems, filesystems, storage firmware, multiple
hosts, or hostile rollback.

Actuator schema v2 adds a monotonic generation, a separate same-directory
recovery witness, content-addressed create-new backups, exact-latest restore,
deterministic interrupted-commit recovery, and an explicit crash-safe upgrade
from witness-less actuator schema v1.

## Commit and recovery protocol

Each mutation holds the actuator lock and persists:

1. a pending witness containing the exact previous and next generation/digest;
2. the next complete actuator state; and
3. a committed witness naming the next state.

Each replacement uses a same-directory create-new temporary file, file
`sync_all`, atomic rename, and parent-directory `sync_all`. A crash can therefore
leave only the previous state, the next state, or a non-canonical temporary file.
After an operator proves the writer is dead and removes its stale lock,
`local-recover`:

- retains the previous state when it matches the pending witness;
- commits the next state when it matches;
- resolves interrupted initialization or v1 upgrade without discarding a
  previously valid state;
- removes only known temporary files after canonical state validation; and
- rejects every other state/witness combination.

The witness is written before the primary state. Ambiguous failure therefore
costs availability rather than allowing an untracked side effect.

## Backup, restore, and rollback

```sh
cargo run -- local-backup out/local-actuator.json out/actuator-backup.json
cargo run -- local-restore out/local-actuator.json out/actuator-backup.json
```

Restore succeeds only when the backup's validated state digest and generation
exactly match the latest committed witness. Older or tampered backups fail
closed. Backup targets are create-new and capped at 2 MiB; actuator state remains
capped at 1 MiB and the witness at 4 KiB.

The co-located witness must survive. This repairs loss or corruption of the
primary state file; it is not whole-disk disaster recovery. Restoring both an old
state and its old witness can roll the system back and remains outside the
demonstrated protection.

## Compatibility

Schema-v1 actuator files contain deletion-consumption history but no recovery
witness. Reinitializing would discard that history and is unsafe. Upgrade them
in place:

```sh
cargo run -- local-upgrade out/local-actuator.json
```

The upgrade preserves service state, history anchor, consumed deletion
identifiers, and the last receipt. Interrupted recovery either commits the exact
v2 state or retains the exact v1 state for retry.

## Evidence and measurements

Tests cover both deterministic commit interruption points, interrupted
initialization and upgrade, canonical temporary cleanup, stale/tampered backup,
missing-primary restore, full consumption ledger, corrupt/oversized state,
concurrent writers, and the executable backup/restore/recover lifecycle.

A forced-termination stress test runs 16 fresh actuator lifecycles with kill
delays from 0 to 60 ms. After verified process death and explicit stale-lock
removal, every iteration recovers to exactly generation zero or one with matching
service values and receipt. The test passed five consecutive focused runs before
the full gate.

Fifty-iteration macOS/aarch64 measurements for the 457-byte benign state:

| Operation | p50 | p95 |
|---|---:|---:|
| Consistent recovery | 191 µs | 3,966 µs |
| Create-new backup | 11,347 µs | 16,794 µs |
| Exact-latest restore | 16,242 µs | 25,548 µs |

The 603-byte raw backup and measurements are retained in
`results/actuator-recovery-benchmark.json`. These are local observations, not
service-level objectives or population estimates.
