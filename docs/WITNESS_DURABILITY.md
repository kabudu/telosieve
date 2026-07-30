# Witness-tip durability and availability

Date: 2026-07-30

## Durable state contract

`telosieve.witness-tip-state/v1` stores timestamp and revocation tips as one
generation. Updates require each tip to remain exact or advance by exactly one;
rollback, gaps, and same-sequence digest conflicts refuse. A bounded recovery
witness records the exact previous and next state digests. Persistence uses a
create-new temporary file, file `sync_all`, atomic rename, and parent-directory
`sync_all`.

Recovery accepts only a primary state matching the pending previous or next
generation, then commits that exact reference. Any third state refuses. Backups
are bounded, create-new, and content-addressed; restore requires equality with
the latest committed recovery witness. The primary and witness can be copied
together to another path or host without path-dependent state.

The two crash-boundary, stale-backup, exact-restore, copy, rollback, and
equivocation tests pass on macOS and in pinned, network-disabled Linux arm64 and
emulated amd64 containers using Docker-managed volumes. These tests exercise
process/filesystem crash consistency, not power-loss persistence or hostile
storage.

## Availability measurement

The deterministic scripted-distribution model bounds work to two authorities,
three attempts, and a 250 ms virtual budget. Seven retained profiles observe:

- nominal, 249 ms bounded delay, and one-sided partition remain available;
- three lost attempts and total authority outage refuse;
- a 251 ms response refuses at the budget boundary; and
- a promptly returned wrong digest refuses as equivocation.

This deliberately treats unavailable trust evidence as loss of availability,
never permission to use stale or unanchored evidence. The model performs no
network I/O or wall-clock sleeping; its measurements are deterministic policy
outcomes, not latency samples or an SLA.

## Reproduction and limits

Run `./scripts/run-witness-durability.sh` for the host lifecycle and availability
matrix. Run `./scripts/qualify-linux-witness.sh linux/arm64` and
`linux/amd64` for the pinned offline Linux boundaries.

The store is single-host and lock-directory coordinated. It has no access
control, encryption, HSM, quorum, remote consensus, repair protocol, live
service, hostile-disk defense, bare-metal power-loss qualification, or
independent operator. Container evidence is project-run local qualification,
not third-party assessment.
