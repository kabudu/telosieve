# Recovery-Root Ceremony Rehearsal

Date: 2026-07-30

## Scope and acceptance contract

This milestone models a credential-free local rehearsal for authorizing one
recovery-root public key. It tests ceremony state and failure handling; it does
not create, store, sign with, or transfer a private key.

The retained profile has three named participants and a fixed quorum of two.
The implementation accepts 3–7 unique participants, requires a strict-majority
quorum, limits a ceremony to 3,600 seconds, and never lowers the original quorum
after excluding a suspected participant. Exclusion must leave enough eligible
participants to satisfy that quorum.

Each approval is bound to the ceremony identifier, subject, authority kind,
canonical Ed25519 recovery-root public key, lifecycle-anchor digest, trusted-time
digest, and the exact participant/exclusion/quorum request. Votes also bind that
request digest to an evidence digest, voter, decision, and bounded timestamp.
Participant names establish deterministic labels only; they are not
authenticated identities.

## Abort policy

The ceremony fails closed on:

- invalid context, public key, timing, participant set, or quorum;
- a duplicate, unregistered, or excluded voter;
- a missing quorum;
- a vote bound to different context or evidence;
- a stale or future vote; or
- any veto, even when enough approvals otherwise exist.

A suspected compromised participant is excluded by creating a new,
content-addressed request. Its old vote cannot be replayed into that request.
The exclusion does not reduce the original quorum or permit the excluded
participant to vote.

## Rehearsal and retained evidence

Run:

```sh
./scripts/run-recovery-ceremony.sh
```

The runner executes exact Rust tests under locked, offline dependency resolution
and emits `results/recovery-ceremony.json` only after both pass. The success test
approves a 2-of-3 request and then approves a refreshed request after excluding
one suspected custodian. The failure test covers duplicate, missing, divergent,
stale, veto, and excluded-compromised votes.

The aggregate records bounds and covered abort classes, not approval signatures
or custody evidence. Editing the JSON is not a substitute for rerunning the
command.

## Residual limits

This repository has no production credentials and performs no network, HSM,
threshold-cryptography, secure-clock, or organizational identity operation.
Multiple labels in one process do not demonstrate independent people, devices,
fault domains, or custody. A real ceremony still requires independently
authenticated participants, protected private-key generation and storage,
separation of duties, durable signed minutes, time assurance, incident
authority, and independent assessment.
