# Incident and Recovery Drills

Date: 2026-07-29

`./scripts/run-incident-drills.sh` executes seven offline drills against real
failure-path tests and emits `telosieve.incident-drills/v1` JSON only when every
command succeeds. It uses locked dependencies, no network, no production
credentials, and no external service.

The registry covers state corruption, committed-witness loss, full deletion
ledger, stale lock, interrupted schema upgrade, operational-key compromise, and
lifecycle-tip rollback/equivocation. Each result retains the exact command,
expected state, operator action, recovery point, evidence-preservation duty, and
pass status in `results/incident-drills.json`.

The operator response is fail closed: preserve files and errors, prove process
death before lock removal, never reconstruct a missing witness, never discard
consumption history, and use only the offline recovery root for key-compromise
recovery. Witness loss, unprovable lock ownership, and coordinated lifecycle
root/tip rollback remain stop conditions rather than automatic repair.

These are deterministic local software drills. They do not exercise real disk
loss, HSMs, Kubernetes credentials, multi-host coordination, human on-call
latency, or an independent organization.
