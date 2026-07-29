# End-to-End Testing

Each scenario fixes seed, service state, authorities, fault declaration, expected
safety envelope, and permitted decisions. Tests replay from clean state.

Required suites:

- benign convergence and rollback;
- malicious but correctly signed goal;
- stale goal and equivocation;
- forged, omitted, delayed, and partitioned phenotype;
- weakened or contradictory viability rules;
- shared-parser discrepancy;
- two faults against a one-fault budget;
- checker timeout, ledger failure, and partial actuator failure.

Assertions cover safety violations, false refusals, recovery latency, evidence
excluded, decision reproducibility, and baseline deltas. An expected refusal is a
successful outcome when evidence is underdetermined.

The M0 integration suite (`tests/m0.rs`) exercises the public file boundary,
signature tampering, hypothesis-budget exhaustion, benign apply and rollback,
poisoned-goal refusal, deterministic byte replay, certificate persistence, and
append-only ledger records. It also replays a signed predecessor distinct from the
current snapshot and rejects missing history, forked records, and an older trusted
tip. The anchored public boundary additionally refuses an uninitialized durable
store before output, then completes after explicit initialization.

`tests/adversarial.rs` registers the M2 hostile-input matrix: poisoned and stale
goals, omitted and forged phenotype evidence, invariant weakening, partitioned
phenotypes, equivocation, parser differential coverage, and correlated faults
against the declared budget. Mutations without valid signatures are expected to
fail at provenance verification; authenticated poisoned intent proceeds to
hypothesis evaluation and refusal.

Certificate-v4 coverage additionally exercises implicit deletion with every
viability domain weakened. The Rust and Python checkers must independently reject
loss of a key present on every current replica, while focused tests preserve
ordinary value updates and key additions. The 512-scenario aggregate assertion
requires zero unsafe approvals without relabelling expected decisions.

Certificate-v6 coverage adds signed authorized and unauthorized deletion
fixtures. It verifies exact key removal through the public engine, unchanged
state on refusal, goal-binding replay rejection, mapping failures, and refusal
when one correlated domain contains every deletion issuer.

Certificate-v7 coverage runs authorized deletion through the public anchored
file boundary twice. The first run applies and persists one record; the second
fails on durable consumption without emitting another. A separate failure-path
test makes ledger persistence fail after durable commit and verifies the
authorization remains burned.

Certificate-v8 coverage adds a real executable lifecycle:
`local-init` initializes authenticated service state, `apply-local` evaluates and
commits it, and `local-show` reads the result through the operator boundary.
Additional public-boundary tests prove refusal is non-mutating, stale replay
emits no second evidence record, and evidence failure cannot roll back or repeat
an already committed transition.
