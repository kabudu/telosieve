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
append-only ledger records. The broader fault suites listed above remain M1/M2
work.
