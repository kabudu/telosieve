# Operations

The research harness runs locally with fixed seeds and no production credentials.
Every run records source commit, configuration digest, dependency lock digest,
authority envelopes, decision certificate, timing, and outcome.

Operational alerts cover signature failure, equivocation, schema mismatch,
hypothesis-budget exhaustion, checker disagreement, ledger write failure, and
actuator partial failure. No automatic retry may broaden authority or weaken an
invariant. Recovery is replay from the last complete ledger record.

Secrets are test keys stored outside fixtures. Logs must not include application
values. Retention and deletion policy must be defined before real traces are used.

For `apply-local`, durable service commit occurs before certificate and ledger
persistence. An evidence-output failure is therefore an applied-but-unreported
incident: do not retry the stale scenario. Preserve the actuator file, lock or
temporary artifacts, and output errors; read current state and the durable
last-actuation operation digest through `local-show`; obtain a new authenticated
phenotype; and only then evaluate a new operation.
Never break an actuator lock until the writer is proven absent.

## Local actuator recovery runbook

1. Stop new actuator commands and prove the previous writer process is absent.
2. Preserve the primary state, `.witness.json`, lock directory, temporary files,
   certificate, ledger, and stderr for incident analysis.
3. Remove only the stale `.actuator.lock` directory.
4. Run `local-recover`; it validates canonical state and witness before removing
   known temporary files or resolving a pending generation.
5. Run `local-show` and compare its generation, operation digest, and state
   digest with the last complete evidence record.
6. If primary state is missing or corrupt but the witness is committed, restore
   only an exact-latest verified backup with `local-restore`.
7. Obtain a new authenticated phenotype before further evaluation.

Never restore an older backup, replace the witness, infer a generation, or retry
an applied stale scenario. Loss or rollback of both state and witness is a stop
condition outside this protocol.
