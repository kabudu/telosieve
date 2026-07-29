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
