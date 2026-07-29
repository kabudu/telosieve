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
