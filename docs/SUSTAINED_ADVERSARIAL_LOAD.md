# Sustained Adversarial Load Qualification

Date: 2026-07-31

Post-M35 qualifies repeated resource-bound attacks against all three read-only
evaluation modes without granting mutation authority. It uses two complementary
layers.

`scripts/run-sustained-adversarial-load.py` runs 16 hostile cases per mode with
at most four child processes concurrently. Kubernetes shadow receives a
1,048,577-byte snapshot, Kubernetes live receives a 1,048,577-byte simulated
API response, and OpenTofu receives a 2,097,153-byte plan. Each input is one byte
above its public adapter limit. Every case has a ten-second deadline, must refuse,
must emit no certificate, temporary certificate, or ledger, and may emit at most
64 KiB of diagnostics.
The complete 48-case campaign must finish within 30 seconds and 512 MiB peak
child RSS. Its fixed qualification contract is retained in
`results/sustained-adversarial-load.json`.

`scripts/run-kubernetes-real-cluster.py` separately runs eight additional valid
evaluations against the disposable real Kubernetes v1.36.1 API server with four
concurrent clients. Every client uses the namespace-scoped read-only credential
and a separate evidence destination. Each evaluation has a five-second timeout,
the load phase has a 30-second bound, and the harness verifies the StatefulSet
UID, resource version, and generation are unchanged after all evaluations.

Run both layers through authoritative local CI or directly after building:

```sh
cargo build --locked --offline
python3 scripts/run-sustained-adversarial-load.py
python3 scripts/run-kubernetes-real-cluster.py
```

This is a bounded saturation sample, not a capacity forecast, denial-of-service
guarantee, managed-cluster result, multi-host test, or independent measurement.
It does not cover infinite arrival rates, host-wide exhaustion, hostile
schedulers, shared control-plane contention, or a compromised producer that
returns consistent lies. Those boundaries remain explicit rather than inferred
from the successful sample.
