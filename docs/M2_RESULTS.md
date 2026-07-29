# M2 Adversarial Results

## Reproduction

The original registered run is pinned to merge
`a0bf340daf752faeb2621b2580cc31939277c3b1`. Check out that revision in a
separate worktree, then run:

```sh
cargo run --release --example benchmark -- scenarios/*.json
./scripts/ci-local.sh
```

The retained raw run is `results/m2-benchmark.json`. It contains 20 iterations
per signed scenario. Timing is machine-specific; decisions, hypothesis counts,
certificate sizes, and safety-oracle outcomes are deterministic for the fixtures.
The live fixtures evolved after M3; their current output is retained separately in
`results/post-m3-viability-benchmark.json`.

## Results

| Scenario | Decision | Hypotheses | p50 µs | p95 µs | Unsafe approvals | Baseline unsafe approvals |
|---|---:|---:|---:|---:|---:|---:|
| benign update | apply | 1 | 22,956 | 27,414 | 0 | 0 |
| poisoned goal | refuse | 2 | 45,783 | 49,269 | 0 | 2 |
| partitioned phenotype | apply | 2 | 45,130 | 62,766 | 0 | 0 |
| weakened viability | apply | 1 | 21,960 | 26,690 | 1 | 3 |

No registered scenario produced a false refusal.

## Negative results and limits

- Authenticated weakened viability outside the declared fault model permits an
  unsafe approval. This is a stop-ship result and confirms that provenance alone
  cannot establish semantic truth.
- The signed-snapshot rollback baseline applies a no-op transition in the current
  harness; it is not evidence for a production history service.
- Latency approximately doubles from one to two hypotheses because M1 starts one
  bounded Python checker process per checkable hypothesis.
- The scenario matrix is finite and deliberately small. It does not establish
  general Byzantine safety, production availability, or cross-platform timing.
- Correlated faults beyond the declared budget remain outside the soundness claim.

M2 therefore supplies falsification evidence, not a product qualification.
