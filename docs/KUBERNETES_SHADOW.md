# Kubernetes Read-Only Shadow Adapter

Date: 2026-07-29

## Boundary

The adapter consumes an already exported, network-free Kubernetes snapshot. It
does not contain a Kubernetes client, accept a kubeconfig, contact an API server,
or call any mutation endpoint. Kubernetes and existing reconcilers remain the
execution plane.

The `telosieve.kubernetes-shadow/v1` export contains:

- one `v1` ConfigMap identity and desired data;
- an exact target reference to one `apps/v1` StatefulSet;
- the observed StatefulSet identity, UID, resource version, generation, and
  controller-observed generation;
- a completeness flag and bounded per-replica key/value observations; and
- the Telosieve subject and exact evaluation/capture time.

The ConfigMap target reference must exactly equal the observed StatefulSet
identity, including UID and resource version. The observed generation must be
non-zero and equal the controller-observed generation. Desired data and observed
replicas must exactly match the independently authenticated Telosieve goal and
phenotype authorities.

## Execution

```sh
cargo run --locked --offline -- shadow-kubernetes \
  scenarios/benign.json \
  snapshots/kubernetes-shadow-benign.json \
  results/kubernetes-shadow-certificate.json \
  results/kubernetes-shadow-ledger.jsonl
```

Certificate v9 includes a `shadow` record binding the full snapshot digest,
target UID, desired and observed resource versions, and capture time. It never
contains an actuation record.

## Failure and resource bounds

The snapshot is streamed with a hard 1 MiB read cap. It permits 1–64 replicas,
at most 256 values per map, metadata/key fields up to 256 non-control bytes, and
values up to 4 KiB. Unknown fields and schemas fail JSON decoding.

Target drift, replacement UID, mismatched or empty resource versions, partial
reads, stale controller generations, capture-time mismatch, authority mismatch,
and structural limits fail before checker startup or evidence output.
Canonical-path checks reject certificate/ledger aliasing with either input or
each other, including existing symlinks.

This is exported-snapshot semantic evidence, not live-watch consistency,
Kubernetes API authorization, admission-control, network-partition, or
production performance evidence. The exporter and scenario capture process
remain trusted to provide a coherent snapshot.

## Retained evidence

The benign snapshot, certificate, and one-record ledger are retained under
`snapshots/` and `results/`. Tests cover exact mapping, drift, partial reads,
stale generations, replacement identity, schema/context/authority mismatch,
structural and byte bounds, output collision, deterministic evidence, and
unchanged input bytes.
