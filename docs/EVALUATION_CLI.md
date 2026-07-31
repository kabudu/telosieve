# Versioned Evaluation CLI and Configuration

## Stable boundary

The evaluation interface is:

```sh
mkdir -p out
cargo run --locked --offline -- evaluate evaluation/config.example.json
```

`telosieve evaluation-capabilities` emits the bounded compiled
`telosieve.evaluation-capabilities/v1` inventory. Its schema/mode records must
exactly equal contract v2's `supported_evaluation_modes`, and every record must
declare `target_mutated: false`.

`telosieve --version` prints the binary package version. The `evaluate` command,
the supported v3–v5 configurations, and
`telosieve.evaluation-report/v1` success report are the supported evaluation
surface. Other commands remain research, recovery, or reference-backend
interfaces unless a later compatibility decision promotes them.

The v4 `kubernetes-shadow` mode consumes an already exported Kubernetes snapshot
only after a signed multi-domain quorum authenticates its exact bytes and
context. It writes certificate and append-only ledger evidence but does not
accept a kubeconfig, contact Kubernetes, hold mutation credentials, or write to
the target system. Configuration v1 is no longer a product capability; the
separate research command remains available for explicitly uncorroborated work.

## Configuration

The v4 object has exactly eight fields:

| Field | Required value or meaning |
|---|---|
| `schema_version` | exactly `telosieve.evaluation-config/v4` |
| `mode` | exactly `kubernetes-shadow` |
| `scenario_path` | authenticated Telosieve scenario |
| `snapshot_path` | bounded Kubernetes shadow export |
| `observation_trust_path` | canonical bounded signer/domain trust document |
| `observation_quorum_path` | canonical bounded attestations for the snapshot |
| `certificate_path` | replaceable current certificate evidence |
| `ledger_path` | append-only certificate ledger |

Unknown or missing fields refuse. Paths may be absolute or relative; relative
paths resolve from the canonical configuration directory, not the caller's
working directory. Each path is limited to 4,096 non-control bytes. The
configuration is capped at 64 KiB, scenarios at 2 MiB, shadow snapshots at
1 MiB, and each quorum document at 64 KiB. Existing shadow structural bounds
remain binding. Quorum verification precedes snapshot JSON parsing.

Certificate, its temporary replacement, and ledger outputs must not alias the
configuration, either input, or each other, including through existing
symlinks. Output parent directories must already exist. Operators should use a
directory with permissions suitable for the platform evidence it will contain.

## Result and exit behavior

Success writes one compact JSON report to stdout containing:

- report and configuration schema versions;
- the evaluation mode, scenario identifier, and applied/refused decision;
- the digest of the exact persisted certificate; and
- `target_mutated: false`.

Both an applied decision and an explicit Telosieve refusal are successful
evaluations and return exit status 0. Configuration, input, verification,
checker, bound, or evidence-persistence failure returns status 1, writes a
prefixed diagnostic to stderr, and writes no success report. Invalid command
shape returns status 2 with usage.

The certificate ledger is append-only and the current certificate uses atomic
replacement, but the two files are not one cross-file transaction. An I/O
failure can leave partial evidence or a temporary certificate file. Preserve and
inspect the output directory before retrying; do not treat the absence of a
success report as proof that no evidence file changed.

The file backend is single-writer. Do not run concurrent evaluations against
the same certificate or ledger paths; it has no cross-process lock or
compare-and-commit protocol. Preserve each report and verify its
`certificate_digest` against the corresponding certificate before assessment.

## Compatibility and security

Unknown configuration schemas or modes refuse; v1 files are not silently
silently migrated. Configuration validation completes before scenario or
snapshot reads. Scenario and snapshot bytes are unchanged by evaluation, and
the resulting certificate contains shadow evidence, including the canonical
verified quorum-evidence digest, but no actuation record. Historical v9
certificates without that optional digest remain readable.

The v5 `kubernetes-live` mode accepts the common scenario, certificate, and
ledger paths plus a `kubernetes` object containing absolute `kubectl_path` and
`kubeconfig_path` values, context, namespace, desired ConfigMap name, and
observed StatefulSet name. It issues exactly four subprocess calls: ConfigMap,
StatefulSet, selected Pods, and the same StatefulSet again. Every call is a
fixed `get`, has a five-second process timeout, and accepts at most 1 MiB stdout
and 16 KiB stderr. Collection refuses stale or unready controllers, incomplete,
unready, or incorrectly owned Pods, invalid identities, and any pre/post
StatefulSet change. Pod state is read from the JSON object in the
`telosieve.io/values` annotation and is then checked by the existing
authenticated shadow evaluator. The controller selector must contain 1–16
bounded `matchLabels`; `matchExpressions` refuse rather than being approximated.
Desired ConfigMap values use the same annotation because `/` is valid in
Telosieve authority keys but not in ConfigMap `data` keys. Legacy `data` remains
accepted when the annotation is absent; disagreement between both forms refuses.

It also requires `observation_trust_path` and two to eight
`observation_sources`. Each source names an absolute executable and at most 32
bounded arguments. Sources have five-second deadlines, 2 MiB stdout and 16 KiB
stderr bounds. Every returned v1 envelope must contain a snapshot exactly equal
to the primary collector's canonical snapshot and a valid attestation; the
quorum must span at least two configured fault domains. Only then is its digest
bound into certificate v9.
Producer executables are trusted operator inputs with process authority on the
evaluation host. They must be reviewed, installed immutably, granted read-only
target credentials, and isolated from one another; domain labels alone enforce
none of those properties. Never pass private key material directly in command
arguments. The packaged Python producer passes only an owner-only key path to
the bounded M38 signing command and issues fixed Kubernetes `get` operations.
Sources run sequentially after the primary four-read collection, so eight
maximal source timeouts add at most 40 seconds to the primary collector's four
five-second process bounds. The direct source process is killed on timeout;
operators must ensure trusted executables do not detach descendants.

`evaluation/config.live.example.json` is the versioned example. Its absolute
binary and credential paths are illustrative and must be replaced with
operator-controlled regular files; its output directory must exist.

Use `deploy/kubernetes/evaluation-rbac.yaml` as a concrete least-privilege
starting point, changing its namespace and resource names together with the
evaluation configuration. It grants only ConfigMap `get`, StatefulSet `get`,
and Pod `get/list`; it grants no Secret or mutation access. The supplied
kubeconfig and `kubectl` binary are trusted operator inputs and may include
credential plugins, so protect and review both.

The fake process harness proves command shape and bounded process faults. The
separate [KUBERNETES_REAL_CLUSTER](KUBERNETES_REAL_CLUSTER.md) harness qualifies
the complete path against a disposable real API server and real RBAC. Managed
clusters, production-scale load, credential plugins, and independent operation remain
unqualified.

The v3 `opentofu-plan` mode adds a `plan_path` for bounded JSON emitted by
`tofu show -json` from a saved plan. It accepts only explicit in-place updates
to built-in `terraform_data` inputs whose before and after states exactly match
the authenticated phenotype and goal. The exact input bytes are bound into
certificate v10. Telosieve does not invoke OpenTofu or apply the plan. See
[OPENTOFU_PLAN](OPENTOFU_PLAN.md).

The separate bounded lifecycle manager installs the CLI and configuration; see
[EVALUATION_LIFECYCLE](EVALUATION_LIFECYCLE.md). The product does not yet redact
an assessor bundle or qualify production resources. Those remain separate
candidate-readiness milestones.
