# Versioned Evaluation CLI and Configuration

## Stable boundary

The first evaluation interface is:

```sh
mkdir -p out
cargo run --locked --offline -- evaluate evaluation/config.example.json
```

`telosieve --version` prints the binary package version. The `evaluate` command,
`telosieve.evaluation-config/v1` configuration, and
`telosieve.evaluation-report/v1` success report are the supported evaluation
surface. Other commands remain research, recovery, or reference-backend
interfaces unless a later compatibility decision promotes them.

The only v1 mode is `kubernetes-shadow`. It consumes an already exported
Kubernetes snapshot and writes certificate and append-only ledger evidence. It
does not accept a kubeconfig, contact Kubernetes, hold mutation credentials, or
write to the target system.

## Configuration

The v1 object has exactly six fields:

| Field | Required value or meaning |
|---|---|
| `schema_version` | exactly `telosieve.evaluation-config/v1` |
| `mode` | exactly `kubernetes-shadow` |
| `scenario_path` | authenticated Telosieve scenario |
| `snapshot_path` | bounded Kubernetes shadow export |
| `certificate_path` | replaceable current certificate evidence |
| `ledger_path` | append-only certificate ledger |

Unknown or missing fields refuse. Paths may be absolute or relative; relative
paths resolve from the canonical configuration directory, not the caller's
working directory. Each path is limited to 4,096 non-control bytes. The
configuration is capped at 64 KiB, scenarios at 2 MiB, and shadow snapshots at
1 MiB. Existing shadow structural bounds remain binding.

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

The v1 file backend is single-writer. Do not run concurrent evaluations against
the same certificate or ledger paths; it has no cross-process lock or
compare-and-commit protocol. Preserve each report and verify its
`certificate_digest` against the corresponding certificate before assessment.

## Compatibility and security

Unknown future configuration schemas or modes refuse; v1 files are never
silently migrated. Configuration validation completes before scenario or
snapshot reads. Scenario and snapshot bytes are unchanged by evaluation, and
the resulting certificate contains shadow evidence but no actuation record.

The interface does not yet collect live Kubernetes state, install itself, redact
an assessor bundle, or qualify production resources. Those remain separate
candidate-readiness milestones.
