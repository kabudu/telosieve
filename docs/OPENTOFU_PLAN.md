# OpenTofu Plan Evaluation

## Scope and invariants

Evaluation config v3 adds the read-only `opentofu-plan` mode. It consumes the
JSON bytes produced by `tofu show -json <saved-plan>` and never invokes OpenTofu,
loads credentials, reads state, or applies a plan. Operators generate the saved
plan separately and retain responsibility for its backend and provider boundary.

The adapter accepts 1–64 managed `terraform_data` update changes. Each resource
must expose an `input` object containing exactly a bounded `replica` string and
bounded string-to-string `values`. Before inputs must exactly equal the signed
phenotype authority; every after value map must exactly equal the signed goal.
Replica names must be stable and unique. Create, delete, replace, no-op, other
resource types, sensitive input, unknown input, and authority disagreement all
fail before certificate or ledger persistence. Plan input is capped at 2 MiB.

Certificate v10 contains only an `opentofu` execution extension. It records the
SHA-256 of the exact plan JSON bytes, JSON format version, OpenTofu version, and
resource-change count. It contains neither actuation nor Kubernetes shadow
evidence. This prevents substitution of a different plan after evaluation; the
certificate still requires the existing detached-attestation workflow when
authenticity or distribution trust is needed.

## Real local qualification

Run:

```sh
cargo build --locked --offline
python3 scripts/run-opentofu-plan.py
```

The harness requires `tofu` and uses only its built-in `terraform_data`
resource. In a disposable directory it initializes local state, applies three
old replica inputs, saves a three-update plan for the authenticated new goal,
renders the real JSON form, and evaluates it through the product CLI. It checks
the exact plan digest and target-mutation report, then proves replacement and
authority-tampered plans emit no evidence. Local state setup is harness-only;
the Telosieve evaluation itself remains read-only.

## Failure, performance, and claim bounds

The adapter performs one bounded file read and linear work over at most 64
changes and 256 values per replica; plan bytes dominate its 2 MiB memory bound.
Evidence output keeps the existing single-writer, append-only-ledger and atomic
current-certificate limitations. The harness is project-controlled evidence on
OpenTofu 1.12.5. It does not validate provider plans, remote backends, policy
completeness, eventual apply behavior, credentials, organizational independence,
or Terraform compatibility.
