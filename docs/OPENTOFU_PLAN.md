# OpenTofu Plan Evaluation

## Scope and invariants

Evaluation config v6 provides the read-only `opentofu-plan` mode. It consumes
the JSON bytes produced by `tofu show -json <saved-plan>` and never invokes
OpenTofu, loads credentials, reads state, or applies a plan. Operators generate
the saved plan separately and retain responsibility for its backend and provider
boundary.

Two to eight configured observation producers must each return a signed
`telosieve.observation-source/v1` envelope containing the hexadecimal encoding
of those exact plan bytes. Telosieve requires byte-for-byte agreement with the
primary plan, distinct trusted producer identities and trust domains, valid
attestation lifetimes, and a valid multi-domain quorum before parsing the plan.
The producer quorum digest is bound into certificate v10.

The packaged `scripts/opentofu-observation-producer.py` is the reference
producer. It invokes a configured canonical OpenTofu executable to render one
absolute, regular, single-link saved plan; signs the exact rendered bytes with
non-group/other-writable OpenTofu and Telosieve executables plus an owner-only
key; and writes only the envelope to standard output. Because that envelope
contains the complete plan in hexadecimal, run the producer only under the
evaluator and never route its stdout to general logs. Configure each producer as
a separate process and custody boundary. The example paths are illustrative and
must be replaced with operator-controlled absolute paths and keys.

The adapter accepts 1–64 managed `terraform_data` update changes. Each resource
must expose an `input` object containing exactly a bounded `replica` string and
bounded string-to-string `values`. Before inputs must exactly equal the signed
phenotype authority; every after value map must exactly equal the signed goal.
Replica names must be stable and unique. Create, delete, replace, no-op, other
resource types, sensitive input, unknown input, and authority disagreement all
fail before certificate or ledger persistence. Plan input is capped at 2 MiB.

Certificate v10 contains only an `opentofu` execution extension. It records the
SHA-256 of the exact plan JSON bytes, the observation quorum digest, JSON format
version, OpenTofu version, and resource-change count. It contains neither
actuation nor Kubernetes shadow evidence. This prevents substitution of a
different plan or producer set after evaluation; the certificate still requires
the existing detached-attestation workflow when authenticity or distribution
trust is needed.

## Real local qualification

Run:

```sh
cargo build --locked --offline
python3 scripts/run-opentofu-plan.py
```

The harness requires `tofu` and uses only its built-in `terraform_data`
resource. In a disposable directory it initializes local state, applies three
old replica inputs, saves a three-update plan for the authenticated new goal,
renders the real JSON form, and evaluates it through the product CLI. Two local
producer processes separately invoke `tofu show -json`, sign, and return the
same exact bytes through the authenticated Unix relays used by the packaged
Linux isolation profile. The harness checks the plan and quorum digests and
target-mutation report, then proves renderer failure/timeout, malformed and
oversized rendering, unsafe key permissions, symlinked saved plans, forgery,
producer disagreement, replacement, and authority-tampered inputs emit no
evidence. Local state setup is
harness-only; the Telosieve evaluation itself remains read-only.

## Failure, performance, and claim bounds

The adapter performs one bounded file read and linear work over at most 64
changes and 256 values per replica. Plan input is capped at 2 MiB; each producer
stdout is capped at 5 MiB to accommodate hexadecimal framing and is terminated
after five seconds. The reference producer caps a saved binary plan at 128 MiB,
rendered JSON at 2 MiB, attestation material at 64 KiB, stderr at 16 KiB, and
each OpenTofu/signing subprocess at three seconds. Evidence output keeps the existing single-writer,
append-only-ledger and atomic current-certificate limitations.

The producer executables and their arguments are trusted local configuration.
They corroborate only the bytes presented to them: project-controlled fixture
producers can share the same host, saved binary plan, plan-generation process,
provider, state, or backend fault. The harness is project-controlled evidence
on OpenTofu 1.12.5.
It does not establish independent provider/state truth, validate external
providers or remote backends, prove policy completeness or eventual apply
behavior, hold credentials, establish organizational independence, or validate
Terraform compatibility.
