# External Assessment Guide

This is the canonical assessor entrypoint for Telosieve `v0.2.0-rc.2`. The
candidate is private, read-only evaluation software. A successful assessment
does not authorize production deployment, public release, Kubernetes or
OpenTofu actuation, or a general safety claim.

## Candidate identity

Assess only a seven-file handoff whose candidate manifest reports:

- version: `0.2.0-rc.2`;
- source commit: the 40-character commit authenticated out of band and repeated
  exactly in the candidate manifest and embedded bundle manifests;
- status: `signed-private-evaluation-release-candidate`;
- authority boundary: `read-only-no-target-mutation`;
- independent assessment required: `true`;
- production and public-release authorization: `false`.

The tag, commit, handoff location, and SHA-256 of the public trust record must
reach the assessor through a channel independent of the handoff. Refuse the
assessment if the project cannot provide that independently authenticated
metadata. The `SHA256SUMS` file protects against accidental corruption only
until its expected value is independently authenticated; it is not a trust
anchor by itself.

The signed release notes inside the handoff are the candidate's
evaluator-facing claim record. Refuse a handoff when the manifest commit differs
from the independently authenticated expected commit.

## Safety rules

1. Work in a disposable environment without production credentials.
2. Obtain the source repository and candidate handoff through separate agreed
   channels when possible.
3. Do not run `bin/telosieve` from the ZIP before verification succeeds.
4. Do not execute the verifier copied inside the untrusted handoff. Use the
   verifier from an independently obtained checkout of the frozen source.
5. Compare the handoff trust record with its independently supplied SHA-256
   before verification. A signature checked against attacker-supplied trust is
   not proof of the project signing identity.
6. Preserve the original handoff read-only and perform experiments on copies.
7. Treat configurations, evidence, paths, digests, cluster metadata, saved
   plans, and assessment results as potentially sensitive.

Stop and report a finding if identity metadata, checksums, signature, embedded
source commit, binary digest, version, file set, or claim boundaries disagree.
Do not make candidate bytes agree by modifying them.

## Prerequisites

Handoff verification requires Python 3, Git, SHA-256 tooling, and a stable Rust
1.97-or-newer toolchain with the candidate's locked dependencies already
available when operating offline. The complete local qualification additionally
requires Bash, Docker, kind, kubectl, OpenTofu, the pinned kind node image, and
the repository's cached Linux qualification images. Consult
[Supply Chain](SUPPLY_CHAIN.md) before acquiring missing dependencies.

Use a macOS or Linux host with enough temporary storage for Rust builds,
disposable containers, and a kind cluster. Record the OS, architecture,
toolchain versions, installed dependencies, unavailable prerequisites, and all
deviations. The project's retained measurements do not establish equivalent
behavior on every platform.

## 1. Establish independent inputs

Set absolute paths without placing either tree inside the other:

```sh
SOURCE=/absolute/path/to/independently-obtained/telosieve
HANDOFF=/absolute/path/to/telosieve-v0.2.0-rc.2
```

In the source checkout, require the exact frozen commit and a clean worktree:

```sh
git -C "$SOURCE" checkout --detach ae5bfbffe96510f64026aed02e3a25b2f81cc59c
git -C "$SOURCE" status --short
git -C "$SOURCE" rev-parse HEAD
```

The status command must emit nothing and `rev-parse` must emit the full commit
above. Independently compare the public trust record digest before using it:

```sh
shasum -a 256 \
  "$HANDOFF/telosieve-0.2.0-rc.2.trust.json"
```

On Linux, `sha256sum` is equivalent. Compare the result manually with the
digest delivered through the independent authenticated channel; do not copy an
expected digest from the handoff itself.

## 2. Build the trusted verifier binary

Build from the independently obtained frozen source, not from candidate ZIP
contents:

```sh
cargo build --manifest-path "$SOURCE/Cargo.toml" \
  --release --locked --offline
"$SOURCE/target/release/telosieve" --version
```

The version command must print `telosieve 0.2.0-rc.2`. If the offline build
cannot resolve already pinned dependencies, record the missing prerequisite;
do not silently remove `--locked` or change dependency versions.

## 3. Verify the signed handoff

Run the source-checkout verifier with the independently built binary:

```sh
python3 "$SOURCE/scripts/verify-release-candidate.py" "$HANDOFF" \
  --trusted-telosieve "$SOURCE/target/release/telosieve" \
  --expected-version 0.2.0-rc.2
```

Success emits one JSON object with `status` equal to `passed`,
`signature_valid` equal to `true`, the independently authenticated source commit, and the
SHA-256 of the trusted verifier. Preserve that output with the assessment
record. The field `independent_evidence` remains `false`: cryptographic
verification authenticates candidate bytes but does not make project-produced
observations independent.

## 4. Reproduce the baseline

After successful verification, extract the candidate ZIP into a new disposable
directory. Preserve the handoff itself unchanged:

```sh
CANDIDATE=/absolute/path/to/new/disposable/candidate-directory
mkdir "$CANDIDATE"
unzip -q \
  "$HANDOFF/telosieve-0.2.0-rc.2-private-evaluation.zip" \
  -d "$CANDIDATE"
"$CANDIDATE/bin/telosieve" --version
"$CANDIDATE/bin/telosieve" evaluation-capabilities
```

Only run these candidate commands after verification. The version must be
`telosieve 0.2.0-rc.2`; capabilities must match
`$CANDIDATE/evaluation/capabilities.json`. If the packaged executable is
incompatible with the assessment host, record exact-binary execution as not run
and perform source reproduction separately. Do not substitute a rebuilt binary
and call it execution of the signed candidate executable.

Run the private repository's sole authoritative CI gate from the clean frozen
source checkout:

```sh
cd "$SOURCE"
./scripts/ci-local.sh
```

This gate is intentionally local. There are no hosted checks to treat as
passing. It runs locked, offline Rust validation plus release, lifecycle,
adversarial-load, Linux isolation, real disposable Kubernetes, and OpenTofu
qualifications. A full run therefore requires every prerequisite listed above.
Record an unavailable test as not run, never as passed.

## 5. Exercise the evaluation modes

The machine-readable [candidate test plan](../evaluation/candidate-test-plan.json)
is authoritative for the three supported modes. Run tests from the clean frozen
source checkout or from a disposable copy of the verified bundle as directed
below; never change the signed handoff.

### Kubernetes shadow

```sh
mkdir -p "$CANDIDATE/out"
cd "$CANDIDATE"
./bin/telosieve evaluate evaluation/config.example.json
```

This directly exercises the signed candidate executable against its packaged
bounded local snapshots and must report `target_mutated: false` without cluster
credentials.

### Disposable real Kubernetes

```sh
cd "$SOURCE"
python3 scripts/run-kubernetes-real-cluster.py
```

This requires Docker, kind, kubectl, and the already cached pinned node image.
It creates and unconditionally cleans up a project-defined disposable cluster.
The current harness uses `target/debug/telosieve` built from the frozen source;
it does not exercise the signed release executable. Record that distinction.
It tests a real API server and RBAC boundary, but not EKS, GKE, AKS, independent
control planes, production credentials, or organizationally independent
producers. See [Real Kubernetes Qualification](KUBERNETES_REAL_CLUSTER.md).

### Saved OpenTofu plan

```sh
cargo build --locked --offline
python3 scripts/run-opentofu-plan.py
```

This uses disposable local `terraform_data` state. Telosieve reads a saved plan
and never receives provider, backend, state-mutation, or apply authority. It
uses `target/debug/telosieve` built from the frozen source rather than the
signed release executable; record that distinction.
does not qualify remote state, external providers, Terraform compatibility, or
eventual apply behavior. See [OpenTofu Plan Evaluation](OPENTOFU_PLAN.md).

For separately operated environments, replace only documented operator inputs;
do not weaken schemas, quorum rules, timeouts, size bounds, credential
separation, or the no-mutation invariant to obtain a successful result.

## Assessment priorities

Prioritize attempts to falsify parser and protocol soundness, provenance and
identity separation, quorum independence assumptions, correlated producer and
control-plane faults, denial-of-service bounds, evidence persistence and
recovery, cross-platform reproducibility, and the no-target-mutation boundary.
Managed Kubernetes and remote-state OpenTofu measurements are especially
valuable because project-controlled local harnesses do not supply that evidence.

Expected refusal under ambiguous, malformed, stale, oversized, unauthorized,
or disagreeing evidence is a successful fail-closed outcome. An approval is
safe only within the registered bounded oracle; neither approval nor refusal is
evidence of a general safety theorem.

## Reporting format

Return one record containing:

- assessor and organization, with any independence or conflict disclosure;
- assessment dates and environment/toolchain inventory;
- candidate version, source commit, handoff checksums, independently received
  trust-record digest, and trusted-verifier digest;
- every command attempted and its exit status, including tests not run and why;
- findings classified as critical, high, medium, low, or informational;
- for each finding: affected claim or invariant, prerequisites, exact
  reproduction steps, expected and observed behavior, artifacts or logs,
  security/availability impact, and suggested smallest remedy;
- confirmation of whether any target mutation or production credential access
  was observed;
- remaining uncertainties and explicit non-conclusions;
- remediation version and reassessment result when applicable.

Use this copyable structure so absent evidence remains visible:

```md
# Telosieve external assessment record

## Identity and independence
- Assessor / organization:
- Independence and conflicts:
- Assessment interval:

## Candidate and environment
- Version / source commit:
- Handoff SHA256SUMS digest:
- Independently received trust-record digest:
- Trusted-verifier digest:
- OS / architecture / toolchains:

## Execution record
| Command | Exit status | Result | Evidence | Deviation or reason not run |
| --- | ---: | --- | --- | --- |

## Findings
### Finding identifier and title
- Severity:
- Affected claim or invariant:
- Prerequisites and reproduction:
- Expected / observed behavior:
- Evidence and impact:
- Smallest suggested remedy:

## Boundary observations
- Target mutation observed:
- Production credential access observed:
- Remaining uncertainties and explicit non-conclusions:

## Remediation and reassessment
- Remediation version:
- Reassessment result:
```

Redact secrets and application data, but retain exact candidate identities and
cryptographic digests. Send sensitive findings through the private channel
agreed with the project; this repository does not define or authorize a public
disclosure process.

## Historical handoff

[Independent-Assessment Handoff](ASSESSOR_HANDOFF.md) preserves the earlier
Post-M15 research reproduction at commit
`17ec5e04bc05ca16b322ec6e436b9979972a0ba5`. It is not the procedure for
assessing `v0.2.0-rc.2`.
