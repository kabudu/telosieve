# Release Strategy

There is no product release yet. Research releases require:

1. frozen protocol and fault model;
2. reproducible harness and locked dependencies;
3. complete baseline and adversarial results;
4. security and soundness review;
5. refreshed novelty/name diligence;
6. explicit limitations and negative results.

Version `0.1.0-research` may tag the first reproducible artifact. Public hosting,
packages, telemetry, production adapters, and claims are separately gated.

The M3 decision is to narrow the project to private research. The observed
weakened-viability unsafe approval blocks `0.1.0-research`, any public release,
and productisation. A tag or release requires a new explicit decision after the
reopening conditions in
[PRODUCTISATION_DECISION](PRODUCTISATION_DECISION.md) are satisfied.

Certificate v4's stable-key safety kernel removes the original and cross-domain
unsafe approvals across all retained fixtures and the 512 generated scenarios.
The release block remained in force at certificate v5 because this finite
evidence is not a general safety proof, authenticated disagreement fails closed,
authorized deletion had no protocol, third-party organizational reproduction and
review were missing, domain independence was unverified, and no new explicit
release decision had been made.

Certificate v6 subsequently adds exact context-bound deletion authorization.
Certificate v7 adds bounded, atomic one-shot consumption to the single-host
anchored path. The release block remains because production actuation,
independent review/reproduction, platform-qualified durable storage, and
verified organizational domain separation are still absent.

Certificate v8 adds a transactional file-backed reference actuator and auditable
before/after state digests. It removes the pure-simulation limitation only for
that bounded local backend; external production actuation and its operational
qualification remain blocked.

Actuator schema v2 adds measured macOS/aarch64 recovery, exact-latest backup
restore, and rollback detection against a co-located witness. This does not
qualify whole-disk recovery, other platforms, hostile storage, multiple hosts,
or an external production service, so the release block remains.

Pinned offline Linux arm64 and emulated amd64 containers subsequently reproduce
the recovery-state and forced-termination suites on Docker-managed volumes.
This removes the macOS-only software-path limitation for that VM boundary, but
does not qualify bare-metal power loss, device caches, hostile storage,
multi-host operation, or external actuation. The release block remains.

## CI and delivery policy

Telosieve is private, so local CI is the sole authoritative quality gate:

```sh
./scripts/ci-local.sh
```

Every milestone is developed on a scoped feature branch, validated with that
command, pushed, reviewed through a pull request, and squash-merged. The command
must pass again at the final reviewed head. Its result is recorded in the pull
request. Absent hosted checks are policy-compliant and must never be represented
as passing hosted CI.

Hosted CI is disabled by policy. It may be introduced only at a documented
public-opening or research-release gate with explicit user approval and a review
of workflow permissions, secrets, cost, dependency provenance, and untrusted
pull-request behavior. A visibility change alone does not authorize hosted CI.
