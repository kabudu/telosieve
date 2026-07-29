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
The release block remains in force because this finite evidence is not a general
safety proof. Certificate v5 removes the measured agreeing-goal false refusals,
but authenticated disagreement still fails closed, authorized deletion has no
protocol, third-party organizational reproduction and review remain missing,
domain independence is unverified, and no new explicit release decision has
been made.

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
