# Contributing to Telosieve

Telosieve welcomes narrowly scoped research, security, documentation, integration, and implementation contributions. Read [AGENTS.md](AGENTS.md), [Product Specification](docs/PRODUCT_SPECIFICATION.md), [Threat Model](docs/THREAT_MODEL.md), and [Release Strategy](docs/RELEASE.md) before changing release-critical behavior.

## Development workflow

1. Start from current `master` with a clean worktree.
2. Create a focused branch and state atomic acceptance criteria.
3. Update implementation, behavioral tests, evidence, documentation, risks, compatibility, and roadmap state together.
4. Run `./scripts/ci-local.sh`; the complete local gate and applicable hosted
   `portable` check must both pass.
5. Open a pull request describing impact, validation, limitations, and any unresolved evidence gap.
6. Address material review findings and rerun the complete local gate at the reviewed head.

The protected `master` branch requires an up-to-date passing `portable` check,
a pull request, resolved review conversations, and linear history. Force pushes
and branch deletion are disabled. Repository-administrator bypass exists only
for the documented privacy-safe local squash procedure in
[Release Strategy](docs/RELEASE.md); it does not authorize ordinary direct
pushes or omitted review.

Do not add hosted CI, publish packages, change repository visibility, weaken fail-closed behavior, introduce mutation credentials, or broaden product claims without the separately documented approval gates.

## Engineering expectations

- Prefer the simplest sufficient architecture and bounded resource paths.
- Treat malformed, stale, ambiguous, divergent, unavailable, or oversized evidence as refusal, never success.
- Preserve protocol compatibility unless an explicit migration and versioning decision authorizes a break.
- Add tests through public behavior, including refusal and partial-failure paths.
- Keep secrets, credentials, private keys, evaluator data, and machine-specific paths out of commits, fixtures, logs, and diagnostics.
- Use UK English in project documentation and do not use Unicode U+2014.

By submitting a contribution, you agree that it is licensed under the repository's Apache License 2.0 terms. Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.
