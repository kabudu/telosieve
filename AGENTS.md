# Telosieve Agent Instructions

## Engineering standard

Apply Lazarus Mode to every implementation and release increment. Define atomic
acceptance criteria before editing, use the simplest sufficient architecture,
bound failure and resource paths, validate in proportion to risk, and audit every
requirement before declaring a milestone complete.

## Private-repository CI policy

While Telosieve is private, `./scripts/ci-local.sh` is the sole authoritative CI
gate. Run it before every milestone commit and again at the final reviewed pull
request head. Record the exact command and successful result in the pull request.
Absent hosted checks are policy-compliant; never describe them as passing.

Do not create or enable GitHub Actions or any other hosted CI. Hosted CI requires
all of:

1. a documented public-opening or research-release decision;
2. explicit user approval to activate hosted CI;
3. an update to `docs/RELEASE.md` in the authorizing pull request;
4. secrets, permissions, cost, and supply-chain review before activation.

Making the repository public does not itself authorize hosted CI.

## Milestone delivery loop

For every roadmap increment:

1. Start from a clean, current `master`.
2. Select one unchecked milestone and define its acceptance evidence.
3. Create `codex/<short-item-name>` from `master`.
4. Implement code, tests, evidence, documentation, risks, and roadmap state
   together.
5. Run `./scripts/ci-local.sh` and perform a Lazarus Mode self-review.
6. Commit only intended files and push the feature branch.
7. Open a pull request against `master`; inspect its complete remote diff and all
   review feedback.
8. Fix material findings and rerun `./scripts/ci-local.sh` at the reviewed head.
9. Squash-merge only a current, review-complete head with successful local CI.
10. Fast-forward local `master`, verify local and remote SHAs, delete the merged
    local branch, and only then begin another milestone.

Do not push implementation milestones directly to `master`, bypass review, treat
one milestone as completing later work, or publish packages/releases without the
separate gates in `docs/RELEASE.md`.
