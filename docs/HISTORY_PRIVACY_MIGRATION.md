# History Privacy Migration

Date authorized: 2026-08-08

Status: completed 2026-08-08

## Requirement

The owner's personal email address must not occur in any current file,
historical blob, commit header, tag header, branch, pull-request ref, release
record, or other object exposed by the Telosieve repository.

## Decision

A force-push into the former GitHub repository was insufficient because closed
pull-request refs and platform-retained objects may continue to expose rewritten
commit metadata. The private GitHub repository was therefore replaced by a newly
created private repository at the same owner/name after all commit and tag
identities were rewritten to the owner's GitHub noreply address.

The migration preserves source-file content and commit topology but intentionally
changes every affected object ID. Old pull requests, remote feature branches,
annotated tags, comments, and repository-local platform history will not be
carried into the replacement repository. The existing signed rc.1 and rc.2
candidates are commit-bound to the superseded graph and become revoked historical
evidence, not distributable candidates. A successor candidate must be versioned,
qualified, signed, verified, and tagged from the sanitized graph.

## Acceptance criteria

1. Repository-local author configuration uses the GitHub noreply address.
2. Every commit and tag reachable from every retained ref is free of the personal
   address.
3. Every historical and current blob passes the bounded secret, path, and identity
   audit.
4. The replacement GitHub repository is private, has only intentionally retained
   sanitized refs, and reports the sanitized `master` head.
5. A fresh clone contains no personal address in `git log --all`, `git cat-file`
   output, tracked files, or the bounded object audit.
6. Old candidate tags are absent and their revocation is documented.
7. The next signed candidate binds the sanitized source commit and passes offline
   verification before source visibility can change.

Abort the public-opening sequence if any retained or platform-visible ref exposes
the old graph, if repository recreation cannot be verified, or if a candidate or
document still treats a superseded commit as current.

## Completion evidence

The sanitized graph contains 88 commits and no tags. Its sole branch is `master`
at `4d1ca3efe151556a3cb992cdc8a7d2cb9b0418f8`. Before replacement, the complete
authoritative local gate passed at that head, including the real-cluster and
external-system harnesses.

The former private repository was deleted and a new private repository was
created at the same owner/name. Remote enumeration then reported exactly one
head (`master`) and no tags. A fresh single-branch, no-tags clone established:

- the remote head and local head were identical;
- `git log --all` contained only the configured GitHub noreply identity;
- `git fsck --full --no-reflogs --unreachable` reported no unreachable objects;
- the bounded history audit passed 1,876 objects, including 88 metadata objects
  and 1,338 historical blobs; and
- the working tree was clean.

The obsolete local object database and migration workspaces were removed after
the fresh-clone verification. Criteria 1–6 are complete. Criterion 7 remains the
next release milestone: freeze a newly versioned candidate from this sanitized
graph before any source-visibility change.
