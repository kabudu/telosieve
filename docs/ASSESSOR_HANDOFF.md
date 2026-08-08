# Independent-Assessment Handoff

Date: 2026-07-29

> **Historical handoff:** this document reproduces the Post-M15 research state
> only. It does not apply to a signed release candidate. Assess the current candidate
> using the current [External Assessment Guide](EXTERNAL_ASSESSMENT.md).

The machine-readable handoff at `assessment/manifest.json` freezes source commit
`971e9206eb891eeb53b78ffb27171291d81d4db7`. That commit is the Post-M15 source
head; Post-M16 adds only the manifest, verification tooling, retained result, and
documentation around it. A commit cannot contain its own Git object ID without
a self-referential hash, so the assessed source and handoff wrapper are
deliberately separated.

The manifest names the three exact local commands, binds nine representative
inputs and retained results by SHA-256, and states five claim boundaries and six
unresolved release blockers. `scripts/validate-assessor-manifest.py` validates
the schema, full commit identity, immutable Git-object digests, sorted unique
paths, command set, private-repository status, and absence of hosted workflows.

Run:

```sh
./scripts/verify-assessor-handoff.sh > results/assessor-handoff.json
```

The verifier creates a fresh local clone in a bounded temporary directory,
checks out the frozen commit detached, requires a clean worktree, runs
`./scripts/ci-local.sh`, regenerates the incident and parser-corpus aggregates,
requires byte-for-byte agreement with the retained results, emits JSON only
after success, and removes the clone on exit. Cargo operations remain locked and
offline. The workflow does not request or exercise production credentials.

This prepares evidence for an assessor; it is not independent assessment. The
author, machine, organization, and local dependency cache remain project-owned.
The release and productisation blocks in `docs/RELEASE.md` remain binding.
