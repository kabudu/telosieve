# v0.2.0-rc.2 Freeze Record

Date: 2026-08-08

## Frozen identity

- version and annotated tag: `0.2.0-rc.2`, `v0.2.0-rc.2`;
- rewritten source commit: `3539e3825a97a107703fccbf6f4a8de92c786c09`;
- remote `master` and peeled remote tag commit at the ceremony:
  `3539e3825a97a107703fccbf6f4a8de92c786c09`;
- target: `aarch64-apple-darwin`;
- Rust: `rustc 1.97.0 (2d8144b78 2026-07-07)`;
- Cargo: `cargo 1.97.0 (c980f4866 2026-06-30)`.

## Gate and build evidence

`./scripts/ci-local.sh` passed from a clean worktree at the frozen source
commit. Hosted checks were absent by private-repository policy and are not
described as passing. Two isolated locked/offline release builds produced
identical 2,318,320-byte binaries with SHA-256
`09b12213e729bde399376f087bbde2264c0e37879318ebb4dcc23f22806aab76`.
The qualification recorded an alteration refusal and a peak child RSS of
633,782,272 bytes.

## Signed handoff

The atomic seven-file handoff was created outside Git under the directory name
`v0.2.0-rc.2`. Its manifest reports:

- status: `signed-private-evaluation-release-candidate`;
- signer: `telosieve-project-evaluation`;
- key ID: `v0.2.0-rc.2`;
- context: `telosieve/private-evaluation`;
- custody: `project-controlled-evaluation`;
- authority: `read-only-no-target-mutation`;
- issued/evaluation time: `2026-08-08T14:59:24Z`;
- expiry: `2026-09-07T14:59:24Z`;
- bundle SHA-256:
  `1d5609ff7f3937d55c2dc70bc9408e28c29c681ba1ed0981315929dff24ecb5f`;
- trust-record SHA-256:
  `66bbf015c186cd70312aa483bde078d9c11b6412d2cd53e4a37f186526c9c452`.

All six checksummed payload files passed SHA-256 verification. The packaged
offline verifier accepted the signature, exact source commit, seven-artifact
shape, expected version, and independently built source-binary digest. The
owner-only 64-byte signing key remained a mode `0600`, regular, single-link file
outside both Git and the handoff; its contents and path are intentionally not
recorded here.

## Boundary and next gate

This record closes the project-controlled rc.2 freeze. It does not convert that
signature into independent evidence, authorize production promotion, authorize
public artifact distribution, establish external organizational independence,
or establish general safety. Named evaluators must authenticate the trust-record
digest through a channel separate from the private create-new handoff. Public
source visibility remains governed by [Public Opening Decision](PUBLIC_OPENING_DECISION.md).
