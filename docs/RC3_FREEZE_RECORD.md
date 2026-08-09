# v0.2.0-rc.3 Freeze Record

Date: 2026-08-08

## Frozen identity

- version and annotated tag: `0.2.0-rc.3`, `v0.2.0-rc.3`;
- source commit: `ad26fe36901602ffd06d45cdcb0224401b7fb0f4`;
- remote `master` and peeled remote tag commit at the ceremony:
  `ad26fe36901602ffd06d45cdcb0224401b7fb0f4`;
- annotated tag object: `7b24a24e2d11b4ecf6d3d011d3fbc0e2ec9f7c12`;
- target: `aarch64-apple-darwin`;
- Rust: `rustc 1.97.0 (2d8144b78 2026-07-07)`;
- Cargo: `cargo 1.97.0 (c980f4866 2026-06-30)`.

The tagger identity uses the owner's GitHub noreply address. The former rc.1 and
rc.2 tags are absent from the replacement repository and remain revoked.

## Gate and build evidence

`./scripts/ci-local.sh` passed from a clean worktree at the frozen source commit.
Hosted checks were absent by private-repository policy and are not described as
passing. Two isolated locked/offline release builds produced identical
2,318,368-byte binaries with SHA-256
`dcda08b33aa4540174cf9a06e138df8dfc0fd47432b041a94676f9406de6844a`.
The qualification recorded an alteration refusal and peak child RSS of
614,301,696 bytes. The same digest was reproduced by the final source build used
for signing and offline verification.

The complete history audit passed at the frozen commit, and the literal personal
address scan returned no repository path. The replacement remote contained only
`master` before the new candidate tag was added.

## Signed handoff

The atomic seven-file handoff was created outside Git under the directory name
`v0.2.0-rc.3`. Its manifest reports:

- status: `signed-private-evaluation-release-candidate`;
- signer: `telosieve-project-evaluation`;
- key ID: `v0.2.0-rc.3`;
- context: `telosieve/private-evaluation`;
- custody: `project-controlled-evaluation`;
- authority: `read-only-no-target-mutation`;
- issued/evaluation time: `2026-08-08T23:53:55Z`;
- expiry: `2026-09-07T23:53:55Z`;
- bundle SHA-256:
  `66f6060fef6ace6cd2f85ae427f9ca8c9a45cacce0efb96012299d7a86aeb40a`;
- trust-record SHA-256:
  `86fe4529d273b9d6e3197db0aaaf4a4ebef82ab7f4c18adade3a223615677212`;
- candidate-manifest SHA-256:
  `ed93ae424b9c083cc64dbb61465cf58f5459106c915e0957c993e86fd8a9ab05`.

All six checksummed payload files passed SHA-256 verification. The packaged
offline verifier accepted the signature, exact sanitized source commit,
seven-artifact shape, expected version, and independently built source-binary
digest. The one-use 64-byte signing key was a mode `0600`, regular, single-link
file outside Git and the handoff; it was destroyed after successful remote-tag
verification. Its contents never entered command output or repository history.

## Boundary and next gate

This record closes the project-controlled privacy-safe rc.3 freeze and the final
candidate condition in [History Privacy Migration](HISTORY_PRIVACY_MIGRATION.md).
It does not convert the signature into independent evidence, authorize production
promotion, authorize public artifact distribution, establish external
organisational independence, or establish general safety. Named evaluators must
authenticate the trust-record digest through a channel separate from the private
create-new handoff. Public source visibility remains governed by
[Public Opening Decision](PUBLIC_OPENING_DECISION.md).
