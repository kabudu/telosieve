# Private Candidate Signing Ceremony

This procedure freezes a private evaluation candidate. It does not authorize a
public or production release, create a signing identity, establish custody, or
replace independent assessment.

## Preconditions

1. Record a clean reviewed `master` commit and run `./scripts/ci-local.sh` at
   that exact commit.
2. Build the release binary and deterministic bundle with the full commit SHA.
   Retain a passing clean-tree [BUILD_PROVENANCE](BUILD_PROVENANCE.md) record
   for that commit and require the bundled binary digest to match it.
3. Have two named custodians verify the commit, bundle manifest, intended
   recipients, context, signer, key ID, and validity interval. The private key
   remains offline, outside the repository and bundle.
4. Obtain the public trust record through a channel independent of the bundle.

## Ceremony

Run the documented `bundle-sign` command once against the frozen bundle. Then
run `bundle-verify` with the independently delivered trust record and an agreed
evaluation time. Both custodians record the exact source commit; SHA-256 digests
of the bundle, signature, and trust file; CLI version; signer and key ID;
validity interval; recipient set; and verification outcome.

Publish by create-new transfer only. Preserve the three exact files and ceremony
record read-only. Abort on dirty source, digest drift, existing output, key-file
policy failure, verification failure, disagreement, unexpected recipient, or
partial transfer. Do not repair a refusal by changing time, trust, metadata, or
artifact bytes; investigate and restart from a newly reviewed candidate.

`scripts/build-release-candidate.py` implements the project-controlled private
evaluation freeze and `scripts/verify-release-candidate.py` verifies the exact
handoff offline. The builder requires clean `master`, the reviewed source
commit, the binary digest from clean-tree reproducibility evidence, an external
owner-only key, an absent output directory, and an explicit validity window. It
publishes the directory atomically only after signature verification.
The handoff verifier requires `--trusted-telosieve` pointing to an absolute
binary obtained independently of the handoff, such as one rebuilt from the
reviewed source commit. It never executes the bundled binary before signature
verification; that binary is only digest-checked against the candidate manifest.

## Remaining gates

Project tests may simulate this workflow only with ephemeral keys and named
roles. An operational ceremony requires an explicitly approved identity,
independently governed custody, real custodians, an approved private channel,
and subsequent assessment of these exact bytes.
