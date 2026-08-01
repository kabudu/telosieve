# Private Evaluation Bundle Qualification

`scripts/build-private-bundle.py` creates an offline deterministic ZIP from an
absolute locally validated Telosieve binary and a fixed allowlist of evaluation
configuration, RBAC, lifecycle, diagnostics, policy, and operator documents.
The fixed allowlist includes all three contracted configurations, the Kubernetes
and OpenTofu integration material, authenticated offline/real-cluster scenarios,
the candidate test plan, and the operator/security documents needed to assess
them. It also includes and digest-binds the adversarial coverage contract,
validator, and retained result so open research gaps travel with the candidate.
The strict pre-freeze readiness map, validator, and retained result distinguish
seven locally verified gates from the exact-byte signing gate that closes only
during candidate freeze.
The fixed contents also carry the bounded sustained-load harness and its retained
qualification contract.
The builder executes the supplied binary's bounded
`evaluation-capabilities` command and refuses unless it exactly matches contract
v2, the packaged configurations, and the three-mode test plan. Every entry and
the canonical full source commit are bound by the version 3
`bundle-manifest.json`; timestamps,
ordering, compression, and modes are fixed.
Only the Telosieve binary, Kubernetes/OpenTofu observation producers, relay and
client, and Linux identity-qualification tools are executable in the archive;
other allowlisted source material is read-only. The producer programs still
require operator-supplied platform executables, configuration, saved plans or
credentials, and signing keys.
The bundle also carries the authenticated Unix relay/client, hardened systemd
template, example relay profiles, local qualification, and pinned offline Linux
multi-UID qualification used to prepare and test separate producer identities;
it does not create host accounts or install services automatically.

```sh
python3 scripts/build-private-bundle.py \
  --binary "$(pwd -P)/target/release/telosieve" \
  --source-commit "$(git rev-parse HEAD)" \
  --output /secure-private/telosieve-evaluation.zip
```

The output must be an absent absolute path and is published no-clobber with mode
`0600`. Static inputs are limited to 16 MiB each and 32 MiB total; binary
capability collection is limited to 64 KiB and five seconds.
`scripts/run-private-bundle-qualification.py` builds twice and requires
byte identity, verifies every manifest entry, forcibly terminates a build before
publication, proves no output appeared, then proves recovery produces the same
digest. It validates the exact capability, contract, configuration, test-plan,
profile, and manifest relationships and refuses mismatched, malformed,
oversized, or timed-out capability binaries without publication. It records
wall time, peak child RSS, platform, and a 160 MiB output ceiling under a
15-second deadline.

`evaluation/candidate-profile.json` inside the ZIP labels the output
`unsigned-private-evaluation-candidate-input`, binds the exact capability and
contract digests, and keeps both signing and independent assessment mandatory.
It is deliberately not a ceremony record or release authorization.

Use [CANDIDATE_SIGNING](CANDIDATE_SIGNING.md) only after the exact commit has
passed review and authoritative local CI.

The CLI can sign the exact ZIP with a domain-separated Ed25519 envelope and
verify it against independently supplied trust and evaluation time:

```sh
telosieve bundle-public-key /secure/signing/private-key.hex
telosieve bundle-sign /secure-private/telosieve-evaluation.zip \
  /secure/signing/private-key.hex telosieve/private-evaluation \
  release-lab key-2026 1785456000 1788048000 \
  /secure-private/telosieve-evaluation.signature.json
telosieve bundle-verify /secure-private/telosieve-evaluation.zip \
  /secure-private/telosieve-evaluation.signature.json \
  /secure-private/telosieve-evaluation.trust.json
```

The strict trust JSON contains `context`, `evaluation_time`, and one to eight
keys with `signer`, `key_id`, lowercase-hex `public_key`, `not_before`, and
`not_after`. Obtain it independently of the bundle channel. Signing keys must
be absolute, owner-only, regular, single-link files; signatures are create-new
mode `0600`. Never place a private key in the bundle or trust file.

This bundle is private candidate input, not a release. The protocol test uses
an ephemeral key, not an operational release identity. Current measurements
cover the local macOS host and a project-controlled Linux container, not real
systemd, managed-platform load, power loss, hostile storage, or multi-host
rollout. Independent assessment of the exact eventual signed bundle
remains mandatory before stronger safety or production claims.
