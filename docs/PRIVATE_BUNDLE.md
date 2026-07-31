# Private Evaluation Bundle Qualification

`scripts/build-private-bundle.py` creates an offline deterministic ZIP from an
absolute locally validated Telosieve binary and a fixed allowlist of evaluation
configuration, RBAC, lifecycle, diagnostics, policy, and operator documents.
Every entry and the canonical full source commit are bound by the version 2
`bundle-manifest.json`; timestamps,
ordering, compression, and modes are fixed.

```sh
python3 scripts/build-private-bundle.py \
  --binary "$(pwd -P)/target/release/telosieve" \
  --source-commit "$(git rev-parse HEAD)" \
  --output /secure-private/telosieve-evaluation.zip
```

The output must be an absent absolute path and is published no-clobber with mode
`0600`. `scripts/run-private-bundle-qualification.py` builds twice and requires
byte identity, verifies every manifest entry, forcibly terminates a build before
publication, proves no output appeared, then proves recovery produces the same
digest. It records wall time, peak child RSS, platform, and a 160 MiB output
ceiling under a 15-second deadline.

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
cover the local macOS host, not Linux, Kubernetes runtime load, power loss,
hostile storage, or
multi-host rollout. Independent assessment of the exact eventual signed bundle
remains mandatory before stronger safety or production claims.
