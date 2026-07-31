# Private Evaluation Bundle Qualification

`scripts/build-private-bundle.py` creates an offline deterministic ZIP from an
absolute locally validated Telosieve binary and a fixed allowlist of evaluation
configuration, RBAC, lifecycle, diagnostics, policy, and operator documents.
Every entry is size- and SHA-256-bound by `bundle-manifest.json`; timestamps,
ordering, compression, and modes are fixed.

```sh
python3 scripts/build-private-bundle.py \
  --binary "$(pwd -P)/target/release/telosieve" \
  --output /secure-private/telosieve-evaluation.zip
```

The output must be an absent absolute path and is published no-clobber with mode
`0600`. `scripts/run-private-bundle-qualification.py` builds twice and requires
byte identity, verifies every manifest entry, forcibly terminates a build before
publication, proves no output appeared, then proves recovery produces the same
digest. It records wall time, peak child RSS, platform, and a 160 MiB output
ceiling under a 15-second deadline.

This bundle is private candidate input, not a release. It is checksummed but not
signed by an operational release identity. Current measurements cover the local
macOS host, not Linux, Kubernetes runtime load, power loss, hostile storage, or
multi-host rollout. Independent assessment of the exact eventual signed bundle
remains mandatory before stronger safety or production claims.
