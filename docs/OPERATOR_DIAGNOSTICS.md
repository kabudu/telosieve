# Operator Diagnostics and Privacy-Reviewed Export

`scripts/evaluation-diagnostics.py` verifies one managed private evaluation
installation and writes a content-redacted diagnostic manifest:

```sh
python3 scripts/evaluation-diagnostics.py \
  --root /opt/telosieve-evaluation \
  --output /secure-handoff/telosieve-diagnostics.json
```

The root and output must be absolute. The output must not already exist and must
be outside the installation. Collection is offline, performs no network access,
does not invoke the evaluator, and writes no telemetry.

## Disclosure allowlist

The v1 export contains only:

- fixed schema, health, privacy, and check fields;
- the opaque release identifier;
- SHA-256 digests of the binary and configuration;
- aggregate evidence file count and byte size; and
- an ordinal, size, and SHA-256 digest for each evidence file.

It never includes evidence contents, configuration values, environment
variables, file or directory names, paths, command output, stderr, Kubernetes
metadata, credentials, application values, or timestamps. Digests and exact
sizes can still permit correlation or guessing of low-entropy inputs, so the
export remains sensitive assessor material and must use an approved encrypted
channel and retention policy.

## Bounds and failure behavior

Collection accepts at most 1,000 evidence files and 256 MiB total. Every
installation and evidence entry must be an owner-only regular file or directory
with no symlinks or hard links. The active release and its binary/configuration
digests must match the lifecycle manifest. Unsafe permissions, unexpected
entries, digest mismatch, bounds, an in-root destination, or an existing output
refuse before publication. Stable before/after file identity is required while
hashing. Output uses atomic no-clobber publication of a private temporary file
and mode `0600`.

The qualification places a unique secret in a path and evidence body, checks the
exact recursive output allowlist, and proves neither value nor any installation
path appears. It also proves existing-output, symlink, permission, and in-root
destination refusals.

This is privacy-reviewed project-controlled software evidence, not proof that
SHA-256 digests are anonymous, an independent privacy assessment, a support
bundle with raw evidence, telemetry, or a production observability system.
