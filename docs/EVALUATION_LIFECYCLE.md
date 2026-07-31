# Evaluation Installation Lifecycle

## Scope and support boundary

`scripts/evaluation-lifecycle.py` packages a locally built Telosieve binary and
one v1 or v2 evaluation configuration into a private, single-host installation.
The supported filesystem boundary is macOS or Linux with Python 3, atomic
same-filesystem rename, symlinks, and local storage. This workflow does not
publish, download, sign, or distribute an artifact, install a service, create
credentials, or qualify a Kubernetes cluster.

Build and validate the exact source locally before installation:

```sh
./scripts/ci-local.sh
cargo build --locked --offline --release
```

Choose an absolute installation root on a local filesystem. The examples use
`/opt/telosieve-evaluation`; substitute an operator-owned path when unprivileged
installation is required. Supply a separately reviewed configuration whose
output paths are absolute and point into the installation's `evidence`
directory or another protected retained location.
All packaged configuration paths must be absolute so activation cannot change
their meaning when the digest-named release directory changes.

## Layout and invariants

The managed root contains:

```text
current -> releases/<release-digest>
releases/<release-digest>/telosieve
releases/<release-digest>/evaluation.json
releases/<release-digest>/install.json
evidence/
```

The release digest binds the binary and configuration digests. `current` is
replaced atomically, so readers see the complete previous or next pair, never a
new binary with an old configuration. Files are copied rather than linked to
caller-controlled sources. The root, releases, backups, configuration, and
evidence use owner-only permissions; installed releases are owner-read-only and
binaries are owner-executable.

Each operation takes an exclusive `.lifecycle.lock`. A concurrent or
interrupted operation refuses. Remove a stale lock only after proving that no
lifecycle process remains and preserving the root for investigation. At most 16
release directories, 10,000 backup files, 1 GiB of backup content, a 128 MiB
binary, and a 64 KiB configuration are accepted.

## Install

The root must be absolute, non-symlinked, and absent as an installation:

```sh
python3 scripts/evaluation-lifecycle.py install \
  --root /opt/telosieve-evaluation \
  --binary "$(pwd -P)/target/release/telosieve" \
  --config "$(pwd -P)/evaluation/config.json"
```

Run the installed boundary explicitly:

```sh
/opt/telosieve-evaluation/current/telosieve evaluate \
  /opt/telosieve-evaluation/current/evaluation.json
```

Installation refuses a non-executable, oversized, relative, or symlinked binary;
an invalid or unsupported configuration; a conflicting release; and an already
installed root.

## Backup

Back up before every upgrade and before uninstall. The destination must be an
absent absolute path outside the installation root:

```sh
python3 scripts/evaluation-lifecycle.py backup \
  --root /opt/telosieve-evaluation \
  --output /secure-backups/telosieve-before-upgrade
```

The backup contains the active binary/configuration release, retained evidence,
and `backup.json`, which binds every file path, size, and SHA-256 digest. Keep
the directory owner-only, on separately protected storage, and under the
retention policy for its potentially sensitive evidence. Backups are
point-in-time file copies, not a coordinated snapshot with a running evaluator;
stop evaluation writers before backup.

## Upgrade

After local CI and backup, activate a new binary/configuration pair:

```sh
python3 scripts/evaluation-lifecycle.py upgrade \
  --root /opt/telosieve-evaluation \
  --binary "$(pwd -P)/target/release/telosieve" \
  --config "$(pwd -P)/evaluation/config.json"
```

Upgrade verifies the current release, fully materializes and verifies the new
immutable release, then atomically switches `current`. It never edits or deletes
evidence. A failure before activation leaves the previous release active; a
failure after activation leaves the complete new pair active. Verify
`current/telosieve --version`, run a bounded evaluation smoke check, and retain
the pre-upgrade backup before accepting the upgrade.

## Rollback

Rollback restores only the backed-up binary/configuration pair:

```sh
python3 scripts/evaluation-lifecycle.py rollback \
  --root /opt/telosieve-evaluation \
  --backup /secure-backups/telosieve-before-upgrade
```

Every backup inventory entry and release digest is verified before activation.
Tampering, missing files, unexpected files, symlinks, or digest mismatch refuse
without switching `current`. Rollback deliberately does not rewind, replace, or
restore the live `evidence` directory because doing so could erase append-only
history or re-authorize stale work. Reconcile preserved evidence and obtain
fresh authenticated inputs before the next evaluation.

## Uninstall

Take and verify a final backup, stop evaluation writers, then pass the canonical
root twice:

```sh
root="$(cd /opt/telosieve-evaluation && pwd -P)"
python3 scripts/evaluation-lifecycle.py uninstall \
  --root "$root" \
  --confirm-root "$root"
```

Uninstall verifies the active managed release and exact confirmation before
removing only `current` and `releases`. It preserves `evidence`, backups outside
the root, and the root itself. Review and dispose of preserved evidence only
under the approved retention/deletion policy; the lifecycle tool never deletes
it.

## Recovery and limitations

On any error, stop and inspect stderr, `.lifecycle.lock`, `current`, the release
manifests, and the backup manifest. Do not repoint symlinks, edit manifests, or
remove release files manually to make verification pass. Restore software only
through a verified backup.

This milestone proves the lifecycle against a real locally built Telosieve
binary, its embedded independent Python checker, and temporary local
filesystems. The host must provide `python3`; no source checkout is needed at
runtime. It does not yet qualify power-loss
durability, network filesystems, package managers, service supervisors,
container images, Windows, multi-host rollout, privileged path ownership, or a
signed/checksummed reproducible private distribution bundle.
