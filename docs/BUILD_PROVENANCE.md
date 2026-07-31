# Candidate Build Provenance

`scripts/run-reproducible-build-qualification.py` performs two isolated,
non-incremental `cargo build --release --locked --offline` builds with the local
locked dependency cache. It requires byte-identical binaries, detects a
deliberately altered comparison, and records the source commit, clean-tree flag,
binary digest and size, Rust/Cargo identity, target, elapsed time, peak child
RSS, and temporary work size.

The qualification bounds each build to 120 seconds, each binary to 128 MiB,
combined temporary output to 1 GiB, and peak child RSS to 1 GiB. Temporary
target directories are removed on success and failure.

```sh
python3 scripts/run-reproducible-build-qualification.py
```

For candidate signing, retain a passing record whose `working_tree_clean` is
true and whose `source_commit` equals the bundle manifest. Build the bundled
binary through this exact release command and confirm its digest matches the
record before signing.

This is same-source, same-host, same-toolchain project-controlled evidence. It
does not establish hermeticity, independently reproduced binaries, compiler or
dependency trust, cross-platform reproducibility, or a verifiable mapping from
source semantics to machine code. Those remain external provenance gates.
