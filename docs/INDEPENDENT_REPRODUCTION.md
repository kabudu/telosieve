# Isolated Reproduction

## Result

On 2026-07-29, revision
`8ee63cb3cb0f2fee303bcdefa20d5aed20fcd8b3` was reproduced in a separate
network-disabled Linux/arm64 container:

- image `rust:1.97-bookworm`;
- image ID
  `sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa`;
- Rust/Cargo 1.97.1 and Python 3.11.2, distinct from the macOS host's
  Rust/Cargo 1.97.0 and Python 3.14.6;
- repository mounted read-only, with disposable tmpfs paths for build and test
  scratch data;
- dependency cache copied from a read-only mount and Cargo forced offline.

All 16 tests, warning-denied rustdoc, locked/offline metadata resolution, project
validation, and all four registered benchmarks passed. Deterministic decisions,
hypothesis counts, certificate sizes, unsafe approvals, false refusals, and
baseline unsafe approvals matched the macOS evidence. Linux timing differed and
is not used as a correctness assertion. The machine-readable record is
`results/isolated-reproduction-2026-07-29.json`.

## Reproduction

With Docker, the cached image, and a populated Cargo registry cache:

```sh
./scripts/reproduce-container.sh
```

The stock image lacks rustfmt and Clippy, so the isolated run does not claim those
checks. Both pass in authoritative host local CI. The isolated run covers
behavior, documentation, dependency resolution, repository policy, and registered
experiment outputs.

## Independence boundary

This is environment and toolchain independence, not an independent organization,
operator, or reimplementation. It is sufficient to reject a macOS/Python-3.14-only
artifact explanation. It does not satisfy the stronger productisation requirement
for third-party reproduction or independent security review.
