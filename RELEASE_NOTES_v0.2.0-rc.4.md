# Telosieve v0.2.0-rc.4: Public evaluation release

Telosieve is now publicly available for inspection, integration testing, and independent assessment as read-only evaluation software.

## Highlights

- **Read-only evaluation:** evaluate authenticated infrastructure intent against corroborated observations and viability rules without mutating targets.
- **Mainstream integrations:** exercise Kubernetes, OpenTofu, Redis, PostgreSQL, and fixed GET-only HTTP/JSON paths.
- **Fail-closed evidence:** refuse missing, stale, malformed, divergent, oversized, or unsupported inputs instead of guessing.
- **Public toolchain:** install from crates.io, inspect Apache-2.0 source, run portable GitHub CI, and explore the GitHub Pages architecture site.
- **Assessment package:** follow the documented assessor workflow, threat model, negative findings, compatibility rules, and retained qualification evidence.

## Evaluation boundary

This release does not grant production mutation authority and is not a general safety, Byzantine-resilience, novelty, production-readiness, or independent-validation claim. Observation domains remain project-configured, and retained qualifications do not prove organisational independence or arbitrary-system correctness.

## Installation

Install the command-line evaluator with `cargo install telosieve --version 0.2.0-rc.4`, or build the tagged source with Rust 1.97 using `cargo build --locked --release`.

## Evidence and compatibility

The release includes certificate compatibility for v7 through v11, mandatory observation quorum bindings for all supported modes, reproducible local build qualifications, bounded adversarial coverage, and disposable real-system integration harnesses. See [Validation](docs/VALIDATION.md), [Protocol Compatibility](docs/PROTOCOL_COMPATIBILITY.md), and the [Changelog](CHANGELOG.md).

## External validation requested

Independent assessors should prioritize parser and protocol soundness, correlated producer or control-plane faults, managed Kubernetes and remote-state OpenTofu behavior, independently operated Redis, PostgreSQL and HTTP endpoints, identity and key custody, denial-of-service bounds, cross-platform reproducibility, and operator recovery. Begin with the [External Assessment Guide](docs/EXTERNAL_ASSESSMENT.md).
