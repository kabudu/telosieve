#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

run() {
  printf 'local-ci: %s\n' "$*"
  "$@"
}

run cargo fmt --all --check
run cargo clippy --locked --offline --all-targets --all-features -- -D warnings
run cargo test --locked --offline --all-targets --all-features
run cargo test --locked --offline --test integration_contract
run python3 scripts/test-redis-integration.py
run python3 scripts/test-postgresql-integration.py
run python3 scripts/test-http-json-integration.py
run env RUSTDOCFLAGS=-Dwarnings cargo doc --locked --offline --no-deps
printf 'local-ci: cargo metadata --locked --offline --no-deps --format-version 1\n'
cargo metadata --locked --offline --no-deps --format-version 1 >/dev/null
run python3 scripts/validate-project.py
run python3 scripts/validate-release-metadata.py
run python3 scripts/validate-release-presentation.py
run python3 scripts/validate-open-source-readiness.py
run python3 scripts/validate-hosted-workflows.py
run python3 scripts/validate-brand.py
run python3 scripts/validate-pages-site.py
run python3 scripts/validate-assessor-manifest.py
run python3 scripts/validate-supply-chain.py
run python3 scripts/qualify-witness-operator-record.py
run python3 scripts/validate-evaluation-contract.py
run python3 scripts/validate-candidate-readiness.py
run python3 scripts/validate-adversarial-coverage.py
run python3 scripts/run-evaluation-lifecycle-qualification.py
run python3 scripts/run-diagnostics-qualification.py
run python3 scripts/run-private-bundle-qualification.py
run python3 scripts/run-http-json-pki-prometheus-qualification.py
run python3 scripts/run-release-candidate-qualification.py
run python3 scripts/run-producer-isolation-qualification.py
run ./scripts/qualify-linux-producer-isolation.sh
run python3 scripts/run-reproducible-build-qualification.py
run python3 scripts/run-sustained-adversarial-load.py
run python3 scripts/run-kubernetes-real-cluster.py
run python3 scripts/run-opentofu-plan.py
run python3 scripts/run-redis-integration.py
run python3 scripts/run-postgresql-integration.py
run python3 scripts/run-http-json-integration.py
run git diff --check

forbidden_dash="$(printf '\342\200\224')"
if git grep -n "$forbidden_dash" -- .; then
  printf 'local-ci: Unicode U+2014 is forbidden in tracked project text\n' >&2
  exit 1
fi

if rg -n '\b(TODO|FIXME|REPLACE_WITH)\b' \
  README.md AGENTS.md docs src tests examples scenarios Cargo.toml; then
  printf 'local-ci: incomplete placeholder marker found\n' >&2
  exit 1
fi

printf 'local-ci: passed\n'
