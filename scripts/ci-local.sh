#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

run() {
  printf 'local-ci: %s\n' "$*"
  "$@"
}

if [[ -d .github/workflows ]]; then
  printf 'local-ci: hosted CI workflows are forbidden while the repository is private\n' >&2
  exit 1
fi

run cargo fmt --all --check
run cargo clippy --locked --offline --all-targets --all-features -- -D warnings
run cargo test --locked --offline --all-targets --all-features
run env RUSTDOCFLAGS=-Dwarnings cargo doc --locked --offline --no-deps
printf 'local-ci: cargo metadata --locked --offline --no-deps --format-version 1\n'
cargo metadata --locked --offline --no-deps --format-version 1 >/dev/null
run python3 scripts/validate-project.py
run python3 scripts/validate-assessor-manifest.py
run python3 scripts/validate-supply-chain.py
run git diff --check

if rg -n '\b(TODO|FIXME|REPLACE_WITH)\b' \
  README.md AGENTS.md docs src tests examples scenarios Cargo.toml; then
  printf 'local-ci: incomplete placeholder marker found\n' >&2
  exit 1
fi

printf 'local-ci: passed\n'
