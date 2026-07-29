# Dependency Provenance and Advisory Inventory

Date: 2026-07-29

`results/dependency-inventory.json` is generated from `Cargo.lock` and
`cargo metadata --locked --offline`. It records all 44 resolved packages,
including the local Telosieve package and 43 third-party registry packages.
Every entry has an exact version, source, license expression, direct/transitive
classification, and registry SHA-256 checksum where applicable. The inventory
is bound to the lockfile digest and sorted for byte-deterministic regeneration.

Generate or verify it with:

```sh
python3 scripts/dependency-inventory.py > results/dependency-inventory.json
python3 scripts/dependency-inventory.py --check results/dependency-inventory.json
```

The retained graph has six direct third-party packages. Its declared license
expressions are Apache-2.0, MIT, BSD-3-Clause, Unicode-3.0, LLVM-exception,
BSD-1-Clause, and Unlicense combinations. This is a metadata inventory, not
legal advice or verification that every source file matches its crate manifest.

`results/advisory-audit.json` was produced by cargo-audit 0.22.1 using:

```sh
python3 scripts/run-advisory-audit.py > results/advisory-audit.json
```

That refresh operation accesses RustSec and is intentionally not part of routine
offline CI. The retained result binds the same lockfile to RustSec commit
`7c7ccac53056b87f69ac677f15ea2d9a98a6f8e2`, containing 1,173 advisories and
last updated on 2026-07-29. It reports zero known vulnerabilities, zero warnings,
and no accepted findings. This means only that this lockfile had no match in
that database snapshot; it is not evidence that dependencies are vulnerability
free.

`scripts/validate-supply-chain.py` regenerates the inventory offline and rejects
lockfile, checksum, package, source, version, license, or ordering drift. It also
requires complete advisory provenance, no unreviewed findings, and an audit no
older than 30 days. Any future finding must be fixed or explicitly documented
before the retained result and validator policy change.
