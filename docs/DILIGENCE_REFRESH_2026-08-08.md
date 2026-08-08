# Diligence Refresh: 2026-08-08

## Scope and method

This point-in-time refresh covered the exact and case-folded Telosieve name, GitHub repository names, crates.io, npm, PyPI, the `.com` registry, UK Companies House, web-indexed UK and WIPO trademark records, current prior-art references, the complete Git object history, Cargo dependency provenance, and RustSec advisories. Searches were performed on 2026-08-08. Search absence is not legal clearance, a reservation, or proof of novelty.

## Name and registry result

- General-web exact-name searches returned no credible software, company, or product collision. A noisy OCR match in an unrelated 1990 music-industry scan was not a relevant use.
- Authenticated GitHub repository search returned only the existing private `kabudu/telosieve` repository.
- The official crates.io API returned `404` with `crate telosieve does not exist`; npm and PyPI exact package endpoints returned `404`.
- Verisign RDAP returned `404` for `telosieve.com`; this is a transient registry observation, not a domain reservation.
- UK Companies House returned no company result for the exact name.
- Web searches constrained to the UK IPO and WIPO trademark services returned no indexed exact match. Their interfaces and coverage do not replace a professional clearance search.

Before commercial launch or investment in a registered mark, obtain legal review across relevant jurisdictions and Nice classes, recheck confusingly similar and phonetic marks, and decide whether to register the name and domains. The fallback naming exercise remains open if counsel identifies a material collision.

## Novelty and prior art result

The closest established ingredients remain desired-state reconciliation and self-healing, runtime models and verification, policy/admission systems, signed provenance, threshold or quorum evidence, reproducible builds, and fail-closed security controls. The current candidate hypothesis is narrower: a provenance-separated evaluator that may suspect desired-state authority, excludes suspected evidence from bounded planning, requires corroborated observations and explicit viability checks, and refuses when surviving evidence cannot distinguish an admissible transition.

No search establishes that combination as legally or academically novel. Existing [Novelty Diligence](NOVELTY.md) and [Prior-Art Matrix](PRIOR_ART_MATRIX.md) remain the claim boundary. Independent scholarly challenge, patent review, and freedom-to-operate advice are still absent.

## Repository and supply-chain result

`python3 scripts/audit-public-history.py` found no private-key marker, common AWS/GitHub/Slack token shape, owner-specific absolute path, risky credential filename, oversized historical blob, or unsafe current path within its documented object and byte bounds. Manual review also found no committed handoff directory or assessor correspondence. This pattern audit cannot prove that arbitrary historical text contains no sensitive information, so it must run again immediately before visibility changes and be supplemented by owner review.

The pre-migration Git graph contains the owner's personal author address. The owner has rejected disclosure. The repository must therefore complete the destructive, audited replacement defined in [History Privacy Migration](HISTORY_PRIVACY_MIGRATION.md), revoke the commit-bound rc.1 and rc.2 candidates, and freeze a successor from the sanitized graph before public opening.

The locked dependency graph contains 43 third-party packages. `cargo audit --json` version 0.22.1 checked the current lockfile against RustSec database commit `1237bbe09d2701e14e6593a630fbaf28928df712` and reported no vulnerability or warning. The result is time-bounded and does not establish dependency, compiler, registry, or build-system trust.

## Opening recommendation

Proceed with productisation and exact-candidate freeze while keeping the repository private. Public source opening is reasonable only after the conditions in [Public Opening Decision](PUBLIC_OPENING_DECISION.md) pass. Continue to prohibit production-readiness, general-safety, organizational-independence, market-fit, patentability, and legal-clearance claims.
