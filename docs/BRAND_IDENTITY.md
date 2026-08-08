# Telosieve Brand Identity

Brand version: `1.0.0-evaluation`

Status: approved for the open-source evaluation product on 2026-08-08. This identity communicates product scope; it is not evidence of safety, independent validation, legal name clearance, or production readiness.

## Product and audience

Telosieve is fail-closed evaluation software for questioning desired-state instructions when authority evidence may be stale, compromised, or malicious. Its primary users are platform reliability engineers, security engineers, infrastructure maintainers, researchers, and independent assessors. The first buyer-like audience is an engineering or security leader evaluating whether disputed-authority controls merit further testing, not purchasing an autonomous production repair service.

The category phrase is **corroborated desired-state evaluation**. Use familiar adjacent language such as reconciliation, policy evaluation, provenance, quorum evidence, and refusal. Do not invent a category that implies an established market.

## Brand platform

- **Purpose:** make risky infrastructure instructions examinable before enforcement.
- **Promise:** produce a bounded, inspectable decision or an explicit refusal without target mutation in supported evaluation modes.
- **Principles:** evidence before confidence; refusal is a valid result; provenance is not truth; bounds are part of correctness; negative findings remain visible.
- **Personality:** precise, sceptical, calm, technically direct, and accountable.
- **Anti-traits:** heroic, sentient, militaristic, magical, alarmist, infallible, or self-congratulatory.
- **Tagline:** Question the instruction before enforcing it.

## Positioning and reasons to believe

Short description: **Telosieve is evaluation software that corroborates bounded observations, tests explicit authority-fault hypotheses, and refuses when surviving evidence cannot justify a read-only desired-state decision.**

Medium description: **Telosieve helps infrastructure and security teams evaluate desired-state instructions when the authority behind them may be wrong. It separates goal, observation, and viability evidence; requires authenticated corroboration in supported modes; emits versioned evidence; and fails closed without target mutation. Its current results are project-controlled evaluation evidence and require independent assessment.**

Reasons to believe must link to repository evidence:

- deterministic protocol and compatibility corpus;
- explicit refusal certificates and retained negative findings;
- mandatory observation-quorum verification in every supported capability;
- real disposable Kubernetes, OpenTofu, Redis, PostgreSQL, and HTTP/JSON qualifications;
- bounded local CI, reproducible candidate construction, and signed handoff verification;
- published threat, risk, soundness, and external-assessment boundaries.

## Claims matrix

Preferred terms include `evaluation software`, `read-only`, `fail closed`, `corroborated`, `bounded`, `authenticated`, `project-controlled evidence`, `candidate`, `refusal`, and `requires independent validation`.

Do not claim `safe`, `secure by proof`, `production-ready`, `Byzantine resilient`, `autonomous repair`, `prevents AI escape`, `eliminates compromise`, `zero trust`, `novel`, `patented`, `independently verified`, or `enterprise-grade` unless a later exact gate establishes the specific statement. Never use a shield, tick, lock, immune-system metaphor, or green-only state to imply guaranteed protection.

Context-specific voice:

- **Developer:** state the exact interface, schema, command, bound, and refusal behavior.
- **Research:** separate hypothesis, measurement, negative result, limitation, and independent-reproduction status.
- **Security:** lead with affected boundary, exploitability, containment, and verified remediation; avoid drama.
- **Leadership:** state the operational problem, evaluation boundary, evidence, cost, and unresolved decision.
- **Incident:** use short factual updates with time, scope, current containment, next verification, and explicit unknowns.

## Direction study and selection

Three genuinely different directions are retained under `assets/brand/concepts/`:

| Direction | Mechanism | Strength | Risk | Result |
|---|---|---|---|---|
| A: evidence aperture | three evidence paths cross a visible evaluation boundary and become one result | directly represents provenance separation, corroboration, and a bounded output | may be mistaken for a generic data pipeline without copy | selected |
| B: ledger weave | offset blocks form an auditable chain | communicates retained history and structured evidence | overweights ledger/storage and performs poorly at small size | not selected |
| C: bounded horizon | observations terminate at a visible decision line | communicates a limit and refusal boundary | can resemble analytics or navigation marks | not selected |

The internal review hid direction names, randomized order, and used the same neutral one-sentence prompt for each: “What kind of product and behavior does this mark suggest?” Scoring dimensions were mechanism fidelity, claim safety, category fit, distinctiveness, monochrome behavior, and recognition at 16, 24, and 32 pixels. Direction A scored highest on mechanism fidelity and small-size recognition without suggesting a shield, lock, robot, or automatic remediation. This was one project-controlled review, not an external comprehension study or trademark opinion.

## Logo system

The selected mark shows three distinguishable evidence paths entering an open aperture and one bounded result leaving it. The three paths remain visually distinct to avoid implying that corroboration erases provenance. The central shape is an aperture, not a shield. The square result is deliberately not a tick.

Canonical files:

- `telosieve-symbol.svg`: primary symbol;
- `telosieve-small.svg`: simplified 16 to 32 pixel form;
- `telosieve-wordmark.svg`: editable wordmark;
- `telosieve-horizontal.svg`: repository and documentation header;
- `telosieve-stacked.svg`: square and presentation layout;
- `telosieve-monochrome.svg`: one-colour print and terminal-adjacent use;
- `telosieve-reversed.svg`: dark-field symbol.

Clear space is at least one input-node diameter around every mark. Minimum sizes are 16 pixels for the small symbol, 32 pixels for the primary symbol, 180 pixels for the horizontal lockup, and 220 pixels for the stacked lockup. Use the small symbol below 32 pixels. Do not rotate, skew, add shadows, recolour individual paths outside the token system, close the aperture, convert the result square to a tick, place copy inside the clear space, or use the colour mark where monochrome or forced-colour output is required.

## Colour and state

Light surfaces use ink `#101820`, paper `#F7FAFC`, and surface `#FFFFFF`. Evidence paths use cyan `#007C91`, amber `#8A4B08`, and violet `#6B4BB6`. Verified evaluation output uses teal `#006B5F`; refusal uses red `#B42318`; unknown uses slate `#475467`. Dark surfaces use the lighter counterparts declared in the token file.

Text/background pairs enforced by the asset builder meet WCAG contrast thresholds: body text is at least 4.5:1 and primary ink/paper pairs are at least 7:1. Colour never carries state alone. Refusal uses a cross and label, unsupported uses a dashed line and label, uncertainty uses a question mark and label, and verified output uses a square and label. Forced-colour tokens map to system colours.

## Typography

Use Inter when separately installed, followed by the declared system sans-serif stack. Use the system monospace stack for commands, hashes, schemas, and evidence. No font is embedded or redistributed. Headings are sentence case, labels are concise, and long identifiers remain selectable text. Do not use condensed security-display faces, all-caps paragraphs, or decorative code fonts.

## Icons, diagrams, charts, and imagery

Icons use a 24-pixel grid, two-pixel stroke, rounded joins, and both shape and text labels for state. The canonical diagram key distinguishes circular authorities, coloured evidence paths, outlined verification boundaries, bounded process boxes, square results, and crossed refusals. Integrations stay outside the core verification boundary in diagrams.

Charts must display accepted, refused, unsupported, timed-out, excluded, and missing rows. Always show denominators, measurement bounds, uncertainty, and whether evidence is independent. Never collapse refusals into failures or omit negative results for visual simplicity.

Illustration should use abstract evidence, boundaries, and infrastructure topology. Do not use humanoid agents, surveillance imagery, weapons, shields, padlocks, brains, or disaster photography. Motion is optional, functional, under 200 milliseconds for interface state, and disabled under `prefers-reduced-motion`; no pulsing danger decoration or autonomous “thinking” animation is permitted.

## Channels and templates

- Repository: horizontal SVG above the concise product boundary.
- CLI and terminal: plain-text `Telosieve`, explicit result labels, and `NO_COLOR` compatibility; never rely on the symbol.
- Release: curated `<Product> vX.Y.Z: <theme>` title, one-sentence outcome, three to five highlights, installation/verification path, and limitations.
- Social: the 1200 by 630 evaluation card with product name, tagline, read-only category, and independent-validation boundary.
- Presentations and documents: stacked or horizontal mark, diagram key, chart key, and evidence links.
- Incident communication: monochrome wordmark or plain text, timestamped facts, affected versions, containment, next update, and unknowns.

## Assets, provenance, and reproduction

`assets/brand/BRAND_ASSET_MANIFEST.json` records the source and export SHA-256, byte size, dimensions, colour space, licence, provenance, allowed use, and export command. SVGs contain accessible titles and descriptions, no scripts, remote resources, unsafe links, metadata secrets, or embedded rasters. Sources and templates are Apache-2.0; no third-party icon or stock asset is included. Optional Inter use does not redistribute the font.

Run:

```sh
python3 scripts/build-brand-assets.py --check
python3 scripts/validate-brand.py
```

The builder renders every PNG twice and requires byte identity, exact dimensions, committed-byte equality, source/manifest digest agreement, and contrast thresholds. The current retained export qualification is macOS/aarch64 using the system SVG renderer normalized by ImageMagick. SVG structure is portable, but byte-identical raster reproduction across operating systems and font engines is not claimed.

## Governance

The repository owner is product and brand owner. Engineering owns deterministic assets and integration consistency; security owns prohibited protection claims; research owns evidence and novelty wording; accessibility owns contrast and non-colour semantics; legal clearance remains external. A future contributor may fill more than one role, but every role must be explicitly reviewed at a release gate.

Brand sources, tokens, and manifest use their own `1.0.0-evaluation` version. Protocol version changes do not silently change the brand. Material mark, palette, typography, claim, or category changes require a reviewed milestone, migration note, regenerated exports, new manifest, and archive of released assets. Security or cultural-symbol findings may trigger immediate withdrawal, followed by documented replacement rather than silent file substitution.

## Remaining human gates

Formal trademark and cultural-symbol review, a multi-participant non-leading comprehension study, print proofing, and cross-platform optical comparison remain external launch evidence. They do not block source publication of this clearly labelled evaluation identity, but they block claims of legal clearance, measured comprehension, or a commercially registered mark.
