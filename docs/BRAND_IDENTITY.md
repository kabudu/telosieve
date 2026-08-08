# Telosieve Brand Identity

Brand version: `2.0.0`

Status: approved as Telosieve's enduring product identity on 2026-08-08 and corrected on the same date to remove release-maturity coupling. This identity communicates the product's purpose and mechanism; it is not evidence of safety, independent validation, legal name clearance, production readiness, or current release authorization.

## Product maturity is not brand identity

Telosieve has one product identity across research, evaluation, release-candidate, and any future production-grade stages. The name, convergence-gate mark, brand version, purpose, principles, personality, tagline, colour, typography, and canonical product templates are maturity-neutral. They are designed for the intended durable product, not as temporary evaluation packaging.

Current maturity is a separate, replaceable messaging overlay. The overlay states release channel, read-only or actuation scope, support posture, evidence maturity, production authorization, and independent-validation status. Changing those facts must not require redrawing the mark, renaming the product, changing the brand version, or replacing the core tagline. The current overlay is `assets/brand/templates/evaluation-overlay.svg`; it is not part of any canonical logo.

## Product and audience

Telosieve is corroborated control for desired-state systems: it questions infrastructure instructions when authority evidence may be stale, compromised, or malicious. Its enduring users are platform reliability engineers, security engineers, infrastructure maintainers, researchers, and assurance practitioners. The product is intended to make authority-sensitive decisions inspectable and fail closed when the evidence is insufficient.

The product category phrase is **corroborated desired-state control**. Use familiar adjacent language such as reconciliation, policy evaluation, provenance, quorum evidence, and refusal. This is a positioning category, not a claim that an established market category or production capability already exists. Current release copy must state the exact implemented read-only evaluation boundary.

## Brand platform

- **Purpose:** make risky infrastructure instructions examinable before enforcement.
- **Promise:** corroborate authority before desired-state instructions take effect, with explicit refusal when the evidence is insufficient.
- **Principles:** evidence before confidence; refusal is a valid result; provenance is not truth; bounds are part of correctness; negative findings remain visible.
- **Personality:** precise, sceptical, calm, technically direct, and accountable.
- **Anti-traits:** heroic, sentient, militaristic, magical, alarmist, infallible, or self-congratulatory.
- **Tagline:** Question the instruction before enforcing it.

## Positioning and reasons to believe

Permanent short description: **Telosieve provides corroborated control for desired-state systems, questioning infrastructure instructions and refusing when surviving authority evidence cannot justify them.**

Permanent medium description: **Telosieve helps infrastructure and security teams question desired-state instructions when the authority behind them may be wrong. It separates goal, observation, and viability evidence, corroborates authenticated observations, retains versioned evidence, and treats refusal as a first-class outcome.**

Current maturity overlay: **The current `v0.2.0-rc.3` release is a project-controlled, read-only evaluation candidate. It has no production actuation authority, no production SLA, and still requires independent assessment.**

Reasons to believe must link to repository evidence:

- deterministic protocol and compatibility corpus;
- explicit refusal certificates and retained negative findings;
- mandatory observation-quorum verification in every supported capability;
- real disposable Kubernetes, OpenTofu, Redis, PostgreSQL, and HTTP/JSON qualifications;
- bounded local CI, reproducible candidate construction, and signed handoff verification;
- published threat, risk, soundness, and external-assessment boundaries.

## Claims matrix

Permanent identity terms include `corroborated control`, `desired-state systems`, `authority evidence`, `question before enforcing`, `fail closed`, `bounded`, `authenticated`, and `refusal`. Maturity-overlay terms include `evaluation software`, `read-only`, `project-controlled evidence`, `candidate`, and `requires independent validation`.

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
| A: convergence gate | three independent paths bend into a faceted sieve and one bounded result exits | bold silhouette, direct mechanism, strong monochrome and small-size behaviour | the waist can suggest an hourglass without the evidence paths | selected |
| B: sieve monogram | an angular S carries three coloured inputs toward one result | ownable letterform and strong wordmark pairing | reads as a route or cable and obscures provenance after entry | not selected |
| C: evidence loom | three ribbons weave through a two-bar lattice | dynamic and clearly communicates independent evidence | visually busy, weaker at favicon size, and can imply continuous data processing | not selected |

The internal review used a common light field and compared all three directions at equal size before their names and rationale were considered. Scoring dimensions were mechanism fidelity, silhouette, claim safety, category fit, distinctiveness, monochrome behaviour, and recognition at 16, 24, and 32 pixels. Direction A scored highest because the central gate remains identifiable without colour, the three sources remain distinct until the decision boundary, and the output is bounded without suggesting a shield, lock, tick, robot, or automatic remediation. This was one project-controlled review, not an external comprehension study or trademark opinion.

## Logo system

The selected mark shows three distinguishable evidence paths bending into a faceted convergence gate and one bounded result leaving it. The gate's asymmetric evidence paths prevent the central form being read in isolation as an hourglass; its negative slit expresses filtering rather than closure. The three paths remain visually distinct to avoid implying that corroboration erases provenance. The central shape is a sieve gate, not a shield. The square result is deliberately not a tick.

Canonical files:

- `telosieve-symbol.svg`: primary symbol;
- `telosieve-small.svg`: simplified 16 to 32 pixel form;
- `telosieve-favicon.svg`: dark-field 32 pixel browser and OS surface;
- `telosieve-wordmark.svg`: editable wordmark;
- `telosieve-horizontal.svg`: repository and documentation header;
- `telosieve-stacked.svg`: square and presentation layout;
- `telosieve-monochrome.svg`: one-colour print and terminal-adjacent use;
- `telosieve-reversed.svg`: dark-field symbol.

Clear space is at least one input-node diameter around every mark. Minimum sizes are 16 pixels for the small symbol, 32 pixels for the primary symbol, 180 pixels for the horizontal lockup, and 220 pixels for the stacked lockup. Use the small symbol below 32 pixels, the dark-field favicon on browser/OS surfaces, and the reversed dark-field avatar where the surrounding theme is unknown. Do not rotate, skew, add shadows, soften or round the gate facets, recolour individual paths outside the token system, fill the negative slit, convert the result square to a tick, place copy inside the clear space, or use the colour mark where monochrome or forced-colour output is required.

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
- Social and product: the maturity-neutral 1200 by 630 product card with product name, tagline, category, and principles.
- Release maturity: apply a separately versioned status overlay or adjacent copy; never modify the canonical lockup or product-card master to encode evaluation or production status.
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

Brand sources, tokens, and manifest use their own `2.0.0` version. Protocol and release-maturity changes do not silently change the brand. Material mark, palette, typography, promise, or category changes require a reviewed milestone, migration note, regenerated exports, new manifest, and archive of released assets. Security or cultural-symbol findings may trigger immediate withdrawal, followed by documented replacement rather than silent file substitution.

### Migration from the maturity-coupled label

The revoked `v0.2.0-rc.2` record preserves the earlier `1.0.0-evaluation` label and first aperture geometry as historical evidence. Brand `1.0.0` separated maturity from identity. Brand `2.0.0` now replaces the diagram-like aperture with the more distinctive faceted convergence gate while retaining the name, tagline, palette, typography, semantic states, and asset paths. Consumers must refresh every logo and raster export rather than mixing generations; use `evaluation-overlay.svg` only when current maturity disclosure is required. Do not infer a production promotion from either identity correction.

## Remaining human gates

Formal trademark and cultural-symbol review, a multi-participant non-leading comprehension study, print proofing, and cross-platform optical comparison remain external launch evidence. They do not make the product identity provisional, but they block claims of legal clearance, measured comprehension, or a commercially registered mark and may require a future governed correction if they uncover a material issue.
