# Candidate Readiness Evidence

`evaluation/candidate-readiness.json` maps every gate in the private evaluation
product contract to concrete repository evidence and commands enforced by
`./scripts/ci-local.sh`. Run:

```sh
python3 scripts/validate-candidate-readiness.py
```

The pre-freeze state is deliberately asymmetric: seven implementation gates are
`locally-verified`; `signed-checksummed-reproducible-private-bundle` remains
`pending-freeze`. Source code can prove the deterministic bundle and signing
protocol, but it cannot truthfully claim that as-yet-unbuilt candidate bytes
have been signed. The release-candidate ceremony must build from a clean,
reviewed commit, match its reproducible-build digest, sign the exact bundle, and
emit a sidecar manifest that closes that final gate.

The validator requires the exact contract gate order, strict fields, sorted
unique evidence, existing non-symlink files, validation commands present in the
authoritative local CI script, the private/read-only policy boundary, and the
absence of hosted workflows. It also exercises missing, duplicate, prematurely
signed, weakened-authority, absent-evidence, reordered-gate, and
evidence-substitution refusals.

This evidence establishes internal readiness for candidate freeze. It is not an
operational signature, independent assessment, production promotion, public
release, or hosted-CI authorization.
