#!/bin/sh
set -eu

repository="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repository"

python3 scripts/validate-assessor-manifest.py >&2
source_commit="$(python3 -c 'import json; print(json.load(open("assessment/manifest.json"))["source_commit"])')"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/telosieve-assessor.XXXXXX")"
checkout="$temporary/checkout"
cleanup() {
    rm -rf "$temporary"
}
trap cleanup EXIT HUP INT TERM

git clone --quiet --no-hardlinks "$repository" "$checkout"
git -C "$checkout" -c advice.detachedHead=false checkout --quiet "$source_commit"
if [ -n "$(git -C "$checkout" status --porcelain)" ]; then
    echo "assessor-handoff: clean checkout unexpectedly dirty" >&2
    exit 1
fi
if [ -d "$checkout/.github/workflows" ]; then
    echo "assessor-handoff: hosted CI is forbidden for this private repository" >&2
    exit 1
fi

(
    cd "$checkout"
    ./scripts/ci-local.sh
    ./scripts/run-incident-drills.sh > "$temporary/incident-drills.json"
    cmp results/incident-drills.json "$temporary/incident-drills.json"
    ./scripts/run-parser-corpora.sh > "$temporary/parser-corpora.json"
    cmp results/parser-corpora.json "$temporary/parser-corpora.json"
) >&2

printf '{\n'
printf '  "schema_version":"telosieve.assessor-verification/v1",\n'
printf '  "source_commit":"%s",\n' "$source_commit"
printf '  "checkout":"fresh-local-clone-detached-clean",\n'
printf '  "network_dependency_mode":"locked-offline",\n'
printf '  "production_credentials_required":false,\n'
printf '  "hosted_ci_used":false,\n'
printf '  "artifact_digests_verified":9,\n'
printf '  "commands_passed":3,\n'
printf '  "status":"passed"\n'
printf '}\n'
echo "assessor-handoff: passed source=$source_commit" >&2
