#!/usr/bin/env python3
"""Validate the bounded evaluation-mode adversarial coverage contract."""

from __future__ import annotations

import copy
import json
import os
import re
import stat
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "evaluation/adversarial-coverage.json"
RESULT = ROOT / "results/adversarial-coverage-validation.json"
MAX_REGISTRY_BYTES = 256 * 1024
MAX_THREAT_CLASSES = 64
MAX_EVIDENCE_PER_CELL = 4
MAX_TEXT_BYTES = 4 * 1024 * 1024
ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
ALLOWED_EVIDENCE_ROOTS = {"src", "tests", "scripts", "deploy", "results"}
EXPECTED_TOP_LEVEL = {"schema_version", "authority_boundary", "modes", "limits", "threat_classes"}
EXPECTED_CLASS = {"id", "title", "priority", "applicable_modes", "coverage"}
EXPECTED_EVIDENCE = {"path", "anchor"}
EXPECTED_THREAT_IDS = {
    "authority-evidence-substitution",
    "compromised-consistent-producer",
    "credential-scope-abuse",
    "incoherent-or-racing-observation",
    "malformed-ambiguous-or-oversized-input",
    "mutation-attempt",
    "output-alias-or-partial-evidence",
    "replay-rollback-or-equivocation",
    "sustained-adversarial-load",
    "transport-timeout-or-outage",
}
EXPECTED_RESULT = {
    "schema_version": "telosieve.adversarial-coverage-validation/v1",
    "modes": 3,
    "threat_classes": 10,
    "required_classes": 9,
    "covered_cells": 22,
    "deferred_cells": 3,
    "not_applicable_cells": 5,
    "adversarial_refusals": 11,
    "status": "passed-with-registered-research-gaps",
}


def fail(message: str) -> None:
    raise ValueError(message)


def strict_json(data: bytes, label: str) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(data, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not strict UTF-8 JSON: {error}")


def bounded_text(path: Path, anchor: str) -> None:
    lexical = path
    candidate = lexical
    while candidate != ROOT:
        if candidate.is_symlink():
            fail("evidence path contains a symlink")
        candidate = candidate.parent
    try:
        resolved = lexical.resolve(strict=True)
        relative = resolved.relative_to(ROOT)
    except ValueError:
        fail("evidence path escapes the repository")
    if not relative.parts or relative.parts[0] not in ALLOWED_EVIDENCE_ROOTS:
        fail("evidence path is outside an executable or retained-evidence root")
    descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_TEXT_BYTES:
            fail("evidence file is not regular or exceeds the validation bound")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(MAX_TEXT_BYTES + 1)
        if len(data) > MAX_TEXT_BYTES:
            fail("evidence file exceeded its bound while reading")
    finally:
        os.close(descriptor)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        fail("evidence file is not UTF-8 text")
    if anchor not in text:
        fail("evidence anchor is absent")


def validate(registry: object, *, inspect_files: bool = True) -> dict[str, int]:
    if not isinstance(registry, dict) or set(registry) != EXPECTED_TOP_LEVEL:
        fail("registry fields do not exactly match the v1 schema")
    if registry["schema_version"] != "telosieve.adversarial-coverage/v1":
        fail("registry schema is unsupported")
    if registry["authority_boundary"] != "read-only-no-target-mutation":
        fail("registry weakens the evaluation authority boundary")
    modes = registry["modes"]
    if modes != ["kubernetes-shadow", "kubernetes-live", "opentofu-plan"]:
        fail("registry modes must exactly match the ordered evaluation contract")
    if registry["limits"] != {
        "maximum_threat_classes": MAX_THREAT_CLASSES,
        "maximum_evidence_per_cell": MAX_EVIDENCE_PER_CELL,
        "maximum_registry_bytes": MAX_REGISTRY_BYTES,
    }:
        fail("registry resource limits changed")
    classes = registry["threat_classes"]
    if not isinstance(classes, list) or not 1 <= len(classes) <= MAX_THREAT_CLASSES:
        fail("threat-class count is invalid")
    ids: set[str] = set()
    counts = {"required": 0, "covered": 0, "deferred": 0, "not-applicable": 0}
    for threat in classes:
        if not isinstance(threat, dict) or set(threat) != EXPECTED_CLASS:
            fail("threat-class fields are invalid")
        threat_id = threat["id"]
        if not isinstance(threat_id, str) or not ID.fullmatch(threat_id) or threat_id in ids:
            fail("threat-class id is invalid or duplicated")
        ids.add(threat_id)
        if not isinstance(threat["title"], str) or not 8 <= len(threat["title"]) <= 200:
            fail("threat-class title is invalid")
        priority = threat["priority"]
        if priority not in {"required", "research-gap"}:
            fail("threat-class priority is invalid")
        counts["required"] += priority == "required"
        applicable = threat["applicable_modes"]
        if (
            not isinstance(applicable, list) or not applicable
            or applicable != [mode for mode in modes if mode in applicable]
            or len(applicable) != len(set(applicable))
        ):
            fail("applicable modes are invalid, duplicated, or out of order")
        coverage = threat["coverage"]
        if not isinstance(coverage, dict) or list(coverage) != modes:
            fail("coverage must explicitly and exactly enumerate every ordered mode")
        for mode in modes:
            cell = coverage[mode]
            if not isinstance(cell, dict) or "status" not in cell:
                fail("coverage cell is invalid")
            status = cell["status"]
            if status == "covered":
                if set(cell) != {"status", "evidence"} or mode not in applicable:
                    fail("covered cell is malformed or not applicable")
                evidence = cell["evidence"]
                if not isinstance(evidence, list) or not 1 <= len(evidence) <= MAX_EVIDENCE_PER_CELL:
                    fail("covered cell evidence count is invalid")
                seen: set[tuple[str, str]] = set()
                for item in evidence:
                    if not isinstance(item, dict) or set(item) != EXPECTED_EVIDENCE:
                        fail("evidence reference fields are invalid")
                    path, anchor = item["path"], item["anchor"]
                    if (
                        not isinstance(path, str) or not isinstance(anchor, str)
                        or not 1 <= len(path) <= 256 or not 3 <= len(anchor) <= 200
                        or Path(path).is_absolute() or ".." in Path(path).parts
                        or (path, anchor) in seen
                    ):
                        fail("evidence reference is unsafe or duplicated")
                    seen.add((path, anchor))
                    if inspect_files:
                        bounded_text(ROOT / path, anchor)
                counts["covered"] += 1
            elif status in {"deferred", "not-applicable"}:
                if set(cell) != {"status", "reason"}:
                    fail("non-covered cell fields are invalid")
                reason = cell["reason"]
                if not isinstance(reason, str) or not 16 <= len(reason) <= 300:
                    fail("non-covered cell reason is invalid")
                if status == "deferred" and (priority != "research-gap" or mode not in applicable):
                    fail("only applicable research gaps may be deferred")
                if status == "not-applicable" and mode in applicable:
                    fail("an applicable mode cannot be marked not-applicable")
                counts[status] += 1
            else:
                fail("coverage status is unsupported")
            if priority == "required" and mode in applicable and status != "covered":
                fail("required applicable coverage is not executable")
    if ids != EXPECTED_THREAT_IDS:
        fail("registered threat-class inventory changed")
    return counts


def adversarial_refusals(registry: dict[str, object]) -> int:
    mutations: list[dict[str, object]] = []
    missing = copy.deepcopy(registry); missing["threat_classes"] = missing["threat_classes"][:-1]; mutations.append(missing)
    duplicate = copy.deepcopy(registry); duplicate["threat_classes"][1]["id"] = duplicate["threat_classes"][0]["id"]; mutations.append(duplicate)
    unknown_mode = copy.deepcopy(registry); unknown_mode["modes"][0] = "unknown-mode"; mutations.append(unknown_mode)
    missing_cell = copy.deepcopy(registry); del missing_cell["threat_classes"][0]["coverage"]["opentofu-plan"]; mutations.append(missing_cell)
    deferred_required = copy.deepcopy(registry); deferred_required["threat_classes"][0]["coverage"]["kubernetes-shadow"] = {"status": "deferred", "reason": "A required cell cannot be silently deferred."}; mutations.append(deferred_required)
    nonexistent = copy.deepcopy(registry); nonexistent["threat_classes"][0]["coverage"]["kubernetes-shadow"]["evidence"][0]["path"] = "tests/not-real.rs"; mutations.append(nonexistent)
    traversal = copy.deepcopy(registry); traversal["threat_classes"][0]["coverage"]["kubernetes-shadow"]["evidence"][0]["path"] = "tests/../Cargo.toml"; mutations.append(traversal)
    absent_anchor = copy.deepcopy(registry); absent_anchor["threat_classes"][0]["coverage"]["kubernetes-shadow"]["evidence"][0]["anchor"] = "not-an-actual-evidence-anchor"; mutations.append(absent_anchor)
    excess_evidence = copy.deepcopy(registry); cell = excess_evidence["threat_classes"][0]["coverage"]["kubernetes-shadow"]; cell["evidence"] = cell["evidence"] * (MAX_EVIDENCE_PER_CELL + 1); mutations.append(excess_evidence)
    self_reference = copy.deepcopy(registry); self_reference["threat_classes"][0]["coverage"]["kubernetes-shadow"]["evidence"][0]["path"] = "evaluation/adversarial-coverage.json"; mutations.append(self_reference)
    weakened = copy.deepcopy(registry); weakened["authority_boundary"] = "read-write"; mutations.append(weakened)
    for mutation in mutations:
        try:
            validate(mutation)
        except (OSError, ValueError):
            continue
        fail("adversarial registry mutation was accepted")
    return len(mutations)


def main() -> int:
    try:
        data = REGISTRY.read_bytes()
        if len(data) > MAX_REGISTRY_BYTES:
            fail("registry exceeds its byte bound")
        registry = strict_json(data, "coverage registry")
        counts = validate(registry)
        refusals = adversarial_refusals(registry)
        result = {
            "schema_version": "telosieve.adversarial-coverage-validation/v1",
            "modes": len(registry["modes"]),
            "threat_classes": len(registry["threat_classes"]),
            "required_classes": counts["required"],
            "covered_cells": counts["covered"],
            "deferred_cells": counts["deferred"],
            "not_applicable_cells": counts["not-applicable"],
            "adversarial_refusals": refusals,
            "status": "passed-with-registered-research-gaps" if counts["deferred"] else "passed",
        }
        retained = strict_json(RESULT.read_bytes(), "retained coverage result")
        if result != EXPECTED_RESULT or retained != EXPECTED_RESULT:
            fail("computed or retained coverage result drifted")
    except (OSError, ValueError) as error:
        print(f"adversarial-coverage: {error}", file=sys.stderr)
        return 1
    print(
        "adversarial-coverage: passed "
        f"modes={result['modes']} classes={result['threat_classes']} "
        f"covered={result['covered_cells']} deferred={result['deferred_cells']} "
        f"not_applicable={result['not_applicable_cells']} refusals={refusals}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
