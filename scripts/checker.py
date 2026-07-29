#!/usr/bin/env python3
"""Independent M1 checker: no planner code or Rust model is shared."""

import json
import sys


def check(request: dict) -> dict:
    current = request["current"]
    transition = request["transition"]
    rules = request["rules"]
    authorized_deletions = set(request["authorized_deletions"])
    reasons = []

    if transition["before_digest"] != request["current_digest"]:
        reasons.append("transition is not bound to the current state")

    replicas = transition["after"]["replicas"]
    if len(replicas) != rules["replica_count"]:
        reasons.append("replica count invariant failed")

    values = list(replicas.values())
    if rules["require_consensus"] and (
        not values or any(candidate != values[0] for candidate in values[1:])
    ):
        reasons.append("replica consensus invariant failed")

    for key, expected in sorted(rules["required_keys"].items()):
        if any(replica.get(key) != expected for replica in values):
            reasons.append(f"required key invariant failed: {key}")

    current_values = list(current["replicas"].values())
    if not current_values:
        reasons.append("current state has no replicas")
    else:
        stable_keys = set(current_values[0])
        for replica in current_values[1:]:
            stable_keys.intersection_update(replica)
        deleted_keys = {
            key for key in stable_keys if any(key not in replica for replica in values)
        }
        for key in sorted(deleted_keys - authorized_deletions):
            reasons.append(f"stable key continuity failed: {key}")
        for key in sorted(authorized_deletions - deleted_keys):
            reasons.append(f"deletion authorization is not exact: {key}")

    return {
        "implementation": "telosieve-python-checker/v4",
        "safe": not reasons,
        "reasons": reasons,
    }


def main() -> int:
    for line in sys.stdin:
        request = json.loads(line)
        json.dump(check(request), sys.stdout, sort_keys=True, separators=(",", ":"))
        sys.stdout.write("\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
