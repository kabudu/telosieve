#!/usr/bin/env python3
"""Independent M1 checker: no planner code or Rust model is shared."""

import json
import sys


def main() -> int:
    request = json.load(sys.stdin)
    current = request["current"]
    transition = request["transition"]
    rules = request["rules"]
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

    if not current["replicas"]:
        reasons.append("current state has no replicas")

    json.dump(
        {
            "implementation": "telosieve-python-checker/v1",
            "safe": not reasons,
            "reasons": reasons,
        },
        sys.stdout,
        sort_keys=True,
        separators=(",", ":"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
