#!/usr/bin/env python3
"""
Separation of duties and ownership check for agent identities (TRIAD TC-11).

Fails if any agent holds a conflicting pair of roles, or has no named owner.

    python lab/sod_check.py            # in CI whenever role assignments change
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ASSIGNMENTS = HERE / "identity" / "role_assignments.json"
RULES = HERE / "identity" / "sod_rules.json"


def check(assignments: dict, rules: dict) -> list[dict]:
    issues = []
    for agent, spec in assignments["agents"].items():
        for field in rules.get("required_fields", []):
            if not spec.get(field):
                issues.append({"agent": agent, "rule": f"missing-{field}", "reason": f"Agent has no {field}"})
        held = set(spec.get("roles", []))
        for rule in rules["conflicts"]:
            if set(rule["roles"]) <= held:
                issues.append({"agent": agent, "rule": rule["id"], "reason": rule["reason"]})
    return issues


def load(path: Path) -> dict:
    return json.loads(path.read_text())


if __name__ == "__main__":
    found = check(load(ASSIGNMENTS), load(RULES))
    if found:
        for i in found:
            print(f"{i['rule']}: {i['agent']}: {i['reason']}")
        sys.exit(1)
    print("No separation of duties conflicts; every agent has an owner.")
