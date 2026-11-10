#!/usr/bin/env python3
"""
Tool definition lock (TRIAD control I, test TC-06).

Hashes every MCP tool definition (name, description, input schema) so a change
made outside the approved pipeline is caught before the agent ever sees it.

    python lab/tool_lock.py generate   # after an approved change: writes tools.lock
    python lab/tool_lock.py verify     # in CI and before deploy: fails on any drift
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFS = HERE / "tools" / "tool_definitions.json"
LOCK = HERE / "tools" / "tools.lock"


def _digest(tool: dict) -> str:
    canonical = json.dumps(tool, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def hashes(defs_path: Path) -> dict[str, str]:
    tools = json.loads(defs_path.read_text())["tools"]
    return {t["name"]: _digest(t) for t in tools}


def generate(defs_path: Path = DEFS, lock_path: Path = LOCK) -> None:
    lock_path.write_text(json.dumps(hashes(defs_path), indent=2, sort_keys=True) + "\n")
    print(f"Locked {len(hashes(defs_path))} tool definitions to {lock_path.name}")


def verify(defs_path: Path = DEFS, lock_path: Path = LOCK) -> tuple[bool, dict]:
    expected = json.loads(lock_path.read_text())
    actual = hashes(defs_path)
    detail = {
        "changed": sorted(n for n in actual if n in expected and actual[n] != expected[n]),
        "added": sorted(n for n in actual if n not in expected),
        "removed": sorted(n for n in expected if n not in actual),
    }
    return not any(detail.values()), detail


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "verify"
    if cmd == "generate":
        generate()
    else:
        ok, detail = verify()
        print("Tool definitions match the lock." if ok else f"Tool definition drift detected: {detail}")
        sys.exit(0 if ok else 1)
