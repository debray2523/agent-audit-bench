"""D5 -- Tamper-evident action log.

Each entry carries the SHA-256 of the previous entry, so editing or deleting a
record breaks the chain. The log captures what the CERT-In guidelines ask
auditors to reconstruct: requests, delegations, permissions used, decisions,
tools invoked, and the external actions that followed.

When D5 is off, MinimalLog stands in for typical ad-hoc application logging:
it records only that a tool ran.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS = "0" * 64


class AuditLog:
    name = "hash-chained-audit-log-v1"

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def record(self, event: dict[str, Any]) -> None:
        prev = self.entries[-1]["hash"] if self.entries else GENESIS
        body = {"seq": len(self.entries), **event, "prev_hash": prev}
        body["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
        self.entries.append(body)

    def verify(self) -> tuple[bool, int]:
        """Return (ok, index of first bad entry or -1)."""
        prev = GENESIS
        for i, e in enumerate(self.entries):
            body = {k: v for k, v in e.items() if k != "hash"}
            if body.get("prev_hash") != prev:
                return False, i
            h = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
            if h != e["hash"]:
                return False, i
            prev = e["hash"]
        return True, -1

    def to_jsonl(self, path: str) -> None:
        with open(path, "w") as f:
            for e in self.entries:
                f.write(json.dumps(e, default=str) + "\n")


class MinimalLog:
    name = "minimal-app-log"

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def record(self, event: dict[str, Any]) -> None:
        if event.get("event") == "executed":
            self.entries.append({"event": "executed", "tool": event.get("tool")})

    def verify(self) -> tuple[bool, int]:
        return False, -1  # no integrity protection

    def to_jsonl(self, path: str) -> None:
        with open(path, "w") as f:
            for e in self.entries:
                f.write(json.dumps(e) + "\n")


def reconstructable(log, ground_truth: list[dict]) -> bool:
    """True if every executed side effect can be traced to agent, tool, args and
    decision trail in an intact log."""
    ok, _ = log.verify()
    if not ok:
        return False
    executed = [e for e in log.entries if e.get("event") == "executed"]
    if len(executed) != len(ground_truth):
        return False
    for e, g in zip(executed, ground_truth):
        if e.get("agent") != g["agent"] or e.get("tool") != g["tool"] or e.get("args") != g["args"]:
            return False
        if "decisions" not in e:
            return False
    return True
