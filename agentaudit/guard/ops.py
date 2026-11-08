"""Operational pieces: approvers (D4), persistent audit log (D5), kill switches (D6),
and secret injection."""
from __future__ import annotations

import hashlib
import json
import os
import threading
from typing import Any, Callable, Optional

from ..defences.audit import GENESIS, AuditLog
from .context import GuardContext, ToolCall


# ------------------------------------------------------------------ D4 approvers
class Approver:
    """approve(call, ctx) -> (approved, reason)."""

    name = "approver"

    def approve(self, call: ToolCall, ctx: GuardContext) -> tuple[bool, str]:
        raise NotImplementedError


class DenyAll(Approver):
    """Fail closed. The safe default when no reviewer is wired up yet."""

    name = "deny-all"

    def approve(self, call, ctx):
        return False, "no approver configured (fail closed)"


class ConsoleApprover(Approver):
    name = "console"

    def approve(self, call, ctx):
        print(f"\n[APPROVAL NEEDED] {ctx.agent_id} for {ctx.user}: {call.tool} {json.dumps(call.args, default=str)}")
        if ctx.task:
            print(f"Task: {ctx.task}")
        ok = input("Approve? [y/N] ").strip().lower() == "y"
        return ok, "approved at console" if ok else "rejected at console"


class CallbackApprover(Approver):
    """Connect any workflow: Slack, Teams, email, a ticketing system. `fn(call, ctx)`
    must return True/False (or (bool, reason)) and should block until decided or
    time out to False."""

    name = "callback"

    def __init__(self, fn: Callable[[ToolCall, GuardContext], Any]):
        self.fn = fn

    def approve(self, call, ctx):
        r = self.fn(call, ctx)
        if isinstance(r, tuple):
            return bool(r[0]), str(r[1])
        return bool(r), "approved by callback" if r else "rejected by callback"


# ------------------------------------------------------------------ D5 audit
class FileAuditLog(AuditLog):
    """Hash-chained, append-only JSONL file that survives restarts. Values listed by
    `redact()` (for example injected secrets) are masked before writing."""

    name = "file-audit-log"

    def __init__(self, path: str, redact: Callable[[], list[str]] = list):
        super().__init__()
        self.path = path
        self.redact = redact
        self._lock = threading.Lock()
        self._last = GENESIS
        self._seq = 0
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    if line.strip():
                        e = json.loads(line)
                        self._last, self._seq = e["hash"], e["seq"] + 1

    def _mask(self, obj: Any) -> Any:
        values = [v for v in self.redact() if v]
        s = json.dumps(obj, default=str)
        for v in values:
            s = s.replace(v, "***REDACTED***")
        return json.loads(s)

    def record(self, event: dict) -> None:
        with self._lock:
            body = {"seq": self._seq, **self._mask(event), "prev_hash": self._last}
            body["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
            with open(self.path, "a") as f:
                f.write(json.dumps(body, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self.entries.append(body)
            self._last, self._seq = body["hash"], self._seq + 1

    @staticmethod
    def verify_file(path: str) -> tuple[bool, int]:
        log = AuditLog()
        with open(path) as f:
            log.entries = [json.loads(line) for line in f if line.strip()]
        return log.verify()


# ------------------------------------------------------------------ D6 kill switch
class MemoryKillSwitch:
    """In-process switch. suspend(None) stops every agent."""

    name = "memory-kill-switch"

    def __init__(self) -> None:
        self._agents: set[str] = set()
        self._all = False

    def suspend(self, agent_id: Optional[str] = None) -> None:
        if agent_id is None:
            self._all = True
        else:
            self._agents.add(agent_id)

    def resume(self, agent_id: Optional[str] = None) -> None:
        if agent_id is None:
            self._all = False
            self._agents.clear()
        else:
            self._agents.discard(agent_id)

    def is_suspended(self, agent_id: str) -> bool:
        return self._all or agent_id in self._agents


class FileKillSwitch(MemoryKillSwitch):
    """Operator lever that works across processes and needs no code: if the flag
    file exists, agents are suspended. A file containing '*' (or empty) stops all
    agents; otherwise it lists agent ids, one per line.

        echo '*' > /var/run/agents.stop      # stop everything
        rm /var/run/agents.stop               # resume
    """

    name = "file-kill-switch"

    def __init__(self, path: str):
        super().__init__()
        self.path = path

    def suspend(self, agent_id: Optional[str] = None) -> None:
        with open(self.path, "a") as f:
            f.write(("*" if agent_id is None else agent_id) + "\n")

    def resume(self, agent_id: Optional[str] = None) -> None:
        if not os.path.exists(self.path):
            return
        if agent_id is None:
            os.remove(self.path)
            return
        with open(self.path) as f:
            lines = [ln.strip() for ln in f if ln.strip() and ln.strip() != agent_id]
        with open(self.path, "w") as f:
            f.write("\n".join(lines) + ("\n" if lines else ""))

    def is_suspended(self, agent_id: str) -> bool:
        if not os.path.exists(self.path):
            return False
        with open(self.path) as f:
            ids = {ln.strip() for ln in f if ln.strip()}
        return not ids or "*" in ids or agent_id in ids


# ------------------------------------------------------------------ secrets
class SecretProvider:
    """Supplies credentials to tool functions at execution time only. The model
    never sees them, the audit log masks them, and SecretEgress blocks them from
    leaving in arguments. Default source: environment variables of the same name."""

    def __init__(self, source: Optional[Callable[[str], Optional[str]]] = None):
        self.source = source or os.environ.get
        self._seen: set[str] = set()

    def get(self, name: str) -> str:
        v = self.source(name)
        if v is None:
            raise KeyError(f"secret '{name}' not available")
        self._seen.add(v)
        return v

    def values(self) -> list[str]:
        return list(self._seen)
