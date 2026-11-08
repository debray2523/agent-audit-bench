"""D6 -- Kill switch: suspend an agent or the whole workflow and revoke its
credentials in one operation (CERT-In: emergency-stop effectiveness)."""
from __future__ import annotations

from typing import Callable, Optional


class KillSwitch:
    name = "kill-switch-v1"

    def __init__(self) -> None:
        self.suspended_agents: set[str] = set()
        self.workflow_suspended = False
        self.on_suspend: list[Callable[[Optional[str]], int]] = []  # e.g. gateway.revoke
        self.events: list[dict] = []

    def suspend(self, agent_id: Optional[str] = None, at_step: int = -1) -> int:
        """Suspend one agent (or the workflow when agent_id is None). Returns credentials revoked."""
        if agent_id is None:
            self.workflow_suspended = True
        else:
            self.suspended_agents.add(agent_id)
        revoked = sum(cb(agent_id) for cb in self.on_suspend)
        self.events.append({"agent": agent_id or "*", "step": at_step, "revoked": revoked})
        return revoked

    def is_suspended(self, agent_id: str) -> bool:
        return self.workflow_suspended or agent_id in self.suspended_agents
