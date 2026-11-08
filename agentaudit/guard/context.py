"""Per-session state the guard keeps for one agent working for one user."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from ..defences.judge import Provenance


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any]


@dataclass
class GuardContext:
    agent_id: str
    role: str
    user: str
    task: str = ""
    allowed_tools: Optional[set[str]] = None      # optional per-task scope, narrower than the role
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: float = field(default_factory=time.time)
    calls: int = 0
    delegations: int = 0
    revoked: bool = False
    evidence: Provenance = field(default_factory=Provenance)
    history: list[ToolCall] = field(default_factory=list)   # executed calls, for duplicate checks
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def memory_namespace(self) -> str:
        """Use this as the key prefix for any agent memory, so users never share it."""
        return f"user:{self.user}"
