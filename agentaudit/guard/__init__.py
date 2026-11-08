"""Guard: the six control layers as a library you can put around your own agents.

See docs/integration-guide.md.
"""
from ..defences.isolation import InputIsolation
from .context import GuardContext, ToolCall
from .core import ActionBlocked, Guard, GuardSession, current_session
from .ops import (Approver, CallbackApprover, ConsoleApprover, DenyAll, FileAuditLog, FileKillSwitch,
                  MemoryKillSwitch, SecretProvider)
from .policy import HIGH, READ, TRUSTED, UNTRUSTED, WRITE, ArgLimit, Policy, ToolSpec
from .rules import (DuplicateAction, LLMJudge, Provenance, Rule, SecretEgress, SystemOfRecord, TaskScope,
                    default_rules)

__all__ = [
    "Guard", "GuardSession", "GuardContext", "ToolCall", "ActionBlocked", "current_session",
    "Policy", "ToolSpec", "ArgLimit", "READ", "WRITE", "HIGH", "TRUSTED", "UNTRUSTED",
    "Rule", "TaskScope", "Provenance", "SecretEgress", "DuplicateAction", "SystemOfRecord", "LLMJudge",
    "default_rules", "Approver", "DenyAll", "ConsoleApprover", "CallbackApprover",
    "FileAuditLog", "MemoryKillSwitch", "FileKillSwitch", "SecretProvider", "InputIsolation",
]
