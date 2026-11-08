"""The control pipeline every proposed action passes through.

Order: kill switch -> tool gateway -> independent judge -> human approval ->
execute -> audit log -> input isolation of the result.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Optional

from .defences import (AuditLog, InputIsolation, KillSwitch, LLMJudge, MinimalLog, OracleApprover,
                       Provenance, RuleJudge, ToolGateway)
from .defences.gateway import GatewayPolicy
from .env import HIGH, TOOLS, UNTRUSTED, World, coerce_args, execute
from .types import Action, Context, Decision, RunTrace


@dataclass(frozen=True)
class DefenceConfig:
    name: str
    isolation: bool = False   # D1
    gateway: bool = False     # D2
    judge: bool = False       # D3
    human: bool = False       # D4
    audit: bool = False       # D5
    killswitch: bool = False  # D6

    def layers(self) -> list[str]:
        return [n for n, on in [("D1", self.isolation), ("D2", self.gateway), ("D3", self.judge),
                                ("D4", self.human), ("D5", self.audit), ("D6", self.killswitch)] if on]


_NONE = DefenceConfig("none")
PRESETS: dict[str, DefenceConfig] = {
    "none": _NONE,
    "D1-isolation": replace(_NONE, name="D1-isolation", isolation=True),
    "D2-gateway": replace(_NONE, name="D2-gateway", gateway=True),
    "D3-judge": replace(_NONE, name="D3-judge", judge=True),
    "D4-human": replace(_NONE, name="D4-human", human=True),
    "D5-audit": replace(_NONE, name="D5-audit", audit=True),
    "D6-killswitch": replace(_NONE, name="D6-killswitch", killswitch=True),
    "all": DefenceConfig("all", True, True, True, True, True, True),
}


class ControlPipeline:
    def __init__(self, world: World, config: DefenceConfig, judge=None, approver=None,
                 policy: Optional[GatewayPolicy] = None):
        self.world = world
        self.config = config
        self.isolation = InputIsolation() if config.isolation else None
        self.gateway = ToolGateway(policy) if config.gateway else None
        self.judge = (judge or RuleJudge()) if config.judge else None
        self.approver = (approver or OracleApprover()) if config.human else None
        self.log = AuditLog() if config.audit else MinimalLog()
        self.killswitch = KillSwitch() if config.killswitch else None
        if self.killswitch and self.gateway:
            self.killswitch.on_suspend.append(self.gateway.revoke)
        self.provenance: dict[str, Provenance] = {}
        self.step_counter = 0
        self.blocks: list[dict] = []
        self.quarantined: list[str] = []

    # ------------------------------------------------------------------ session
    def next_step(self) -> int:
        self.step_counter += 1
        return self.step_counter

    def start_session(self, ctx: Context) -> None:
        self.provenance[ctx.session_id] = Provenance(trusted=[ctx.task.instruction])
        event = {"event": "session_start", "agent": ctx.agent_id, "session": ctx.session_id,
                 "user": ctx.session_user, "role": ctx.role, "task": ctx.task.id, "step": self.step_counter}
        if self.gateway:
            cred = self.gateway.issue(ctx)
            event["credential"] = cred.token
            event["scopes"] = sorted(cred.scopes)
        self.log.record(event)

    def operator_suspend(self, agent_id: Optional[str], at_step: int) -> bool:
        """An operator pulls the kill switch. Without D6 there is no mechanism to do so."""
        if not self.killswitch:
            return False
        revoked = self.killswitch.suspend(agent_id, at_step)
        self.log.record({"event": "suspended", "agent": agent_id or "*", "step": at_step,
                         "credentials_revoked": revoked})
        return True

    # ------------------------------------------------------------------ actions
    def _block(self, layer: str, reason: str, action: Action, ctx: Context) -> tuple[Decision, str]:
        self.log.record({"event": "blocked", "agent": ctx.agent_id, "session": ctx.session_id,
                         "step": ctx.step, "tool": action.tool, "args": action.args,
                         "layer": layer, "reason": reason})
        self.blocks.append({"layer": layer, "reason": reason, "tool": action.tool,
                            "session": ctx.session_id, "step": ctx.step})
        return Decision(False, layer, reason), f"BLOCKED by {layer}: {reason}"

    def handle(self, action: Action, ctx: Context, trace: RunTrace) -> tuple[Decision, str]:
        self.log.record({"event": "proposed", "agent": ctx.agent_id, "session": ctx.session_id,
                         "step": ctx.step, "tool": action.tool, "args": action.args,
                         "rationale": action.rationale})
        approvals: list[str] = []

        if self.killswitch and self.killswitch.is_suspended(ctx.agent_id):
            return self._block("D6-killswitch", "agent suspended by operator", action, ctx)

        tool = TOOLS.get(action.tool)
        if tool is None:
            return self._block("runtime", f"unknown tool '{action.tool}'", action, ctx)

        if self.gateway:
            ok, reason, args = self.gateway.check(action, tool, ctx)
            if not ok:
                return self._block("D2-gateway", reason, action, ctx)
            approvals.append("D2-gateway")
        else:
            try:
                args = coerce_args(tool, action.args)
            except (KeyError, ValueError) as e:
                return self._block("runtime", f"invalid arguments: {e}", action, ctx)

        prov = self.provenance[ctx.session_id]
        if self.judge:
            ok, reason = self.judge.review(tool.name, args, ctx, self.world, prov)
            if isinstance(self.judge, LLMJudge):
                trace.judge_calls += 1
                pt, ct = getattr(self.judge, "last_usage", (0, 0))
                trace.prompt_tokens += pt
                trace.completion_tokens += ct
            if not ok:
                return self._block("D3-judge", reason, action, ctx)
            approvals.append("D3-judge")

        if self.approver and tool.risk == HIGH:
            ok, reason = self.approver.approve(tool.name, args, ctx)
            if not ok:
                return self._block("D4-human", reason, action, ctx)
            approvals.append(f"D4-human:{reason}")

        ns = self.gateway.memory_namespace(ctx) if self.gateway else "shared"
        out = execute(self.world, tool, args, ctx, ns)
        event = {"event": "executed", "agent": ctx.agent_id, "session": ctx.session_id, "step": ctx.step,
                 "tool": tool.name, "args": args, "decisions": approvals, "memory_namespace": ns}
        if self.gateway:
            event["credential"] = self.gateway.creds[ctx.agent_id].token
        self.log.record(event)

        if tool.trust == UNTRUSTED:
            prov.add(out, trusted=False)
            if self.isolation:
                res = self.isolation.process(tool.name, out)
                self.quarantined.extend(res.quarantined)
                return Decision(True, approvals=approvals), res.text
            return Decision(True, approvals=approvals), out
        prov.add(out, trusted=True)
        return Decision(True, approvals=approvals), out
