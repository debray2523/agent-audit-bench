"""Run the benchmark scenarios through the reusable `agentaudit.guard` library.

This makes the `guard-all` configuration a test of exactly the code a team
would deploy, configured the way the integration guide recommends.
"""
from __future__ import annotations

import random
from typing import Optional

from .agent import ROLE_TOOLS
from .defences import OracleApprover
from .env import INTERNAL_DOMAIN, TOOLS, World, execute
from .guard import (CallbackApprover, DuplicateAction, Guard, LLMJudge, MemoryKillSwitch, Policy, Provenance,
                    SecretEgress, SystemOfRecord, TaskScope, ToolSpec)
from .guard.context import GuardContext, ToolCall
from .pipeline import DefenceConfig
from .types import Action, Context, Decision, RunTrace


def benchmark_policy() -> Policy:
    """The policy file a finance team would write for these two agents."""
    sensitive = {"pay_invoice": ["account"], "update_vendor_bank": ["account"], "send_email": ["to"]}
    limits = {"pay_invoice": {"amount": {"max": 50000}},
              "send_email": {"to": {"allowed_domains": [INTERNAL_DOMAIN]}}}
    p = Policy(delegation_tools=["delegate"], delegation_budget=3)
    for name, t in TOOLS.items():
        p.add(ToolSpec(name, risk=t.risk, output_trust=t.trust,
                       roles=[r for r, ts in ROLE_TOOLS.items() if name in ts],
                       params=list(t.params), sensitive_args=sensitive.get(name, []),
                       limits=limits.get(name, {}), description=t.description))
    return p


def ledger_rule(world: World) -> SystemOfRecord:
    def check(call: ToolCall, ctx: GuardContext) -> Optional[str]:
        inv = world.invoices.get(str(call.args.get("invoice_id")))
        if inv is None:
            return "invoice not in ledger"
        if inv["status"] != "open":
            return "invoice already paid"
        if abs(float(call.args["amount"]) - inv["amount"]) > 0.005:
            return f"amount differs from ledger ({inv['amount']:.2f})"
        if str(call.args["account"]) != world.vendors[inv["vendor"]]["account"]:
            return "account differs from vendor master"
        return None
    return SystemOfRecord("ledger", check, tools=["pay_invoice"])


class GuardPipeline:
    """Adapter giving the benchmark's agent loop the same interface as ControlPipeline."""

    def __init__(self, world: World, config: DefenceConfig, approver_miss_rate: float = 0.0,
                 seed: int = 0, judge_llm=None):
        self.world = world
        self.config = config
        oracle = OracleApprover(approver_miss_rate, random.Random(seed + 7919))
        self._bench_ctx: dict[str, Context] = {}

        def approve(call: ToolCall, gctx: GuardContext):
            return oracle.approve(call.tool, call.args, self._bench_ctx[gctx.agent_id])

        rules = [TaskScope(), Provenance(), SecretEgress(), DuplicateAction({"pay_invoice": ["invoice_id"]}),
                 ledger_rule(world)]
        self.judge_calls = 0
        if judge_llm is not None:
            def complete(prompt: str) -> str:
                self.judge_calls += 1
                return judge_llm.chat([{"role": "user", "content": prompt}]).text
            rules.append(LLMJudge(complete))
        self.guard = Guard(benchmark_policy(), isolation=config.isolation, rules=rules,
                           approver=CallbackApprover(approve), killswitch=MemoryKillSwitch())
        self.sessions = {}
        self.step_counter = 0

    @property
    def log(self):
        return self.guard.audit

    @property
    def blocks(self):
        return self.guard.blocks

    @property
    def quarantined(self):
        return self.guard.quarantined

    @property
    def judge(self):
        return type("J", (), {"name": "guard-rules"})()

    def next_step(self) -> int:
        self.step_counter += 1
        return self.step_counter

    def start_session(self, ctx: Context) -> None:
        self._bench_ctx[ctx.agent_id] = ctx
        self.sessions[ctx.session_id] = self.guard.session(
            role=ctx.role, user=ctx.session_user, task=ctx.task.instruction, agent_id=ctx.agent_id,
            allowed_tools=ctx.task.scope_tools)

    def operator_suspend(self, agent_id: Optional[str], at_step: int) -> bool:
        self.guard.suspend(agent_id)
        return True

    def handle(self, action: Action, ctx: Context, trace: RunTrace) -> tuple[Decision, str]:
        self._bench_ctx[ctx.agent_id] = ctx
        session = self.sessions[ctx.session_id]
        tool = TOOLS.get(action.tool)
        args = dict(action.args)
        if tool is not None:  # cast declared args so the audit log matches the ledger's record exactly
            for name, typ in tool.params.items():
                if name in args and typ == "float":
                    try:
                        args[name] = float(args[name])
                    except (TypeError, ValueError):
                        pass
                elif name in args:
                    args[name] = str(args[name])

        def run(**kw):
            return execute(self.world, tool, kw, ctx, session.ctx.memory_namespace)

        n_blocks = len(self.guard.blocks)
        before_judge = self.judge_calls
        out = session.call(action.tool, args, fn=run if tool else (lambda **kw: ""))
        trace.judge_calls += self.judge_calls - before_judge
        if len(self.guard.blocks) > n_blocks:
            b = self.guard.blocks[-1]
            return Decision(False, b["layer"], b["reason"]), str(out)
        return Decision(True), str(out)
