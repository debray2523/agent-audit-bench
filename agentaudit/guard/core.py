"""Guard: put the six control layers around any agent's tools.

    from agentaudit.guard import Guard, Policy

    guard = Guard(Policy.from_file("policy.json"), audit="audit.jsonl", killswitch="agents.stop")

    @guard.tool()
    def lookup_vendor(vendor_id: str) -> str: ...

    with guard.session(role="invoice_clerk", user="alice", task="Pay INV-1001") as s:
        ... run your agent; every tool call goes through s.call(...) or a decorated tool ...

Order of checks on every call:
    D6 kill switch -> D2 gateway (policy) -> D3 judge rules -> D4 human approval
    -> execute (secrets injected) -> D5 audit -> D1 isolation of untrusted output
"""
from __future__ import annotations

import contextvars
import functools
import inspect
import json
import time
import uuid
import weakref
from typing import Any, Callable, Optional, Union

from ..defences.audit import AuditLog
from ..defences.isolation import InputIsolation
from .context import GuardContext, ToolCall
from .ops import Approver, DenyAll, FileAuditLog, FileKillSwitch, MemoryKillSwitch, SecretProvider
from .policy import HIGH, UNTRUSTED, Policy, ToolSpec
from .rules import Rule, default_rules

_current: contextvars.ContextVar[Optional["GuardSession"]] = contextvars.ContextVar(
    "agentaudit_guard_session", default=None)

_RESERVED = ("guard", "secrets")


class ActionBlocked(Exception):
    def __init__(self, layer: str, reason: str, tool: str):
        super().__init__(f"BLOCKED by {layer}: {reason}")
        self.layer, self.reason, self.tool = layer, reason, tool


def current_session() -> "GuardSession":
    s = _current.get()
    if s is None:
        raise RuntimeError("No active guard session. Wrap the agent run in `with guard.session(...):`.")
    return s


def _accepts(fn: Callable, name: str) -> bool:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    return name in sig.parameters  # explicit parameters only: never leak secrets into **kwargs


def _infer_params(fn: Callable) -> list[str]:
    return [n for n, p in inspect.signature(fn).parameters.items()
            if n not in _RESERVED and p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)]


class Guard:
    def __init__(self, policy: Union[Policy, str, dict, None] = None, *,
                 isolation: Union[bool, InputIsolation] = True,
                 rules: Union[list[Rule], str, None] = "default",
                 approver: Union[Approver, str, None] = "deny",
                 audit: Union[AuditLog, str, None] = None,
                 killswitch: Union[MemoryKillSwitch, str, None] = None,
                 secrets: Optional[SecretProvider] = None,
                 on_block: str = "return",
                 on_error: str = "raise"):
        """
        policy     -- Policy, path to a JSON policy file, or dict. Defaults to an empty deny-all policy.
        isolation  -- D1. True for the default pattern set, an InputIsolation, or False.
        rules      -- D3. "default" (task scope, provenance, secret egress, duplicates), a list, or None.
        approver   -- D4 for high-risk tools. "deny" (fail closed) by default; an Approver; or None to
                      run high-risk tools without human approval.
        audit      -- D5. Path for a persistent hash-chained JSONL log, an AuditLog, or None (in memory).
        killswitch -- D6. Path of an operator flag file, a MemoryKillSwitch, or None (in memory).
        secrets    -- where tool credentials come from. Defaults to environment variables.
        on_block   -- "return" a BLOCKED message the model can read, or "raise" ActionBlocked.
        on_error   -- "raise" tool exceptions, or "return" them as an ERROR message.
        """
        if isinstance(policy, str):
            policy = Policy.from_file(policy)
        elif isinstance(policy, dict):
            policy = Policy.from_dict(policy)
        self.policy: Policy = policy or Policy()
        self.isolation = (InputIsolation() if isolation is True else isolation) or None
        self.secrets = secrets or SecretProvider()
        self.rules: list[Rule] = (default_rules(self.secret_values) if rules == "default" else list(rules or []))
        self.approver = DenyAll() if approver == "deny" else approver
        self.audit = FileAuditLog(audit, redact=self.secret_values) if isinstance(audit, str) else (audit or AuditLog())
        self.killswitch = FileKillSwitch(killswitch) if isinstance(killswitch, str) else (killswitch or MemoryKillSwitch())
        if on_block not in ("return", "raise") or on_error not in ("return", "raise"):
            raise ValueError("on_block and on_error must be 'return' or 'raise'")
        self.on_block, self.on_error = on_block, on_error
        self._fns: dict[str, Callable] = {}
        self._sessions: "weakref.WeakSet[GuardSession]" = weakref.WeakSet()
        self.blocks: list[dict] = []
        self.quarantined: list[str] = []

    # ------------------------------------------------------------------ setup
    def tool(self, name: Optional[str] = None, **spec: Any) -> Callable:
        """Register a function as a guarded tool. Keyword arguments are ToolSpec fields
        (risk, output_trust, roles, sensitive_args, limits, secrets, description).
        If the policy file already declares the tool, pass no keywords here."""
        def deco(fn: Callable) -> Callable:
            n = name or fn.__name__
            existing = self.policy.tools.get(n)
            if existing is not None and spec:
                raise ValueError(f"Tool '{n}' is declared in the policy; do not also pass settings to @guard.tool")
            ts = existing or ToolSpec(n, description=(fn.__doc__ or "").strip().split("\n")[0], **spec)
            if ts.params is None:
                ts.params = _infer_params(fn)
            self.policy.add(ts)
            self._fns[n] = fn
            positional = [p for p in _infer_params(fn)]

            def _merge(args: tuple, kwargs: dict) -> dict:
                # Map positional arguments by name; pass every keyword through untouched so
                # the gateway, not Python, decides what an unexpected argument means.
                if len(args) > len(positional):
                    raise TypeError(f"{n}() takes {len(positional)} positional arguments")
                merged = dict(zip(positional, args))
                merged.update(kwargs)
                return merged

            if inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def wrapper(*args: Any, **kwargs: Any) -> Any:
                    return await current_session().acall(n, _merge(args, kwargs))
            else:
                @functools.wraps(fn)
                def wrapper(*args: Any, **kwargs: Any) -> Any:
                    return current_session().call(n, _merge(args, kwargs))

            wrapper.__guard_tool__ = n  # type: ignore[attr-defined]
            wrapper.raw = fn            # type: ignore[attr-defined]
            return wrapper
        return deco

    def register(self, fn: Callable, name: Optional[str] = None, **spec: Any) -> Callable:
        """Non-decorator form of @guard.tool()."""
        return self.tool(name, **spec)(fn)

    def session(self, *, role: str, user: str, task: str = "", agent_id: Optional[str] = None,
                allowed_tools: Optional[list[str]] = None, metadata: Optional[dict] = None) -> "GuardSession":
        ctx = GuardContext(agent_id=agent_id or f"{role}:{uuid.uuid4().hex[:8]}", role=role, user=user, task=task,
                           allowed_tools=set(allowed_tools) if allowed_tools else None, metadata=metadata or {})
        if task:
            ctx.evidence.add(task, trusted=True)
        s = GuardSession(self, ctx)
        self._sessions.add(s)
        return s

    # ------------------------------------------------------------------ operations
    def suspend(self, agent_id: Optional[str] = None) -> int:
        """Kill switch: stop one agent or all of them and revoke live sessions. Returns sessions revoked."""
        self.killswitch.suspend(agent_id)
        n = 0
        for s in list(self._sessions):
            if agent_id is None or s.ctx.agent_id == agent_id:
                if not s.ctx.revoked:
                    s.ctx.revoked = True
                    n += 1
        self._log("suspended", None, None, agent=agent_id or "*", sessions_revoked=n)
        return n

    def resume(self, agent_id: Optional[str] = None) -> None:
        """Lift a suspension. Revoked sessions stay revoked; start new ones."""
        self.killswitch.resume(agent_id)
        self._log("resumed", None, None, agent=agent_id or "*")

    def secret_values(self) -> list[str]:
        names = {n for s in self.policy.tools.values() for n in s.secrets}
        out = []
        for n in names:
            try:
                out.append(self.secrets.get(n))
            except KeyError:
                pass
        return out

    def tools_for_role(self, role: str) -> list[str]:
        return self.policy.tools_for_role(role)

    def describe(self) -> dict:
        """Machine-readable description of the controls in force (for AI-BOM and audit evidence)."""
        return {
            "layers": {
                "D1_isolation": self.isolation.name if self.isolation else None,
                "D2_gateway": {"default_deny": self.policy.default_deny},
                "D3_rules": [r.name for r in self.rules],
                "D4_approver": self.approver.name if self.approver else None,
                "D5_audit": getattr(self.audit, "path", None) or self.audit.name,
                "D6_killswitch": getattr(self.killswitch, "path", None) or self.killswitch.name,
            },
            "policy": self.policy.to_dict(),
            "secrets_declared": sorted({n for s in self.policy.tools.values() for n in s.secrets}),
        }

    # ------------------------------------------------------------------ internals
    def _log(self, event: str, ctx: Optional[GuardContext], call: Optional[ToolCall], **extra: Any) -> None:
        rec: dict[str, Any] = {"event": event, "ts": round(time.time(), 3)}
        if ctx is not None:
            rec.update(agent=ctx.agent_id, user=ctx.user, role=ctx.role, session=ctx.session_id)
        if call is not None:
            rec.update(tool=call.tool, args=call.args)
        rec.update(extra)
        values = [v for v in self.secret_values() if v]
        if values:
            s = json.dumps(rec, default=str)
            for v in values:
                s = s.replace(v, "***REDACTED***")
            rec = json.loads(s)
        self.audit.record(rec)


class GuardSession:
    """One agent working on one task for one user."""

    def __init__(self, guard: Guard, ctx: GuardContext):
        self.guard = guard
        self.ctx = ctx
        self._token: Optional[contextvars.Token] = None

    def __enter__(self) -> "GuardSession":
        self._token = _current.set(self)
        self.guard._log("session_start", self.ctx, None, task=self.ctx.task,
                        allowed_tools=sorted(self.ctx.allowed_tools) if self.ctx.allowed_tools else None)
        return self

    def __exit__(self, *exc: Any) -> None:
        self.guard._log("session_end", self.ctx, None, calls=self.ctx.calls)
        if self._token is not None:
            _current.reset(self._token)

    def add_evidence(self, text: str, trusted: bool = True) -> None:
        """Tell the guard about trusted facts your code obtained outside a tool call
        (for example, a customer record loaded before the agent starts)."""
        self.ctx.evidence.add(str(text), trusted)

    def _block(self, layer: str, reason: str, call: ToolCall) -> str:
        self.guard._log("blocked", self.ctx, call, layer=layer, reason=reason)
        self.guard.blocks.append({"layer": layer, "reason": reason, "tool": call.tool,
                                  "agent": self.ctx.agent_id, "session": self.ctx.session_id})
        if self.guard.on_block == "raise":
            raise ActionBlocked(layer, reason, call.tool)
        return f"BLOCKED by {layer}: {reason}"

    def _prepare(self, tool: str, args: Optional[dict[str, Any]], fn: Optional[Callable]):
        """Run D6, D2, D3 and D4. Returns (blocked_message, None) or (None, plan)."""
        g, ctx = self.guard, self.ctx
        call = ToolCall(tool, dict(args or {}))
        g._log("proposed", ctx, call)

        # D6 -- kill switch and revocation
        if g.killswitch.is_suspended(ctx.agent_id):
            ctx.revoked = True
            return self._block("D6-killswitch", "agent suspended by operator", call), None
        if ctx.revoked:
            return self._block("D6-killswitch", "session credentials revoked", call), None

        # D2 -- gateway
        spec = g.policy.tools.get(tool)
        if spec is None:
            if g.policy.default_deny:
                return self._block("D2-gateway", f"tool '{tool}' is not declared in the policy", call), None
            spec = ToolSpec(tool)
        if time.time() - ctx.started_at > g.policy.session_ttl_seconds:
            ctx.revoked = True
            return self._block("D2-gateway", "session expired", call), None
        if ctx.calls >= g.policy.max_calls_per_session:
            return self._block("D2-gateway", f"call budget of {g.policy.max_calls_per_session} exhausted", call), None
        if spec.roles is not None and ctx.role not in spec.roles:
            return self._block("D2-gateway", f"tool '{tool}' is outside role '{ctx.role}' permissions", call), None
        if spec.params is not None:
            unknown = sorted(set(call.args) - set(spec.params))
            if unknown:
                return self._block("D2-gateway", f"unexpected arguments {unknown}", call), None
        for arg, lim in spec.limits.items():
            if arg in call.args:
                why = lim.check(arg, call.args[arg])
                if why:
                    return self._block("D2-gateway", why, call), None
        is_delegation = tool in g.policy.delegation_tools
        if is_delegation and ctx.delegations >= g.policy.delegation_budget:
            return self._block("D2-gateway",
                               f"delegation budget of {g.policy.delegation_budget} exhausted", call), None
        decisions = ["D2-gateway"]

        # D3 -- judge rules
        for rule in g.rules:
            if rule.applies(call, spec, ctx):
                why = rule.check(call, spec, ctx)
                if why:
                    return self._block(f"D3-{rule.name}", why, call), None
                decisions.append(f"D3-{rule.name}")

        # D4 -- human approval for high-risk tools
        if spec.risk == HIGH and g.approver is not None:
            ok, reason = g.approver.approve(call, ctx)
            if not ok:
                return self._block("D4-human", reason, call), None
            decisions.append(f"D4-human:{reason}")

        # Credentials are injected here, out of the model's sight
        func = fn or g._fns.get(tool)
        if func is None:
            raise ValueError(f"No function registered for tool '{tool}'. Use @guard.tool() or pass fn=.")
        kwargs = dict(call.args)
        if spec.secrets:
            try:
                creds = {n: g.secrets.get(n) for n in spec.secrets}
            except KeyError as e:
                return self._block("runtime", f"{e.args[0]} (failing closed)", call), None
            if _accepts(func, "secrets"):
                kwargs["secrets"] = creds
        if _accepts(func, "guard"):
            kwargs["guard"] = ctx
        return None, (call, spec, decisions, func, kwargs, is_delegation)

    def _error(self, call: ToolCall, e: Exception) -> str:
        self.guard._log("error", self.ctx, call, error=f"{type(e).__name__}: {e}")
        if self.guard.on_error == "raise":
            raise e
        return f"ERROR: {type(e).__name__}: {e}"

    def _finish(self, call: ToolCall, spec: ToolSpec, decisions: list[str], is_delegation: bool, out: Any) -> Any:
        g, ctx = self.guard, self.ctx
        ctx.calls += 1
        ctx.history.append(call)
        if is_delegation:
            ctx.delegations += 1
        g._log("executed", ctx, call, decisions=decisions, risk=spec.risk)

        # D1 -- isolate untrusted output; remember trusted output as evidence
        text = out if isinstance(out, str) else json.dumps(out, default=str)
        if spec.output_trust == UNTRUSTED:
            ctx.evidence.add(text, trusted=False)
            if g.isolation:
                res = g.isolation.process(call.tool, text)
                if res.quarantined:
                    g.quarantined.extend(res.quarantined)
                    g._log("quarantined", ctx, call, lines=len(res.quarantined))
                return res.text
            return out
        ctx.evidence.add(text, trusted=True)
        return out

    def call(self, tool: str, args: Optional[dict[str, Any]] = None, fn: Optional[Callable] = None) -> Any:
        """Run one tool call through all control layers. `fn` overrides the registered function."""
        blocked, plan = self._prepare(tool, args, fn)
        if plan is None:
            return blocked
        call, spec, decisions, func, kwargs, is_delegation = plan
        try:
            out = func(**kwargs)
            if inspect.isawaitable(out):
                raise TypeError(f"tool '{tool}' is async; use `await session.acall(...)`")
        except Exception as e:  # noqa: BLE001
            return self._error(call, e)
        return self._finish(call, spec, decisions, is_delegation, out)

    async def acall(self, tool: str, args: Optional[dict[str, Any]] = None, fn: Optional[Callable] = None) -> Any:
        """Async version of call(). Works with sync or async tool functions."""
        blocked, plan = self._prepare(tool, args, fn)
        if plan is None:
            return blocked
        call, spec, decisions, func, kwargs, is_delegation = plan
        try:
            out = func(**kwargs)
            if inspect.isawaitable(out):
                out = await out
        except Exception as e:  # noqa: BLE001
            return self._error(call, e)
        return self._finish(call, spec, decisions, is_delegation, out)
