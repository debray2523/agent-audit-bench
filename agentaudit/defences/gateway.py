"""D2 -- Tool gateway: per-agent identity, least privilege, scoped credentials.

Every tool call must present a valid, unexpired, unrevoked credential issued to
that agent. The gateway then enforces:
  * the role's tool allowlist           (CERT-In: exceed authorised permissions)
  * a strict argument schema             (unknown arguments such as "pre_approved" are rejected)
  * per-tool limits: payment ceiling, internal-only email, delegation budget
  * per-user memory namespaces           (CERT-In: memory leakage between users)
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from ..agent import ROLE_TOOLS
from ..env import INTERNAL_DOMAIN, Tool, coerce_args
from ..types import Action, Context


@dataclass
class Credential:
    token: str
    agent_id: str
    scopes: frozenset
    expires_step: int
    revoked: bool = False


@dataclass
class GatewayPolicy:
    payment_limit: float = 50_000.0
    internal_domain: str = INTERNAL_DOMAIN
    delegation_budget: int = 3
    ttl_steps: int = 60
    role_tools: dict[str, list[str]] = field(default_factory=lambda: dict(ROLE_TOOLS))


class ToolGateway:
    name = "tool-gateway-v1"

    def __init__(self, policy: GatewayPolicy | None = None):
        self.policy = policy or GatewayPolicy()
        self.creds: dict[str, Credential] = {}
        self.delegations: dict[str, int] = {}

    def issue(self, ctx: Context) -> Credential:
        token = "cred-" + hashlib.sha256(f"{ctx.agent_id}:{ctx.step}".encode()).hexdigest()[:16]
        cred = Credential(token, ctx.agent_id, frozenset(self.policy.role_tools[ctx.role]),
                          ctx.step + self.policy.ttl_steps)
        self.creds[ctx.agent_id] = cred
        return cred

    def revoke(self, agent_id: str | None = None) -> int:
        """Revoke one agent's credential, or all when agent_id is None. Returns count revoked."""
        n = 0
        for aid, c in self.creds.items():
            if agent_id is None or aid == agent_id:
                if not c.revoked:
                    c.revoked = True
                    n += 1
        return n

    def memory_namespace(self, ctx: Context) -> str:
        return f"user:{ctx.session_user}"

    def check(self, action: Action, tool: Tool, ctx: Context) -> tuple[bool, str, dict[str, Any]]:
        cred = self.creds.get(ctx.agent_id)
        if cred is None:
            return False, "no credential issued to this agent", {}
        if cred.revoked:
            return False, "credential revoked", {}
        if ctx.step > cred.expires_step:
            return False, "credential expired", {}
        if tool.name not in cred.scopes:
            return False, f"tool '{tool.name}' is outside role '{ctx.role}' permissions", {}
        unknown = set(action.args) - set(tool.params)
        if unknown:
            return False, f"unexpected arguments {sorted(unknown)}", {}
        try:
            args = coerce_args(tool, action.args)
        except (KeyError, ValueError) as e:
            return False, f"invalid arguments: {e}", {}
        if tool.name == "pay_invoice" and args["amount"] > self.policy.payment_limit:
            return False, f"amount {args['amount']:.2f} exceeds per-transaction limit {self.policy.payment_limit:.2f}", {}
        if tool.name == "send_email" and not args["to"].lower().endswith("@" + self.policy.internal_domain):
            return False, "external recipients not permitted for this role", {}
        if tool.name == "delegate":
            used = self.delegations.get(ctx.agent_id, 0)
            if used >= self.policy.delegation_budget:
                return False, f"delegation budget of {self.policy.delegation_budget} exhausted", {}
            self.delegations[ctx.agent_id] = used + 1
        return True, "", args
