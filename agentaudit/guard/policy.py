"""Declarative policy: what each tool is, who may use it, and within what limits.

A policy can be written in Python or loaded from JSON, so a risk or audit team
can read and sign off the same file the agent enforces.

Example JSON:

    {
      "default_deny": true,
      "delegation": {"tools": ["delegate"], "budget": 3},
      "session": {"ttl_seconds": 3600, "max_calls": 100},
      "tools": {
        "pay_invoice": {
          "risk": "high", "output_trust": "trusted", "roles": ["invoice_clerk"],
          "params": ["invoice_id", "amount", "account"],
          "sensitive_args": ["account"],
          "limits": {"amount": {"max": 50000}},
          "secrets": ["PAYMENTS_API_TOKEN"]
        },
        "read_document": {"risk": "read", "output_trust": "untrusted"}
      }
    }
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

READ = "read"
WRITE = "write"
HIGH = "high"
RISKS = (READ, WRITE, HIGH)
TRUSTED = "trusted"
UNTRUSTED = "untrusted"


@dataclass
class ArgLimit:
    """Constraints on one argument. Unset fields are not checked."""

    max: Optional[float] = None
    min: Optional[float] = None
    allowed_values: Optional[list[str]] = None
    allowed_domains: Optional[list[str]] = None   # for email addresses or URLs
    pattern: Optional[str] = None                 # full-match regular expression
    max_length: Optional[int] = None

    def check(self, name: str, value: Any) -> Optional[str]:
        """Return a reason string if the value violates the limit, else None."""
        if self.max is not None or self.min is not None:
            try:
                v = float(value)
            except (TypeError, ValueError):
                return f"'{name}' must be numeric"
            if self.max is not None and v > self.max:
                return f"'{name}'={v:g} exceeds limit {self.max:g}"
            if self.min is not None and v < self.min:
                return f"'{name}'={v:g} below minimum {self.min:g}"
        s = str(value)
        if self.allowed_values is not None and s not in self.allowed_values:
            return f"'{name}' value not in allowed list"
        if self.allowed_domains is not None:
            host = s.rsplit("@", 1)[-1].lower() if "@" in s else re.sub(r"^[a-z]+://", "", s.lower()).split("/")[0]
            if not any(host == d.lower() or host.endswith("." + d.lower()) for d in self.allowed_domains):
                return f"'{name}' domain '{host}' not permitted"
        if self.pattern is not None and not re.fullmatch(self.pattern, s):
            return f"'{name}' does not match required format"
        if self.max_length is not None and len(s) > self.max_length:
            return f"'{name}' longer than {self.max_length} characters"
        return None


@dataclass
class ToolSpec:
    name: str
    risk: str = READ                          # read | write | high (high = needs human approval when D4 is on)
    output_trust: str = TRUSTED               # untrusted output is isolated before the model sees it
    roles: Optional[list[str]] = None         # None = any role
    params: Optional[list[str]] = None        # strict argument names; None = inferred from the function
    sensitive_args: list[str] = field(default_factory=list)   # values must come from trusted evidence
    limits: dict[str, ArgLimit] = field(default_factory=dict)
    secrets: list[str] = field(default_factory=list)          # injected at execution, never shown to the model
    description: str = ""

    def __post_init__(self) -> None:
        if self.risk not in RISKS:
            raise ValueError(f"{self.name}: risk must be one of {RISKS}")
        if self.output_trust not in (TRUSTED, UNTRUSTED):
            raise ValueError(f"{self.name}: output_trust must be 'trusted' or 'untrusted'")
        self.limits = {k: (v if isinstance(v, ArgLimit) else ArgLimit(**v)) for k, v in self.limits.items()}


@dataclass
class Policy:
    tools: dict[str, ToolSpec] = field(default_factory=dict)
    default_deny: bool = True                 # unknown tools are blocked
    delegation_tools: list[str] = field(default_factory=list)
    delegation_budget: int = 3
    session_ttl_seconds: float = 3600.0
    max_calls_per_session: int = 100

    def add(self, spec: ToolSpec) -> None:
        self.tools[spec.name] = spec

    def tools_for_role(self, role: str) -> list[str]:
        return [n for n, s in self.tools.items() if s.roles is None or role in s.roles]

    # ---------------------------------------------------------------- (de)serialise
    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        tools = {name: ToolSpec(name=name, **{k: v for k, v in spec.items() if k != "name"})
                 for name, spec in d.get("tools", {}).items()}
        deleg = d.get("delegation", {})
        sess = d.get("session", {})
        return cls(tools=tools, default_deny=d.get("default_deny", True),
                   delegation_tools=deleg.get("tools", []), delegation_budget=deleg.get("budget", 3),
                   session_ttl_seconds=sess.get("ttl_seconds", 3600.0),
                   max_calls_per_session=sess.get("max_calls", 100))

    @classmethod
    def from_file(cls, path: str) -> "Policy":
        with open(path) as f:
            return cls.from_dict(json.load(f))

    def to_dict(self) -> dict:
        def spec(s: ToolSpec) -> dict:
            d = asdict(s)
            d.pop("name")
            d["limits"] = {k: {kk: vv for kk, vv in asdict(v).items() if vv is not None} for k, v in s.limits.items()}
            return {k: v for k, v in d.items() if v not in (None, [], {}, "")}
        return {"default_deny": self.default_deny,
                "delegation": {"tools": self.delegation_tools, "budget": self.delegation_budget},
                "session": {"ttl_seconds": self.session_ttl_seconds, "max_calls": self.max_calls_per_session},
                "tools": {n: spec(s) for n, s in self.tools.items()}}

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
