"""Shared data types."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class Action:
    """An action proposed by an agent: one tool call."""

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""

    def key(self) -> tuple:
        """Stable identity used to compare actions (tool + sorted args)."""
        return (self.tool, tuple(sorted((k, str(v)) for k, v in self.args.items())))


@dataclass
class Decision:
    """Outcome of passing an action through the control pipeline."""

    allowed: bool
    layer: str = ""  # which layer blocked it ("" when allowed)
    reason: str = ""
    approvals: list[str] = field(default_factory=list)  # layers that explicitly approved


@dataclass
class Context:
    """Who is acting, in which session, at which step."""

    agent_id: str
    role: str
    session_user: str
    session_id: str
    task: "Task"
    step: int = 0


@dataclass
class Task:
    """A unit of work given to an agent.

    instruction   -- natural-language task given to a real LLM agent
    scope_tools   -- tools a reasonable agent needs for this task (used by the judge)
    expected_high_risk -- the high-risk actions a correct agent would take
                     (used by the simulated human approver as ground truth)
    plan          -- the action sequence the *scripted simulator* follows
    """

    id: str
    instruction: str
    scope_tools: list[str]
    expected_high_risk: list[Action] = field(default_factory=list)
    plan: list[Action] = field(default_factory=list)


@dataclass
class Session:
    user: str
    role: str
    task: Task


@dataclass
class LLMResponse:
    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass
class StepRecord:
    step: int
    session_id: str
    action: Optional[Action]
    decision: Optional[Decision]
    observation: str
    raw_model_output: str = ""


@dataclass
class RunTrace:
    scenario_id: str
    config_name: str
    seed: int
    steps: list[StepRecord] = field(default_factory=list)
    llm_calls: int = 0
    judge_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    suspended_at_step: Optional[int] = None


ToolFn = Callable[..., Any]
