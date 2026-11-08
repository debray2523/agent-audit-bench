"""Guard LangChain / LangGraph tools.

    from agentaudit.guard.integrations.langchain import guard_tools

    safe_tools = guard_tools(guard, [lookup_vendor, pay_invoice, read_document])
    agent = create_react_agent(model, safe_tools)          # or ToolNode(safe_tools)

    with guard.session(role="invoice_clerk", user="alice", task=question):
        agent.invoke({"messages": [("user", question)]})

The active session is found from the `with guard.session(...)` block. Where a
framework runs tools somewhere the context does not follow (another process, a
queue worker), pass it explicitly:

    agent.invoke(inputs, config={"configurable": {"guard_session": session}})

Requires `langchain-core` (installed with LangGraph). Each tool must be declared
in the guard's policy, or described with `specs={name: {...ToolSpec fields}}`.
"""
from __future__ import annotations

from typing import Any, Optional

from ..core import Guard, GuardSession, current_session
from ..policy import ToolSpec

try:
    from langchain_core.runnables import RunnableConfig
    from langchain_core.tools import BaseTool, StructuredTool
except ImportError as e:  # pragma: no cover
    raise ImportError("guard_tools needs langchain-core: pip install langchain-core") from e


def _session_from(config: Optional[RunnableConfig]) -> GuardSession:
    if config:
        s = (config.get("configurable") or {}).get("guard_session")
        if s is not None:
            return s
    return current_session()


def guard_tool(guard: Guard, tool: BaseTool, spec: Optional[dict[str, Any]] = None) -> StructuredTool:
    """Return a StructuredTool with the same name, description and argument schema
    whose every call passes through the guard."""
    name = tool.name
    if spec is not None:
        if name in guard.policy.tools:
            raise ValueError(f"'{name}' is already declared in the policy")
        guard.policy.add(ToolSpec(name, **spec))
    ts = guard.policy.tools.get(name)
    if ts is None and guard.policy.default_deny:
        raise ValueError(f"Tool '{name}' is not declared in the guard policy. Declare it or pass a spec.")
    if ts is not None and ts.params is None:
        ts.params = list(tool.args.keys())

    def _call_inner(**kwargs: Any) -> Any:
        return tool.invoke(kwargs)

    async def _acall_inner(**kwargs: Any) -> Any:
        return await tool.ainvoke(kwargs)

    def run(config: RunnableConfig, **kwargs: Any) -> Any:
        return _session_from(config).call(name, kwargs, fn=_call_inner)

    async def arun(config: RunnableConfig, **kwargs: Any) -> Any:
        return await _session_from(config).acall(name, kwargs, fn=_acall_inner)

    return StructuredTool.from_function(func=run, coroutine=arun, name=name, description=tool.description,
                                        args_schema=tool.args_schema)


def guard_tools(guard: Guard, tools: list[BaseTool],
                specs: Optional[dict[str, dict[str, Any]]] = None) -> list[StructuredTool]:
    """Guard a list of LangChain tools. `specs` optionally declares tools that the
    policy does not, as {tool_name: {risk: ..., output_trust: ..., ...}}."""
    specs = specs or {}
    return [guard_tool(guard, t, specs.get(t.name)) for t in tools]
