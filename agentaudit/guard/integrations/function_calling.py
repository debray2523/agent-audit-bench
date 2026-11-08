"""Guard a hand-written tool loop using OpenAI-style or Anthropic-style tool calls.

    from agentaudit.guard.integrations.function_calling import tool_schemas, dispatch

    tools = tool_schemas(guard, role="invoice_clerk")          # only the tools this role may use
    with guard.session(role="invoice_clerk", user="alice", task=question) as s:
        while True:
            reply = client.chat.completions.create(model=..., messages=messages, tools=tools)
            msg = reply.choices[0].message
            messages.append(msg)
            if not msg.tool_calls:
                break
            for tc in msg.tool_calls:
                messages.append(dispatch(s, tc))

No SDK dependency: tool-call objects or plain dicts are both accepted.
"""
from __future__ import annotations

import inspect
import json
from typing import Any, Optional, get_type_hints

from ..core import Guard, GuardSession

_JSON_TYPES = {str: "string", int: "integer", float: "number", bool: "boolean", list: "array", dict: "object"}


def _param_schema(fn) -> dict:
    sig = inspect.signature(fn)
    try:
        hints = get_type_hints(fn)
    except Exception:  # noqa: BLE001
        hints = {}
    props, required = {}, []
    for n, p in sig.parameters.items():
        if n in ("guard", "secrets") or p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            continue
        props[n] = {"type": _JSON_TYPES.get(hints.get(n), "string")}
        if p.default is inspect.Parameter.empty:
            required.append(n)
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


def tool_schemas(guard: Guard, role: str, fmt: str = "openai", allowed: Optional[list[str]] = None) -> list[dict]:
    """Tool definitions for the model, filtered to what `role` may use. Showing a model
    only its permitted tools is least privilege at the prompt as well as at the gateway."""
    names = [n for n in guard.tools_for_role(role) if (allowed is None or n in allowed) and n in guard._fns]
    out = []
    for n in names:
        fn = guard._fns[n]
        spec = guard.policy.tools[n]
        desc = spec.description or (fn.__doc__ or "").strip().split("\n")[0] or n
        params = _param_schema(fn)
        if fmt == "openai":
            out.append({"type": "function", "function": {"name": n, "description": desc, "parameters": params}})
        elif fmt == "anthropic":
            out.append({"name": n, "description": desc, "input_schema": params})
        else:
            raise ValueError("fmt must be 'openai' or 'anthropic'")
    return out


def _get(obj: Any, key: str) -> Any:
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)


def _content(result: Any) -> str:
    return result if isinstance(result, str) else json.dumps(result, default=str)


def dispatch(session: GuardSession, tool_call: Any) -> dict:
    """Run one OpenAI-style tool call through the guard; return the tool message to append."""
    fn = _get(tool_call, "function")
    name = _get(fn, "name")
    raw = _get(fn, "arguments") or "{}"
    try:
        args = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except json.JSONDecodeError:
        result = "ERROR: tool arguments were not valid JSON"
    else:
        result = session.call(name, args)
    return {"role": "tool", "tool_call_id": _get(tool_call, "id"), "content": _content(result)}


def dispatch_anthropic(session: GuardSession, block: Any) -> dict:
    """Run one Anthropic `tool_use` content block through the guard; return the `tool_result` block."""
    result = session.call(_get(block, "name"), dict(_get(block, "input") or {}))
    return {"type": "tool_result", "tool_use_id": _get(block, "id"), "content": _content(result)}
