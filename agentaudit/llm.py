"""Model backends.

* ScriptedLLM -- a deterministic test double. It follows a fixed plan and, when
  it sees an attack payload, behaves like a *fully compromised* model. It exists
  to validate the harness and to measure containment by downstream controls.
  Its outputs are NOT evidence of how any real model behaves.

* OpenAICompatibleLLM -- any OpenAI-compatible chat endpoint: OpenAI, Azure
  OpenAI, or a local server such as Ollama / vLLM / llama.cpp. Uses only the
  Python standard library.
"""
from __future__ import annotations

import json
import os
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from .types import Action, LLMResponse

UNTRUSTED_OPEN = "<<UNTRUSTED"


@dataclass
class HijackSpec:
    """What a compromised model does once it reads the payload."""

    marker: str                      # substring of the payload that must be visible
    actions: list[Action] = field(default_factory=list)


class ScriptedLLM:
    name = "scripted-compromisable-v1"
    provider = "local-simulator"

    def __init__(self, plan: list[Action], hijack: Optional[HijackSpec] = None,
                 follow_spotlighted: float = 1.0, rng: Optional[random.Random] = None):
        self.plan = list(plan)
        self.i = 0
        self.hijack = hijack
        self.follow_spotlighted = follow_spotlighted
        self.rng = rng or random.Random(0)
        self.queue: list[Action] = []
        self.hijack_evaluated = False
        self.was_hijacked = False

    def _payload_visible(self, messages: list[dict]) -> tuple[bool, bool]:
        """Return (visible, inside_untrusted_block) for the hijack marker."""
        assert self.hijack is not None
        for m in messages:
            content = m.get("content", "")
            if m.get("role") == "system" or self.hijack.marker not in content:
                continue
            return True, UNTRUSTED_OPEN in content
        return False, False

    def chat(self, messages: list[dict]) -> LLMResponse:
        if self.hijack and not self.hijack_evaluated:
            visible, spotlighted = self._payload_visible(messages)
            if visible:
                self.hijack_evaluated = True
                follows = True if not spotlighted else self.rng.random() < self.follow_spotlighted
                if follows:
                    self.was_hijacked = True
                    self.queue = list(self.hijack.actions)
        if self.queue:
            a = self.queue.pop(0)
        elif self.i < len(self.plan):
            a = self.plan[self.i]
            self.i += 1
        else:
            return LLMResponse(json.dumps({"final": "Task complete."}))
        return LLMResponse(json.dumps({"tool": a.tool, "args": a.args}))


class OpenAICompatibleLLM:
    provider = "openai-compatible"

    def __init__(self, model: str, base_url: str, api_key: str = "", azure_api_version: str = "",
                 temperature: float = 0.0, max_tokens: int = 500, timeout: float = 90.0, retries: int = 4):
        self.model = model
        self.name = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.azure_api_version = azure_api_version
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.retries = retries
        if azure_api_version:
            self.provider = "azure-openai"

    @classmethod
    def from_env(cls, prefix: str = "AAB") -> "OpenAICompatibleLLM":
        """Read AAB_BASE_URL, AAB_API_KEY, AAB_MODEL, AAB_AZURE_API_VERSION."""
        base = os.environ.get(f"{prefix}_BASE_URL")
        model = os.environ.get(f"{prefix}_MODEL")
        if not base or not model:
            raise RuntimeError(f"Set {prefix}_BASE_URL and {prefix}_MODEL (and {prefix}_API_KEY if needed).")
        return cls(model=model, base_url=base, api_key=os.environ.get(f"{prefix}_API_KEY", ""),
                   azure_api_version=os.environ.get(f"{prefix}_AZURE_API_VERSION", ""))

    def _request(self, messages: list[dict]) -> dict:
        body = {"messages": messages, "temperature": self.temperature, "max_tokens": self.max_tokens}
        headers = {"Content-Type": "application/json"}
        if self.azure_api_version:
            url = (f"{self.base_url}/openai/deployments/{self.model}/chat/completions"
                   f"?api-version={self.azure_api_version}")
            headers["api-key"] = self.api_key
        else:
            url = f"{self.base_url}/chat/completions"
            body["model"] = self.model
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
        delay = 2.0
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return json.loads(r.read().decode())
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503) and attempt < self.retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise RuntimeError(f"LLM HTTP {e.code}: {e.read().decode(errors='replace')[:300]}") from e
        raise RuntimeError("LLM request failed after retries")

    def chat(self, messages: list[dict]) -> LLMResponse:
        data = self._request(messages)
        text = data["choices"][0]["message"].get("content") or ""
        usage = data.get("usage") or {}
        return LLMResponse(text, usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0))


def parse_action(text: str) -> tuple[Optional[Action], Optional[str], Optional[str]]:
    """Parse a model reply into (action, final_answer, error).

    Accepts a bare JSON object or one wrapped in a ```json fence.
    """
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        t = t[t.find("{"):] if "{" in t else t
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end == -1:
        return None, None, "no JSON object in reply"
    try:
        obj = json.loads(t[start:end + 1])
    except json.JSONDecodeError as e:
        return None, None, f"invalid JSON: {e}"
    if "final" in obj:
        return None, str(obj["final"]), None
    if "tool" in obj:
        args = obj.get("args") or {}
        if not isinstance(args, dict):
            return None, None, "args must be an object"
        return Action(str(obj["tool"]), args, str(obj.get("rationale", ""))), None, None
    return None, None, "reply must contain 'tool' or 'final'"
