"""D1 -- Input isolation.

Two mechanisms applied to every UNTRUSTED tool output before the model sees it:

1. Quarantine: lines that look like instructions addressed to an AI, requests
   to change bank details, to send credentials, or claims of pre-approval are
   removed and replaced with a marker. Pattern lists are deliberately simple
   and published, so their false-negative and false-positive rates can be
   measured rather than assumed.
2. Spotlighting: the remaining content is wrapped in explicit delimiters and
   the system prompt tells the model never to follow instructions inside them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

DEFAULT_PATTERNS = [
    r"\b(ignore|disregard|override)\b.{0,40}\b(instruction|previous|above|policy|rule)",
    r"\b(ai|assistant|agent|copilot|bot)\b.{0,60}\b(must|should|now|immediately|is authori[sz]ed|are authori[sz]ed)\b",
    r"\b(new|updated|changed|revised)\b.{0,30}\b(bank|account|remittance)\b.{0,20}\b(details|number|account)\b",
    r"\b(send|forward|email|share)\b.{0,60}\b(token|password|credential|api key|secret)\b",
    r"\bpre-?approved\b",
    r"\bdelegate\b.{0,60}\b(again|each|repeat|every)\b",
]


@dataclass
class IsolationResult:
    text: str
    quarantined: list[str] = field(default_factory=list)


class InputIsolation:
    name = "input-isolation-v1"

    def __init__(self, patterns: list[str] | None = None):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in (patterns or DEFAULT_PATTERNS)]

    def suspicious(self, line: str) -> bool:
        return any(p.search(line) for p in self.patterns)

    def process(self, source: str, text: str) -> IsolationResult:
        kept, removed = [], []
        for line in text.splitlines():
            if self.suspicious(line):
                removed.append(line)
                kept.append("[REMOVED BY INPUT ISOLATION: suspected embedded instruction]")
            else:
                kept.append(line)
        body = "\n".join(kept)
        wrapped = f"<<UNTRUSTED source={source}>>\n{body}\n<<END UNTRUSTED>>"
        return IsolationResult(wrapped, removed)
