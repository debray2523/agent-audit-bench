"""Generate an AI bill of materials for the reference agents.

Output follows the CycloneDX 1.6 JSON shape (which supports
"machine-learning-model" components). Check field coverage against CERT-In's
technical guidelines on AI-BOM before relying on it for an audit.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid

from . import __version__
from .agent import ISOLATION_ADDENDUM, ROLE_TOOLS, SYSTEM_PROMPT
from .defences.judge import JUDGE_PROMPT
from .env import TOOLS
from .pipeline import DefenceConfig


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def build_aibom(model_name: str, provider: str, config: DefenceConfig, judge_model: str = "") -> dict:
    hosted = provider not in ("local-simulator", "self-hosted")
    undisclosed = (["training data composition", "fine-tuning data", "safety evaluations at the exact version used"]
                   if hosted else [])
    components = [{
        "type": "machine-learning-model", "bom-ref": "model:agent", "name": model_name,
        "supplier": {"name": provider},
        "properties": [{"name": "aab:role", "value": "agent reasoning model"}] +
                      [{"name": "aab:undisclosed", "value": u} for u in undisclosed],
    }]
    if judge_model:
        components.append({"type": "machine-learning-model", "bom-ref": "model:judge", "name": judge_model,
                           "properties": [{"name": "aab:role", "value": "independent judge (D3)"}]})
    for name, text in [("agent-system-prompt", SYSTEM_PROMPT), ("isolation-addendum", ISOLATION_ADDENDUM),
                       ("judge-prompt", JUDGE_PROMPT)]:
        components.append({"type": "data", "bom-ref": f"prompt:{name}", "name": name,
                           "hashes": [{"alg": "SHA-256", "content": _sha(text)}]})
    for t in TOOLS.values():
        components.append({"type": "application", "bom-ref": f"tool:{t.name}", "name": t.name,
                           "description": t.description,
                           "properties": [{"name": "aab:risk", "value": t.risk},
                                          {"name": "aab:output-trust", "value": t.trust},
                                          {"name": "aab:params", "value": json.dumps(t.params)},
                                          {"name": "aab:roles", "value": ",".join(
                                              r for r, ts in ROLE_TOOLS.items() if t.name in ts)}]})
    components.append({"type": "data", "bom-ref": "data:synthetic-world", "name": "synthetic finance back-office",
                       "description": "Fictional vendors, invoices, customers and a fake credential. No real data."})
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "component": {"type": "application", "name": "agent-audit-bench reference agents",
                          "version": __version__},
            "properties": [{"name": "aab:defences", "value": "+".join(config.layers()) or "none"}],
        },
        "components": components,
    }
