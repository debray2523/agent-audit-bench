"""Exercise the real-model code path against a local fake OpenAI-compatible server."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agentaudit.llm import OpenAICompatibleLLM
from agentaudit.pipeline import PRESETS
from agentaudit.runner import RunOptions, run_one
from agentaudit.scenarios import ALL_SCENARIOS

# A "model" that pays INV-1001 correctly, one tool call per turn.
SCRIPT = [
    {"tool": "list_invoices", "args": {}},
    {"tool": "read_document", "args": {"doc_id": "DOC-1001"}},
    {"tool": "lookup_vendor", "args": {"vendor_id": "V-100"}},
    {"tool": "pay_invoice", "args": {"invoice_id": "INV-1001", "amount": 12000, "account": "ACC-100-AS"}},
    {"final": "Paid INV-1001."},
]


def make_handler(seen):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
            turn = sum(1 for m in body["messages"] if m["role"] == "assistant")
            reply = SCRIPT[min(turn, len(SCRIPT) - 1)]
            out = {"choices": [{"message": {"content": json.dumps(reply)}}],
                   "usage": {"prompt_tokens": 100, "completion_tokens": 20}}
            data = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass
    return H


@pytest.fixture
def server():
    seen = []
    srv = HTTPServer(("127.0.0.1", 0), make_handler(seen))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}", seen
    srv.shutdown()


def test_openai_path_runs_benign_task_under_all_controls(server):
    url, seen = server
    opt = RunOptions(backend="openai",
                     llm_factory=lambda: OpenAICompatibleLLM("fake-model", url + "/v1", api_key="k"))
    r = run_one(ALL_SCENARIOS["B01"], PRESETS["all"], 0, opt)
    assert r["task_success"] is True
    assert r["blocked_actions"] == 0
    assert r["prompt_tokens"] == 100 * r["llm_calls"]
    assert seen[0]["path"] == "/v1/chat/completions"
    assert seen[0]["headers"]["authorization"] == "Bearer k"
    assert "UNTRUSTED" in seen[0]["body"]["messages"][0]["content"]


def test_azure_url_and_header(server):
    url, seen = server
    llm = OpenAICompatibleLLM("my-deploy", url, api_key="az", azure_api_version="2024-10-21")
    llm.chat([{"role": "user", "content": "hi"}])
    assert seen[0]["path"] == "/openai/deployments/my-deploy/chat/completions?api-version=2024-10-21"
    assert seen[0]["headers"]["api-key"] == "az"
    assert "model" not in seen[0]["body"]
