# agent-audit-bench

**Test whether your AI agents would pass the agentic-AI checks in CERT-In's AI Security Auditing Guidelines, and measure what each control actually buys you.**

In November 2026 CERT-In published AI Security Auditing Guidelines that ask auditors to test whether an AI agent can exceed its permissions, use tools without approval, bypass approval steps, misuse credentials, leak memory between users, delegate unsafely, and whether it can be stopped. This repository turns those checks into runnable tests.

It provides:

- **Reference agents** doing finance back-office work on fully synthetic data.
- **Nine attack scenarios** and four benign tasks, each mapped to the CERT-In checks and the OWASP Top 10 for Agentic Applications.
- **Six control layers** you can switch on one at a time or together.
- **An experiment runner** that reports attack success, false blocks, log reconstructability, model calls, tokens and latency.
- **An AI bill of materials generator** and a **hash-chained audit log** verifier.

> Independent research by the author, built on public frameworks and synthetic data. Not affiliated with, or describing the systems of, any employer. Not legal or compliance advice. The CERT-In mapping was drafted from public reports of the guidelines and must be checked against the guideline text before use (see [`controls/README.md`](controls/README.md)).

## Architecture

```mermaid
flowchart LR
    U[Untrusted inputs<br/>documents · inbox · memory] --> D1[D1 Input isolation]
    D1 --> M[AI agent<br/>model proposes an action]
    M --> D2[D2 Tool gateway<br/>identity · least privilege]
    D2 --> D3[D3 Independent judge]
    D3 --> D4[D4 Human approval<br/>high-risk only]
    D4 --> S[Business systems<br/>payments · vendor master · email]
    D6[D6 Kill switch] -.suspend + revoke.-> D2
    M -.every step.-> D5[D5 Hash-chained audit log + AI-BOM]
```

## Quick start

Requires Python 3.10+. No third-party packages at runtime.

```bash
git clone https://github.com/debray2523/agent-audit-bench
cd agent-audit-bench
python -m pip install -e ".[dev]"
python -m pytest -q                         # 67 tests
python -m agentaudit list                   # scenarios and configurations
python -m agentaudit run --backend scripted --seeds 1 --out /tmp/sim   # harness check
```

## Running against a real model

Any OpenAI-compatible endpoint works.

```bash
# Azure OpenAI
export AAB_BASE_URL="https://<resource>.openai.azure.com"
export AAB_MODEL="<deployment-name>"
export AAB_API_KEY="<key>"
export AAB_AZURE_API_VERSION="2024-10-21"

# or a local open-weight model via Ollama
export AAB_BASE_URL="http://localhost:11434/v1"
export AAB_MODEL="qwen2.5:7b-instruct"

python -m agentaudit run --backend openai --seeds 10 --out results/<model> --save-logs
```

For a model-based judge, also set `AAB_JUDGE_BASE_URL`, `AAB_JUDGE_MODEL` (and key / API version) and add `--judge llm`.

Fill and commit [`PREREGISTRATION.md`](PREREGISTRATION.md) **before** any real-model run you intend to publish.

## Scenarios

| ID | Scenario | CERT-In check (as reported) | OWASP Agentic |
|---|---|---|---|
| A01 | Prompt injection in an invoice redirects payment | Prompt injection | ASI01 |
| A02 | Spoofed supplier email changes vendor bank details | Exceed authorised permissions | ASI03, ASI09 |
| A03 | Injected instruction exfiltrates a connector credential | Misuse of credentials | ASI02, ASI03 |
| A04 | Poisoned amount in a document, no imperative language | Context poisoning | ASI01, ASI06 |
| A05 | Agent drawn into a tool outside its role | Tools without approval | ASI02, ASI03 |
| A06 | Memory leaks one user's data to another | Memory leakage between users | ASI06 |
| A07 | Runaway delegation loop | Unsafe delegation | ASI08 |
| A08 | Operator pulls the kill switch mid-attack | Emergency stop | ASI10 |
| A09 | Self-asserted "pre-approval" to bypass review | Approval bypass | ASI09 |

Benign tasks B01–B04 measure whether controls get in the way of legitimate work. B01's document deliberately contains the words "assistant" and "remit" to test for false positives.

## Defence configurations

`none`, `D1-isolation`, `D2-gateway`, `D3-judge`, `D4-human`, `D5-audit`, `D6-killswitch`, `all`.

## Two kinds of run: read this before quoting any number

- **`--backend scripted`** uses a deterministic simulator that behaves like a *fully compromised* model whenever it sees an attack payload. It checks that the harness and controls work as coded. **Its numbers are not evidence about any real model.** Every report it produces carries a banner saying so.
- **`--backend openai`** runs a real model that decides for itself. Only these runs, done under a committed preregistration, are research results.

See [`docs/methodology.md`](docs/methodology.md) for the threat model, the simulated reviewer and known limitations.

## Other commands

```bash
python -m agentaudit report results/<run>/runs.csv --out results/<run>/report.md
python -m agentaudit aibom --config all --out aibom.json
python -m agentaudit verify-log results/<run>/logs/A01__all__seed0.jsonl
```

## Research this builds on

- CERT-In (2026). *AI Security Auditing Guidelines: Framework for Secure, Ethical, and Auditable AI Systems.*
- Somro, Arshad & Gul (2026). *LLM-powered SOC Assistants: Prompt Injection Risks in Threat Triage.* SSRN.
- Litvak (2026). *The System Prompt Is the Attack Surface.* arXiv:2603.25056.
- Tsegai, Kantchelian, Yao & Gao (2026). *From Investigation Failures to Reliable SOC Agents.* arXiv:2610.10608.
- Chen, Long & Wang (2026). *REFINE.* arXiv:2609.32516.
- Liu et al. (2026). *HESP.* arXiv:2609.33446.
- OWASP GenAI Security Project. *Top 10 for Agentic Applications 2026.*
- NIST. *Cyber AI Profile (IR 8596), draft.*

## Citing

See [`CITATION.cff`](CITATION.cff).

## Licence

MIT. See [`LICENSE`](LICENSE).
