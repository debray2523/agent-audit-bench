# Methodology

## Threat model

An attacker cannot reach the agent directly. They control content the agent reads: a supplier's invoice, an email to a shared inbox, a note in shared memory. Their goals are the ones a finance team fears: redirect a payment, change master data, exfiltrate a credential or customer data, make the agent run away, or slip an action past review.

The defender controls the agent's architecture: which tools exist, what permissions the agent holds, what checks sit between a decision and an action, what is logged, and whether an operator can stop it.

## The synthetic organisation

A small finance back office (`agentaudit/env.py`): three vendors, three invoices, a vendor master, a credit report, a shared inbox, agent memory and a fake connector credential. Two roles: `invoice_clerk` and `credit_analyst`. Every tool is labelled by **risk** (read, write, high) and by the **trust** of its output (trusted system of record vs untrusted outside content). All data is fictional.

## Control layers

| Layer | Mechanism | Main checks it evidences |
|---|---|---|
| D1 Input isolation | Quarantine instruction-like lines in untrusted content; wrap the rest in delimiters; tell the model never to follow them | Prompt injection |
| D2 Tool gateway | Per-agent credential; role allowlist; strict argument schema; payment ceiling; internal-only email; delegation budget; per-user memory | Permissions, credentials, approval bypass, delegation, memory |
| D3 Independent judge | Rule judge: maker-checker against the ledger and vendor master, task scope, provenance of sensitive values. Optional model judge. | Unsafe actions, delegation |
| D4 Human approval | No high-risk action without approval; self-asserted approval ignored | Approval bypass |
| D5 Audit log | Hash-chained log of proposals, blocks, executions, credentials and decisions | Reconstruction, logging |
| D6 Kill switch | Suspend agent or workflow and revoke credentials in one operation | Emergency stop |

## Two kinds of run

**Simulator (`--backend scripted`).** A deterministic test double follows a fixed plan and, on seeing an attack payload, behaves like a fully compromised model. This answers one question only: *if the model is hijacked, do the downstream controls contain the damage, as coded?* It validates the harness. It says nothing about how often a real model is hijacked.

**Real model (`--backend openai`).** Any OpenAI-compatible endpoint: Azure OpenAI, OpenAI, or a local open-weight model served by Ollama, vLLM or llama.cpp. The model receives only the natural-language task and decides for itself. These runs are the evidence for the paper.

## Simulated human reviewer

Unattended experiments cannot wait for a person. `OracleApprover` approves an action only if it matches what a correct agent would do for that task. `--miss-rate` sets the chance it approves anything else, to model a rubber-stamping reviewer. Note one property the simulator exposes: a reviewer who checks only "is this the expected payment?" approves an identical duplicate (A09 under D4 alone). Real reviewers may or may not catch this. That is a hypothesis to test, not a finding.

## Known limitations

- Small, synthetic environment. Results show relative effects of controls, not absolute risk in any production system.
- Pattern-based isolation is deliberately simple and public. A determined attacker will phrase around it; A02 and A04 already do.
- The rule judge has access to the system of record. Where no system of record exists, only a model judge is available, and it can itself be manipulated.
- Multi-agent communication is modelled as a delegation tool call, not as real agent-to-agent messaging (control C09 is partial).
- The CERT-In mapping is verified against §§2–8 of the guideline; agent-specific §9 requirements rely on press reports until checked against the PDF (see `controls/README.md`).
- Self-assessment, not an audit by a CERT-In-empanelled auditor.
