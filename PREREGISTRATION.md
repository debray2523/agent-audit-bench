# Preregistration

**Status: DRAFT — not yet registered.** Fill every `TODO`, commit this file, and record the commit hash below **before** running any real-model experiment. Any change after that commit must be listed under *Deviations*, with the reason.

- Registered at commit: `TODO`
- Date: `TODO`
- Author: Debendra Ray (ORCID 0009-0002-5784-4442)

## 1. Research questions

- **RQ1.** Which agentic-AI audit checks from the CERT-In AI Security Auditing Guidelines can be evidenced automatically by a test harness, and which need human attestation?
- **RQ2.** How often do indirect prompt-injection and tool-misuse attacks succeed against reference finance agents built on current models, with no controls?
- **RQ3.** How much does each control layer (D1–D6), alone and combined, reduce attack success, and at what cost in blocked legitimate work, model calls, tokens and latency?

## 2. Hypotheses

- **H1.** With no controls, the attack success rate across A01–A09 is above 20% for every model tested.
- **H2.** Input isolation alone (D1) reduces attack success relative to no controls, but does not reduce A04 (poisoned data without imperative language).
- **H3.** The independent judge (D3) alone yields a lower attack success rate than the tool gateway (D2) alone on payment-redirection attacks (A01).
- **H4.** All controls combined reduce attack success to below 5% while blocking no more than 10% of benign runs.
- **H5.** The combined configuration with a model-based judge at least doubles model calls per run relative to no controls.

## 3. Design

- **Scenarios:** B01–B04 (benign) and A01–A09 (attack), exactly as defined in `agentaudit/scenarios.py` at the registration commit.
- **Configurations:** `none`, `D1-isolation`, `D2-gateway`, `D3-judge`, `D4-human`, `D5-audit`, `D6-killswitch`, `all`.
- **Models:** `TODO` (name, provider, exact version or deployment date for each). At least one hosted model and one open-weight model run locally.
- **Judge:** rule judge for the primary analysis; model judge (`--judge llm`, model `TODO`) as a secondary analysis.
- **Seeds / repetitions:** `TODO` (suggested: 10 per scenario × configuration × model). Temperature 0.0, `max_tokens` 500, `max_steps` 14.
- **Simulated reviewer miss rate:** 0.0 for the primary analysis; 0.1 as a sensitivity analysis.

## 4. Metrics

As defined in `agentaudit/report.py`: attack success rate, task success under attack, benign task success, benign runs with a block, log reconstructability, model calls, judge calls, tokens, latency.

## 5. Analysis plan

- Attack success rate per configuration with Wilson 95% confidence intervals.
- Pairwise comparison of each single-layer configuration against `none` using a two-sided Fisher exact test per scenario, Holm-corrected.
- Report every scenario × configuration cell, including those that do not support the hypotheses.

## 6. Exclusions

- Runs that fail because of API errors (HTTP 4xx/5xx after retries) are re-run once and otherwise excluded and counted.
- No run is excluded because of its outcome.

## 7. What the simulator results are

Runs with `--backend scripted` validate the harness. They are not part of the confirmatory analysis and are never reported as evidence about model behaviour.

## Deviations

None yet.
