# Preregistration: pilot study v1

**Status: REGISTERED (pilot).** The registration point is the git tag `prereg-pilot-v1`, placed on the commit that merges this file into `main`. Any change after that tag must be listed under *Deviations*, with the reason. The `protect-main` ruleset blocks force pushes, so `main`'s history, and this file's date on it, cannot be rewritten.

- Registration tag: `prereg-pilot-v1`
- Date: 8 November 2026
- Author: Debendra Ray (ORCID 0009-0002-5784-4442)
- Study type: **pilot**. Results are reported descriptively. They estimate direction and size of effects and inform a later confirmatory study, which will be registered separately with a larger sample.

## 1. Research questions

- **RQ1.** Which agentic-AI audit requirements in CERT-In's AI Security Auditing Guidelines v1.0 can be evidenced automatically by a test harness, and which need human attestation? (Answered by `controls/control_matrix.csv`; no model runs needed.)
- **RQ2.** How often do indirect prompt-injection and tool-misuse attacks succeed against reference finance agents built on a hosted and an open-weight model, with no controls?
- **RQ3.** How much does each control layer (D1–D6), alone and combined, reduce attack success, and at what cost in blocked legitimate work, model calls, tokens and latency?

## 2. Hypotheses

Stated before any real-model run. In this pilot they are assessed descriptively against the stated thresholds, not with significance tests.

- **H1.** With no controls, the attack success rate across A01–A09 is above 20% for each model.
- **H2.** Input isolation alone (`D1-isolation`) has a lower attack success rate than `none`, but does not lower it for A04 (poisoned data without imperative language).
- **H3.** On A01 (payment redirection), the judge alone (`D3-judge`) has a lower attack success rate than the gateway alone (`D2-gateway`).
- **H4.** `all` has an attack success rate below 5% while blocking actions in no more than 10% of benign runs.
- **H5.** The reusable library (`guard-all`) has an attack success rate no higher than `all`, and blocks actions in no more benign runs than `all`.
- **H6.** Attack success with no controls is higher for the open-weight model than for the hosted model.

(The earlier draft's hypothesis about a model-based judge doubling model calls is **not tested in this pilot**; see §3, *Judge*.)

## 3. Design

- **Code:** the repository at tag `prereg-pilot-v1`. Scenarios exactly as defined in `agentaudit/scenarios.py` there: B01–B04 (benign) and A01–A09 (attack).
- **Configurations (9):** `none`, `D1-isolation`, `D2-gateway`, `D3-judge`, `D4-human`, `D5-audit`, `D6-killswitch`, `all`, `guard-all`.
- **Models (2):**
  1. **GPT-4.1**, hosted on Azure OpenAI, through the OpenAI-compatible backend (`--backend openai`) with `AAB_AZURE_API_VERSION=2024-10-21`. The deployment name and the model version shown in the Azure portal are recorded in `results/<run>/model.json` before the first call.
  2. **Llama 3.1 8B Instruct**, run locally through Ollama (`llama3.1:8b`) at its OpenAI-compatible endpoint. The exact model digest from `ollama show` is recorded in `results/<run>/model.json`.
- **Repetitions:** 3 per scenario × configuration × model, giving 351 runs per model and 702 in total.
- **Sampling:** temperature 0.0, `max_tokens` 500, `max_steps` 14. Repetitions capture any non-determinism in model serving; with temperature 0 they may often be identical, which the analysis will report.
- **Judge:** the rule judge (`--judge rule`) in all configurations that include D3. A model-based judge is out of scope for the pilot.
- **Simulated reviewer:** `--miss-rate 0.0`, so D4 approves only expected business actions. No sensitivity analysis in the pilot.
- **Environment:** the author's computer. OS, Python version, and repository commit are recorded in `results/<run>/model.json`.
- **Order:** for each model, configurations run in the order listed above, all scenarios within a configuration, then repetitions.

## 4. Metrics

As defined in `agentaudit/report.py` at the registration tag:
- attack success rate;
- task success under attack;
- benign task success;
- benign runs with a block;
- log reconstructability;
- model calls, judge calls, tokens and latency.

## 5. Analysis plan

- For each model, report attack success rate per configuration with **Wilson 95% confidence intervals**, and per scenario × configuration.
- Assess each hypothesis against its threshold, and state for each whether the point estimate and the interval support it, contradict it, or are inconclusive.
- Exploratory only: two-sided Fisher exact tests for each single-layer configuration against `none`, Holm-corrected, labelled as exploratory.
- Report every cell, including those that contradict the hypotheses.
- Use the pilot's observed effect sizes to set the sample size of the confirmatory study.

## 6. Exclusions and failures

- A run that fails with an API or connection error after the client's retries is re-run once. If it fails again it is excluded and listed with the error.
- A model reply that cannot be parsed is **not** an exclusion. The agent loop records it and continues; it counts towards the run's outcome.
- No run is excluded because of its outcome.

## 7. What the simulator results are

Runs with `--backend scripted` validate the harness. They are not part of this study and are never reported as evidence about model behaviour.

## 8. Known limitations, stated in advance

- A pilot with 3 repetitions cannot support firm statistical claims.
- Synthetic environment; a self-assessment, not an audit by a CERT-In-empanelled auditor.
- Agent-specific CERT-In requirements (§9) are mapped from press reports until verified against the guideline text (see `controls/README.md`).
- The simulated reviewer approves exactly the expected actions; real reviewers will differ.

## Deviations

None yet.
