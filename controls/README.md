# Control matrix

`control_matrix.csv` maps CERT-In's *Artificial Intelligence (AI) Security Auditing Guidelines: Framework for Secure, Ethical and Auditable Artificial Intelligence Systems* (v1.0, 04 November 2026) to the OWASP Top 10 for Agentic Applications (2026), NIST CSF 2.0 categories, the defence layers in this repository, and the scenarios that test them.

## How each row was checked (review of 8 November 2026)

| `source_status` | Meaning |
|---|---|
| `VERIFIED 2026-11-08` | The section reference and requirement were checked against the text of the guideline PDF. Sections 2–8 were read. |
| `SECONDARY (...)` | The requirement is taken from detailed press reports of the guideline (named in the row). Most agent-specific checks sit in **§9 Advanced AI Security Requirements (pages 62–69)**, which could not be extracted in this review. |

**Open item:** read §9 (pages 62–69) and §12 of the PDF directly, replace each `SECONDARY` with the guideline's own sub-section number and wording, and mark the row `VERIFIED <date>`. Until then, quote §9 requirements as "reported" and cite the press source.

OWASP identifiers ASI01–ASI10 were checked against the published list on 8 November 2026.

## Gaps this review found

The review added four rows the first draft lacked (C16–C19) and changed three rows to **partial**:

- **C06 emergency stop:** suspend, revoke and no-restart are tested; rollback of executed actions is not implemented.
- **C10 records:** a tamper-evident log is implemented; alerting on AI-specific events is not.
- **C12 AI-BOM:** embeddings, vector stores and model adapters are not yet fields in the generated bill of materials.

## Evidence types

- **automated**: a scenario in this repository produces pass/fail evidence.
- **partial**: the harness covers part of the requirement; the gap is stated in `notes`.
- **artifact**: the repository generates a document the auditor can inspect.
- **attestation**: an organisational process; the harness can only supply supporting evidence.

## Sources

- CERT-In (2026). [AI Security Auditing Guidelines v1.0](https://www.cert-in.org.in/PDF/AI_Security_Auditing_Guidelines.pdf), CIGU-2026-0004.
- The Hindu, 5 November 2026, as reported by [Let's Data Science](https://letsdatascience.com/news/cert-in-issues-ai-security-auditing-guidelines-covering-agen-6e37b2b9).
- [Digit: Can AI agents be trusted with sensitive data?](https://www.digit.in/features/general/can-ai-agents-be-trusted-with-sensitive-data-new-cert-in-guidelines-address-the-risks.html)
- [MediaNama: Lowdown on CERT-In's AI Security Auditing Guidelines](https://www.medianama.com/2026/11/223-lowdown-cert-in-ai-security-auditing-guidelines/)
- [Elets eGov: CERT-In sets four-tier risk framework](https://egov.eletsonline.com/2026/11/cert-in-sets-four-tier-risk-framework-for-ai-security-audits-in-india/)
- [OWASP Top 10 for Agentic Applications 2026 (list as published by Giskard)](https://www.giskard.ai/knowledge/owasp-top-10-for-agentic-application-2026)
