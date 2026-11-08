# Paper outline

**Working title:** *Audit-Ready Agents: Testing Research-Proposed Defences against CERT-In's Agentic AI Audit Checks*

1. **Introduction.** CERT-In's AI Security Auditing Guidelines (Nov 2026) make agent behaviour an audit item. Boards and regulated entities need evidence, not assurances.
2. **Related work.** Prompt injection in SOC assistants (Somro et al., 2026); configuration as attack surface (Litvak, 2026); judge-based triage (Tsegai et al., 2026); recall-constrained triage (Chen et al., 2026); external controllers for local models (Liu et al., 2026); OWASP Agentic Top 10; NIST Cyber AI Profile (draft).
3. **Control matrix.** CERT-In agentic checks × OWASP × NIST CSF 2.0; which checks can be automated, which need attestation. (Contribution 1)
4. **Harness.** Synthetic organisation, roles, tools, six control layers, scenarios. (Contribution 2: open source)
5. **Experimental setup.** Models, seeds, configurations, metrics, preregistration.
6. **Results.** Attack success by layer and combined; cost in blocked work, calls, tokens, latency. Report cells that contradict hypotheses. (Contribution 3)
7. **Discussion.** What a board should require; where controls fail (poisoned data, rubber-stamp review); transfer to RBI-regulated entities.
8. **Limitations.** Synthetic setting; self-assessment; mapping verified against guideline text on `TODO date`.
9. **Conclusion.**

Appendices: full scenario definitions; AI-BOM example; per-cell results with confidence intervals.
