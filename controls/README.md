# Control matrix

`control_matrix.csv` maps the agentic-AI checks in CERT-In's *AI Security Auditing Guidelines* (November 2026) to the OWASP Top 10 for Agentic Applications (2026), NIST CSF 2.0 categories, the defence layers in this repository, and the scenarios that test them.

## Status: not yet verified against primary sources

The CERT-In column was drafted from press reports of the guidelines, not from the guideline text itself. Before any result is published:

1. Read the guideline PDF and replace each `cert_in_check_as_reported` with the guideline's own wording and section reference.
2. Check each OWASP identifier (ASI01–ASI10) against the OWASP publication. The identifiers here are the author's best reading and may not match the final numbering.
3. Change `source_status` to `VERIFIED <date>` row by row.
4. Commit the verified matrix **before** running the preregistered experiments.

## Evidence types

- **automated**: a scenario in this repo produces pass/fail evidence.
- **partial**: the harness covers part of the check; the gap is stated in `notes`.
- **artifact**: the repo generates a document the auditor can inspect.
- **attestation**: an organisational process; the harness can only supply supporting evidence.
