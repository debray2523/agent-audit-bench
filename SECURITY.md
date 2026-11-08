# Security policy

`agent-audit-bench` includes `agentaudit.guard`, a library that people may put in front of AI agents that move money, change records or send data. A weakness in it could matter, so please report one privately.

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| < 0.2 | No (benchmark only, no guard library) |

## How to report a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Use GitHub's private vulnerability reporting: go to the **Security** tab of this repository and click **Report a vulnerability**. Only the maintainer will see your report.

Please include:

- what is affected (file, function, version or commit);
- steps or a minimal script to reproduce, ideally against `examples/quickstart/`;
- what an attacker could achieve;
- any fix you suggest.

## What counts as a vulnerability

In scope, for example:

- a tool call that executes although a layer that is switched on should have blocked it: default deny, role, argument schema, limits, delegation budget, kill switch, revocation, judge rule, or human approval;
- a way for a tool's injected credential to reach the model, a tool result, or the audit log unmasked;
- a way to alter, remove or insert audit-log entries without `verify-log` detecting it;
- a way for one session's memory namespace or evidence to affect another user's session;
- the guard failing open when a judge, approver or secret source errors.

Out of scope, because they are documented limitations rather than defects (see the README and `docs/integration-guide.md`):

- phrasing that gets past the pattern-based input isolation (D1). It is deliberately simple; other layers exist because of this;
- a manipulated value that also satisfies the policy limits and every configured judge rule;
- weaknesses in the systems a guarded tool calls;
- anything that needs the attacker to change the policy file, the guard's code, or the host;
- results from the scripted simulator.

Reports that show a documented limitation is worse than documented are still welcome.

## What to expect

- Acknowledgement within 7 days.
- An assessment and, if confirmed, a fix plan within 30 days.
- A fix released, and a GitHub security advisory published, within 90 days of the report, or sooner if a fix is simple. You will be credited unless you prefer otherwise.

This is an independent, unpaid project: there is no bug bounty.

## Safe harbour

Good-faith research that follows this policy, uses only your own systems or the synthetic data in this repository, and gives reasonable time to fix before disclosure, will not be treated as a violation, and the maintainer will not pursue or support legal action against you for it.
