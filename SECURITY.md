# Security policy

Whitehack is a defensive assurance framework. It helps people reason about
vulnerabilities; it does not authorize access, scanning, exploitation, or testing.

## Authorized use

Use Whitehack only when at least one of these is true:

- you own the system and are permitted to test it;
- the owner gave you explicit, current permission covering the exact scope and
  techniques you plan to use; or
- you are performing a passive, offline review of material lawfully available to
  you and the applicable rules permit it.

Record the scope and its non-secret authorization reference in an Integrity Case
before active testing. Stop when scope is unclear, permission expires, a test could
harm people or data, or the observed impact exceeds the agreed boundary.

This project provides no safe harbor for testing third-party systems. A public bug
bounty, vulnerability-disclosure policy, or program brief controls only according
to its own exact terms.

## Reporting a vulnerability in Whitehack

Do **not** put exploit details, credentials, personal data, or an unremediated
vulnerability in a public issue or pull request.

If the maintainers publish a private security contact in the repository or the
Codeberg organization profile, use that channel. If no private channel is listed,
open a detail-free issue titled `Private security contact requested`; include only
your preferred private contact method and no technical details. Wait for a private
reply before sharing the report.

A useful private report contains:

- affected revision and component;
- impact and required preconditions;
- the smallest safe reproduction;
- whether the issue is already being exploited;
- suggested containment or remediation, if known; and
- how the maintainers can acknowledge you.

Maintainers should acknowledge receipt promptly, limit distribution to people who
can remediate, agree on a disclosure timeline, and credit the reporter unless they
prefer anonymity. No fixed response or remediation SLA is promised.

## Public-repository boundary

Public contributions may include framework code, sanitized templates, synthetic
examples, public-source case studies, and findings that are both remediated and
safe to disclose.

Do not commit:

- credentials, tokens, private keys, seed phrases, or private authorization proof;
- personal, customer, employee, or production data;
- internal hostnames, addresses, account identifiers, or access paths;
- unresolved findings, working exploit code, or details that increase live risk;
- third-party material you lack permission to redistribute; or
- reports whose disclosure terms have not been satisfied.

Use opaque references where evidence is confidential, and keep the referenced
artifact in the owner's approved evidence store. Before publishing, inspect the
full Git history as well as the current tree: deleting a secret in a later commit
does not remove it from history.

## Supported version

Security fixes are made on the default branch. Older snapshots may not receive
backports.
