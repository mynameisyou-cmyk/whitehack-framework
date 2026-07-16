# Safety boundary

Whitehack helps structure defensive reasoning. It does not grant authorization.

Use it only when you own the system, have explicit current permission for the
exact scope and techniques, or are doing a passive offline review that applicable
rules allow. Stop if permission is unclear or expired, a test could harm people or
data, or observed impact exceeds the agreed boundary.

Do not publish credentials, personal data, private authorization records, internal
access details, unresolved findings, or working exploit material. A secret removed
in a later Git commit remains in history; rotate it and coordinate proper history
remediation.

Do not report an unremediated vulnerability in a public issue. Use the private
security contact listed by the relevant project. If none exists, request a private
contact without including technical details.

Validation means the Integrity Case is structurally traceable. It is not a security
certification, a safe-harbor promise, or permission to test a third-party system.
