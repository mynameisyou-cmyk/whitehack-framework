# Contributing to Whitehack

Whitehack grows by turning real defensive lessons into reusable structure. Small,
evidence-backed changes are preferred over broad claims.

By intentionally submitting a contribution, you agree that it is provided under
the repository's [Apache-2.0 license](LICENSE), as described in section 5 of that
license.

## Safety and privacy gate

Before opening an issue or change:

1. Confirm that your work concerns a system you own, an explicitly authorized
   scope, or lawfully available passive material.
2. Remove credentials, personal data, internal identifiers, live exploit details,
   and non-public target information.
3. Check both the diff and commit history. Redaction in a later commit is not
   sufficient after sensitive data has entered Git.
4. Report vulnerabilities in Whitehack through [SECURITY.md](SECURITY.md), not a
   public issue.

Use synthetic names and values in examples. A reference to confidential evidence
should be an opaque identifier, not a path, URL, token, or excerpt from the
evidence itself.

## Choose the right contribution

- **Integrity Case tooling:** keep the format portable, deterministic, and useful
  without network access. New fields need schema, validator, renderer, example,
  and test updates together.
- **Schema and trace rules:** keep machine-readable constraints and the local
  validator aligned. Explain which ambiguity or broken trace the rule prevents.
- **Documentation and examples:** use synthetic systems and values. Separate
  demonstrated behavior from inference and keep every reference safe to publish.
- **Integrity Cases from real systems:** contribute only after the owner has
  remediated relevant findings, approved disclosure, and removed operational
  details that could increase live risk.

## Integrity Case quality gate

An accepted Integrity Case should make this chain inspectable:

```text
intent → invariant → threat → control → implementation → evidence → residual risk
```

Every invariant needs an implementing control and passing evidence. Every control
needs a concrete implementation reference and passing evidence. Limitations and
residual risks stay visible; validation is evidence of structural completeness,
not proof that a system is secure.

Validate and render cases before proposing them:

```bash
python3 integrity/integrity_case.py validate path/to/case.json
python3 integrity/integrity_case.py render path/to/case.json
```

## Verification

Run the dependency-free Integrity Case tests:

```bash
python3 -m unittest discover -s integrity/tests -v
python3 -m unittest discover -s site/tests -v
```

In the change description, state what you changed, why the current structure was
insufficient, what you verified, and any remaining uncertainty.
