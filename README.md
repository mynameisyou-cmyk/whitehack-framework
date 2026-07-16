# Whitehack Integrity Framework

Whitehack is an open defensive-assurance framework for systems you own or are
explicitly authorized to assess. It connects security intention to implementation
and evidence while keeping uncertainty and residual risk visible.

```text
authorization → intent → invariant ← threat
                            ↓
                         control → implementation → evidence
                                                   ↓
                                             residual risk
```

The smallest reusable artifact is one JSON **Integrity Case**. It gives builders,
reviewers, and decision-makers the same compact trace without pretending that a
passing document proves a system secure.

## Start in five minutes

```bash
cp integrity/templates/integrity-case.json my-system.integrity.json
# Replace every starter value and confirm authorization before active testing.
python3 integrity/integrity_case.py validate my-system.integrity.json
python3 integrity/integrity_case.py render my-system.integrity.json \
  --output my-system.integrity.md
```

The validator and renderer use only the Python standard library and make no
network requests. Compare your first case with the fully synthetic
[`loopback-owner-console` example](integrity/examples/loopback-owner-console.json)
and its [rendered reviewer dashboard](integrity/examples/loopback-owner-console.md).

Read the [Integrity Case guide](integrity/README.md) for fields, maturity rules,
evidence references, and limitations. The compact visual introduction is also
[available as a dashboard](https://mynameisyou-cmyk.github.io/whitehack-framework/).

## What validation means

Validation checks required fields, cross-references, trace completeness, likely
embedded secret material, unsupported invariants, and controls without passing
evidence. It proves structural traceability only. A human still has to inspect the
implementation, the cited evidence, the authorization boundary, and the residual
risk.

## Safety and publication boundary

The framework does not grant permission to scan, exploit, or access any system.
Use it only inside an owned or explicitly authorized scope. Keep credentials,
personal data, private authorization records, live exploit material, and unresolved
findings out of public cases.

Read [SECURITY.md](SECURITY.md) before testing or reporting. If you are adapting
Whitehack inside a private operational repository, use the clean-history,
allowlist-based gate in [PUBLICATION.md](PUBLICATION.md) before publishing reusable
artifacts.

## Contributing and license

Generic defensive improvements, portable tooling, and synthetic examples are
welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Whitehack Integrity Framework is
licensed under [Apache-2.0](LICENSE).
