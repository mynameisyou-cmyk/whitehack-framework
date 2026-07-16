# Whitehack Integrity Framework

Whitehack is an open defensive assurance framework for systems you own or are
explicitly authorized to assess. It connects security intention to implementation
and evidence while keeping residual risk visible.

The smallest artifact is one JSON Integrity Case:

```text
authorization → intent → invariant ← threat
                            ↓
                         control → implementation → evidence
                                                   ↓
                                             residual risk
```

## Start

1. Download [`integrity-case.template.json`](downloads/integrity-case.template.json).
2. Replace all starter content. Do not mark authorization `authorized` until the
   exact scope and techniques are permitted.
3. Download the dependency-free [`integrity_case.py`](downloads/integrity_case.py)
   validator beside your case.
4. Validate and render the case:

   ```bash
   python3 integrity_case.py validate my-system.integrity.json
   python3 integrity_case.py render my-system.integrity.json --output dashboard.md
   ```

5. Compare with the complete synthetic
   [`loopback-owner-console.example.json`](downloads/loopback-owner-console.example.json).

Validation detects missing fields, broken cross-references, likely embedded secret
material, unsupported invariants, and controls without passing evidence. It proves
structural traceability—not that the cited evidence is truthful or that a system is
secure.

The machine-readable format is documented by
[`integrity-case.schema.json`](downloads/integrity-case.schema.json).

## Contributing

Contributions should be generic, defensive, and safe to publish. Use synthetic
names and values. Never include credentials, personal data, internal access paths,
unresolved findings, or exploit details that increase risk to a live system.

Doctrine changes should name the real observed delta that motivated them. Format
changes must update the schema, validator, renderer, example, and tests together.

See [`SECURITY.md`](SECURITY.md) before testing, reporting, or publishing.

## License

[Apache-2.0](LICENSE.txt).
