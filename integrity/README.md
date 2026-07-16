# Integrity Cases

An Integrity Case is the compact Whitehack entry point: a machine-readable claim
that a system's stated intention is connected to implementation and evidence.

It specializes the repository's `claim → trace → delta` meta-doctrine into one
traceable chain:

```text
authorization
     │
     ▼
intent → invariant ← threat
             │
             ▼
          control → implementation reference
             │
             ▼
          evidence → residual risk / decision
```

The case does not replace code review, threat modeling, tests, or human judgment.
It makes their relationships visible and flags structural gaps such as an invariant
with no control, a control with no implementation reference, or a reviewed claim
with no passing evidence.

## Quick start

```bash
cp integrity/templates/integrity-case.json my-system.integrity.json
# Edit all starter values. Do not mark authorization "authorized" until confirmed.

python3 integrity/integrity_case.py validate my-system.integrity.json
python3 integrity/integrity_case.py render my-system.integrity.json
python3 integrity/integrity_case.py render my-system.integrity.json \
  --output my-system.integrity.md
```

The tool uses only the Python standard library and does not access the network.
Validation exits `0` when there are no structural errors and `1` otherwise.
Warnings identify incomplete draft assurance without blocking iteration.

See the example's
[`rendered dashboard`](examples/loopback-owner-console.md) for the compact reviewer
view produced by the second command.

## The fields

| Section | Question it answers |
|---------|---------------------|
| `case` | What assurance claim is this, who owns it, and how mature is it? |
| `authorization` | Why is this review permitted, and what actions remain excluded? |
| `intent` | What is the system for, what must stay safe, and what is not promised? |
| `components` | Which actors and technical nodes participate, at what trust level? |
| `boundaries` | Where does data or authority cross trust levels? |
| `invariants` | What must remain true for the intention to hold? |
| `threats` | Who could falsify which invariant, under what preconditions? |
| `controls` | What design or implementation is intended to enforce each invariant? |
| `evidence` | What observation supports an invariant or control, and when? |
| `decisions` | Why was this design chosen and what consequences were accepted? |
| `residual_risks` | What remains uncertain or exposed, who owns it, and what happens next? |

The normative shape is
[`schema/integrity-case.schema.json`](schema/integrity-case.schema.json). The local
validator adds cross-reference and traceability checks that JSON Schema cannot
express conveniently.

## Maturity rules

Cases use one of three statuses:

- `draft` — gaps are expected. Unknown authorization, inconclusive evidence, and
  incomplete traceability are warnings, but active testing still requires actual
  permission.
- `reviewed` — every invariant and control must have passing evidence, and
  authorization cannot be unknown.
- `accepted` — the same structural bar as reviewed; the owner has accepted the
  documented residual risks.

`superseded` preserves historical decisions but should point to the replacement in
a decision or residual-risk entry.

Passing validation means the document is structurally traceable. It does **not**
mean the references are truthful, the evidence is sufficient, or the system is
secure. A reviewer must inspect the cited implementation and evidence.

## Evidence references

`artifact` and `implementation` values are references, not embedded evidence. Use
stable repository paths, test names, configuration keys, commit IDs, or opaque
records in an approved evidence store. Never paste secrets, personal data,
confidential authorization records, or live exploit material into a public case.

Evidence results are deliberately small: `pass`, `fail`, or `inconclusive`.
Failures and uncertainty remain visible in the dashboard rather than being turned
into optimistic prose.

## Moving into the full Whitehack lifecycle

When one Integrity Case becomes crowded:

1. register each major node under `assets/`;
2. promote important boundaries into `interfaces/` contracts;
3. move open unknowns into each asset's `QUESTIONS.md`;
4. use `reviews/` before ship and the finding lifecycle after ship; and
5. feed safe closed lessons into `patterns/` and `compound/`.

The Integrity Case remains the compact assurance index; the larger artifacts carry
the depth.
