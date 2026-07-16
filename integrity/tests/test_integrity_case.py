from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from integrity.integrity_case import (
    assurance_counts,
    load_case,
    render_case,
    validate_case,
)


INTEGRITY_DIR = Path(__file__).resolve().parents[1]
EXAMPLE = INTEGRITY_DIR / "examples" / "loopback-owner-console.json"
TEMPLATE = INTEGRITY_DIR / "templates" / "integrity-case.json"
SCHEMA = INTEGRITY_DIR / "schema" / "integrity-case.schema.json"


class IntegrityCaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case = load_case(EXAMPLE)

    def test_schema_and_starter_are_valid_json_objects(self) -> None:
        self.assertIsInstance(json.loads(SCHEMA.read_text(encoding="utf-8")), dict)
        self.assertIsInstance(load_case(TEMPLATE), dict)

    def test_sanitized_example_is_complete(self) -> None:
        result = validate_case(self.case)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.warnings, ())
        self.assertEqual(
            assurance_counts(self.case),
            {
                "invariants": 4,
                "supported_invariants": 4,
                "controls": 4,
                "supported_controls": 4,
                "evidence": 4,
                "passing_evidence": 4,
                "residual_risks": 1,
            },
        )

    def test_starter_is_a_valid_draft_with_visible_warnings(self) -> None:
        result = validate_case(load_case(TEMPLATE))
        self.assertEqual(result.errors, ())
        self.assertTrue(any("permission is unknown" in item for item in result.warnings))
        self.assertTrue(any("no passing evidence" in item for item in result.warnings))
        self.assertTrue(any("placeholder" in item for item in result.warnings))

    def test_unknown_component_reference_fails(self) -> None:
        changed = copy.deepcopy(self.case)
        changed["boundaries"][0]["to"] = "missing-component"
        result = validate_case(changed)
        self.assertTrue(any("unknown component" in item for item in result.errors))

    def test_orphaned_invariant_fails(self) -> None:
        changed = copy.deepcopy(self.case)
        changed["controls"] = [
            control for control in changed["controls"] if "I3" not in control["enforces"]
        ]
        changed["evidence"] = [
            item for item in changed["evidence"] if item["id"] != "E4"
        ]
        result = validate_case(changed)
        self.assertTrue(any("I3 has no implementing control" in item for item in result.errors))

    def test_reviewed_case_requires_known_authorization(self) -> None:
        changed = copy.deepcopy(self.case)
        changed["case"]["status"] = "reviewed"
        changed["authorization"]["status"] = "unknown"
        result = validate_case(changed)
        self.assertTrue(any("permission is unknown" in item for item in result.errors))

    def test_reviewed_case_requires_passing_control_evidence(self) -> None:
        changed = copy.deepcopy(self.case)
        changed["evidence"][0]["result"] = "inconclusive"
        result = validate_case(changed)
        self.assertTrue(any("C1 has no passing evidence" in item for item in result.errors))

    def test_likely_secret_material_fails_without_echoing_value(self) -> None:
        changed = copy.deepcopy(self.case)
        changed["evidence"][0]["artifact"] = "AKIA" + "ABCDEFGHIJKLMNOP"
        result = validate_case(changed)
        self.assertTrue(any("secret material" in item for item in result.errors))
        self.assertFalse(any("AKIA" in item for item in result.errors))

    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema_version":"1.0","schema_version":"2.0"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                load_case(path)

    def test_dashboard_is_compact_and_escapes_html(self) -> None:
        changed = copy.deepcopy(self.case)
        changed["case"]["title"] = "Console <script>alert(1)</script>"
        rendered = render_case(changed, "example.json")
        self.assertIn("Invariant support", rendered)
        self.assertIn("4/4 (100%)", rendered)
        self.assertIn("## Invariant trace", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_committed_example_dashboard_is_current(self) -> None:
        expected = render_case(self.case, EXAMPLE.name)
        actual = EXAMPLE.with_suffix(".md").read_text(encoding="utf-8")
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
