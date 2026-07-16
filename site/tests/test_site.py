from __future__ import annotations

import unittest
from html.parser import HTMLParser
from pathlib import Path


SITE_DIR = Path(__file__).resolve().parents[1]


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.hrefs: list[str] = []
        self.scripts = 0
        self.forms = 0
        self.inline_styles = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if attributes.get("id"):
            self.ids.add(attributes["id"] or "")
        if tag in {"a", "link"} and attributes.get("href"):
            self.hrefs.append(attributes["href"] or "")
        if tag == "script":
            self.scripts += 1
        if tag == "form":
            self.forms += 1
        if "style" in attributes:
            self.inline_styles += 1


class StaticSiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.html = (SITE_DIR / "index.html").read_text(encoding="utf-8")
        self.parser = _PageParser()
        self.parser.feed(self.html)

    def test_page_has_no_script_form_or_inline_style(self) -> None:
        self.assertEqual(self.parser.scripts, 0)
        self.assertEqual(self.parser.forms, 0)
        self.assertEqual(self.parser.inline_styles, 0)

    def test_local_links_are_subpath_safe(self) -> None:
        local = [href for href in self.parser.hrefs if not href.startswith("https://")]
        self.assertTrue(local)
        for href in local:
            self.assertTrue(
                href.startswith(("./", "#")),
                f"local link is not subpath-safe: {href}",
            )
            if href.startswith("./"):
                relative = href.split("#", 1)[0][2:]
                self.assertTrue(
                    (SITE_DIR / relative).exists(),
                    f"local link target does not exist: {href}",
                )

    def test_fragment_links_have_targets(self) -> None:
        for href in self.parser.hrefs:
            if href.startswith("#"):
                self.assertIn(href[1:], self.parser.ids)

    def test_source_links_cover_onboarding_artifacts(self) -> None:
        joined = "\n".join(self.parser.hrefs)
        self.assertIn("./README.md", joined)
        self.assertIn("./downloads/integrity-case.template.json", joined)
        self.assertIn("./downloads/loopback-owner-console.example.json", joined)
        self.assertIn("./SECURITY.md", joined)

    def test_downloads_match_the_canonical_cases(self) -> None:
        repository = SITE_DIR.parent
        pairs = [
            (
                SITE_DIR / "downloads" / "integrity-case.template.json",
                repository / "integrity" / "templates" / "integrity-case.json",
            ),
            (
                SITE_DIR / "downloads" / "loopback-owner-console.example.json",
                repository / "integrity" / "examples" / "loopback-owner-console.json",
            ),
            (
                SITE_DIR / "downloads" / "integrity_case.py",
                repository / "integrity" / "integrity_case.py",
            ),
            (
                SITE_DIR / "downloads" / "integrity-case.schema.json",
                repository / "integrity" / "schema" / "integrity-case.schema.json",
            ),
            (
                SITE_DIR / "LICENSE.txt",
                repository / "LICENSE",
            ),
        ]
        for public_copy, canonical in pairs:
            self.assertEqual(
                public_copy.read_bytes(),
                canonical.read_bytes(),
                f"refresh the public download from {canonical}",
            )

    def test_only_local_stylesheet_is_loaded(self) -> None:
        self.assertIn('./style.css', self.parser.hrefs)
        self.assertNotIn("@import", (SITE_DIR / "style.css").read_text(encoding="utf-8"))

    def test_authorized_use_is_visible(self) -> None:
        lowered = self.html.lower()
        self.assertIn("explicit permission", lowered)
        self.assertIn("framework does not grant authorization", lowered)
        self.assertIn("synthetic example", lowered)


if __name__ == "__main__":
    unittest.main()
