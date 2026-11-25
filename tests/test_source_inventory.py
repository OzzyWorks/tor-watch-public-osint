import unittest
from pathlib import Path

import yaml


class SourceInventoryTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / "config" / "sources.yml"
        self.sources = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("sources", [])

    def test_source_ids_are_unique_and_all_sources_are_https(self):
        ids = [source.get("id") for source in self.sources]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(self.sources), 12)
        for source in self.sources:
            with self.subTest(source=source.get("id")):
                self.assertTrue(str(source.get("url", "")).startswith("https://"))

    def test_japanese_incident_news_sources_are_enabled(self):
        by_id = {source["id"]: source for source in self.sources}
        for source_id in ("itmedia_security", "itmedia_domestic", "scannetsecurity"):
            with self.subTest(source=source_id):
                self.assertTrue(by_id[source_id]["enabled"])
                self.assertEqual(by_id[source_id]["language"], "ja")
                self.assertEqual(by_id[source_id]["source_class"], "media")

    def test_every_source_has_provenance_and_classification(self):
        required = ("category", "source_class", "reliability", "language", "provenance_group")
        for source in self.sources:
            with self.subTest(source=source.get("id")):
                for field in required:
                    self.assertTrue(source.get(field), f"{source.get('id')} missing {field}")
                self.assertIn(source["reliability"], {"high", "medium", "low"})
                self.assertTrue(source.get("name"))

    def test_added_independent_sources_are_present(self):
        ids = {source["id"] for source in self.sources}
        self.assertTrue({
            "cisa_advisories", "securityaffairs", "malwarebytes",
            "cyberscoop", "helpnetsecurity",
            "itmedia_security", "itmedia_domestic", "scannetsecurity",
        }.issubset(ids))


if __name__ == "__main__":
    unittest.main()
