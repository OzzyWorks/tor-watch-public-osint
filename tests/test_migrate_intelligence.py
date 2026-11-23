import tempfile
import unittest
from pathlib import Path

from scripts.migrate_intelligence import migrate_items
from torwatch.intelligence_storage import list_observations


class MigrateIntelligenceTests(unittest.TestCase):
    def test_backfill_is_idempotent_and_preserves_legacy_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "history.db"
            sources = [{
                "id": "feed-a", "name": "Feed A", "source_class": "media",
                "category": "security_media", "reliability": "high",
                "language": "en", "enabled": True,
            }]
            items = [{
                "id": "legacy-1", "source": "Feed A",
                "title": "Example ransomware data breach",
                "url": "https://example.com/story",
                "published": "2026-11-23T10:00:00Z",
                "detected_at": "2026-11-23T11:00:00Z",
                "matched_assets": ["Example Corp"], "risk": 75,
                "reasons": ["incident_term:ransomware"],
                "status": "public_report",
            }]
            self.assertEqual(migrate_items(items, sources, db), 1)
            self.assertEqual(migrate_items(items, sources, db), 0)
            rows = list_observations(db_path=db)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["assertion_type"], "media_report")
            self.assertEqual(rows[0]["payload"]["legacy_alert"]["risk"], 75)
            self.assertEqual(rows[0]["payload"]["companies"], ["Example Corp"])


if __name__ == "__main__":
    unittest.main()
