import tempfile
import unittest
from pathlib import Path

from torwatch.intelligence_storage import init, list_observations, save_observation, upsert_source


class IntelligenceStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "intel.db"

    def tearDown(self):
        self.temp.cleanup()

    def test_schema_creation_is_idempotent_and_additive(self):
        first = init(self.db)
        first.execute("CREATE TABLE legacy_fixture(id INTEGER PRIMARY KEY)")
        first.commit()
        first.close()
        second = init(self.db)
        tables = {row[0] for row in second.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        second.close()
        self.assertIn("legacy_fixture", tables)
        self.assertIn("observations", tables)
        self.assertIn("incidents", tables)
        self.assertIn("incident_relations", tables)
        self.assertIn("discovery_items", tables)

    def test_source_upsert_and_observation_deduplication(self):
        upsert_source({
            "id": "feed-a", "name": "Feed A", "category": "media",
            "source_class": "media", "reliability": "high",
            "language": "en", "enabled": True,
        }, self.db)
        item = {
            "observation_id": "OBS-123", "source_id": "feed-a",
            "source_class": "media", "url": "https://example.com/a",
            "title": "Example ransomware report", "assertion_type": "media_report",
            "payload": {"test": True},
        }
        self.assertTrue(save_observation(item, self.db))
        self.assertFalse(save_observation(item, self.db))
        rows = list_observations(db_path=self.db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source_id"], "feed-a")
        self.assertEqual(rows[0]["payload"]["payload"], {"test": True})

    def test_confidence_constraints_are_enforced(self):
        con = init(self.db)
        with self.assertRaises(Exception):
            con.execute("""
                INSERT INTO incidents(incident_id,confidence,created_at,updated_at)
                VALUES('bad',101,'now','now')
            """)
        con.close()


if __name__ == "__main__":
    unittest.main()
