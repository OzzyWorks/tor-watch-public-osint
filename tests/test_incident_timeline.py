import tempfile
import unittest
from pathlib import Path

from torwatch.intelligence_storage import init, save_observation, upsert_source
from torwatch.incident_timeline import attach_observation, build_incident_timeline


class IncidentTimelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "intel.db"
        con = init(self.db)
        con.execute("""
            INSERT INTO incidents(incident_id,created_at,updated_at)
            VALUES('INC-T','2026-01-01','2026-01-01')
        """)
        con.commit()
        con.close()
        upsert_source({
            "id": "media-a", "name": "Media A", "source_class": "media",
            "provenance_group": "origin-a",
        }, self.db)
        upsert_source({
            "id": "victim", "name": "Victim official", "source_class": "official",
            "provenance_group": "victim",
        }, self.db)

    def tearDown(self):
        self.temp.cleanup()

    def test_timeline_is_chronological_and_preserves_assertion_type(self):
        save_observation({
            "observation_id": "OBS-M", "source_id": "media-a",
            "source_class": "media", "title": "Media report",
            "published_at": "2026-11-21T10:00:00Z",
            "assertion_type": "media_report", "url": "https://news.example/a",
        }, self.db)
        save_observation({
            "observation_id": "OBS-O", "source_id": "victim",
            "source_class": "official", "title": "Victim statement",
            "published_at": "2026-11-22T10:00:00Z",
            "assertion_type": "official", "url": "https://victim.example/notice",
        }, self.db)
        attach_observation("INC-T", "OBS-O", "official_statement", 95,
                           "Published by the affected organization", self.db)
        attach_observation("INC-T", "OBS-M", "candidate", 55,
                           "Independent media report", self.db)
        events = build_incident_timeline("INC-T", self.db)
        self.assertEqual([e["observation_id"] for e in events], ["OBS-M", "OBS-O"])
        self.assertEqual(events[1]["assertion_type"], "official")
        self.assertEqual(events[1]["relation_type"], "official_statement")
        self.assertEqual(events[0]["provenance_group"], "origin-a")

    def test_rejects_invalid_link_types(self):
        with self.assertRaises(ValueError):
            attach_observation("INC-T", "OBS-X", "confirmed", 90, "reason", self.db)


if __name__ == "__main__":
    unittest.main()
