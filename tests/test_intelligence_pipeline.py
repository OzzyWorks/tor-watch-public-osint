import json
import tempfile
import unittest
from pathlib import Path

from torwatch.intelligence_storage import init, save_observation, upsert_source
from torwatch.intelligence_pipeline import run_intelligence_pipeline


class IntelligencePipelineTests(unittest.TestCase):
    def test_pipeline_builds_candidates_evidence_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "intel.db"
            upsert_source({
                "id": "media-a", "name": "Media A", "source_class": "media",
                "reliability": "high", "provenance_group": "origin-a",
            }, db)
            save_observation({
                "observation_id": "OBS-PIPE", "source_id": "media-a",
                "source_class": "media", "title": "Example Corp hit by ransomware data breach",
                "url": "https://news.example/incident",
                "published_at": "2026-11-23T10:00:00+00:00",
                "observed_at": "2026-11-23T11:00:00+00:00",
                "assertion_type": "media_report", "language": "en",
                "companies": ["Example Corp"], "event_types": ["ransomware", "data_breach"],
                "candidate_keys": ["CAND-EXAMPLE"],
            }, db)
            first = run_intelligence_pipeline(db, observation_limit=100)
            second = run_intelligence_pipeline(db, observation_limit=100)
            self.assertEqual(first["incidents_created"], 1)
            self.assertEqual(first["observation_links"], 1)
            self.assertEqual(first["incidents_assessed"], 1)
            self.assertEqual(second["incidents_created"], 0)
            self.assertEqual(second["observation_links"], 1)
            self.assertEqual(first["discoveries"], second["discoveries"])
            con = init(db)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM incident_observations").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT status FROM incidents").fetchone()[0], "candidate")
            con.close()


if __name__ == "__main__":
    unittest.main()
