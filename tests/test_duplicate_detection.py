import tempfile
import unittest
from pathlib import Path

from torwatch.intelligence_storage import init, save_observation, upsert_source
from torwatch.duplicate_detection import find_duplicate_candidates, review_duplicate_candidate


class DuplicateDetectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "intel.db"
        upsert_source({"id": "media-a", "name": "Media A", "source_class": "media",
                       "provenance_group": "origin-a"}, self.db)
        upsert_source({"id": "media-b", "name": "Media B", "source_class": "media",
                       "provenance_group": "origin-b"}, self.db)
        for item in [
            {"observation_id": "OBS-A", "source_id": "media-a",
             "title": "Example Corp confirms ransomware data breach after cyberattack",
             "url": "https://news.example/story?id=1",
             "published_at": "2026-11-20T10:00:00Z"},
            {"observation_id": "OBS-B", "source_id": "media-b",
             "title": "Example Corp confirms ransomware data breach after cyberattack",
             "url": "https://other.example/report",
             "published_at": "2026-11-21T10:00:00Z"},
        ]:
            save_observation({**item, "source_class": "media", "assertion_type": "media_report"}, self.db)

    def tearDown(self):
        self.temp.cleanup()

    def test_near_identical_reports_are_candidates_not_merged(self):
        candidates = find_duplicate_candidates(db_path=self.db)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["decision"], "candidate")
        self.assertFalse(candidates[0]["same_provenance_group"])
        self.assertEqual(len(candidates[0]["observations"]), 2)
        self.assertEqual(candidates[0]["observations"][0]["source_name"], "Media A")
        self.assertEqual(candidates[0]["observations"][1]["source_name"], "Media B")
        con = init(self.db)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 2)
        con.close()

    def test_review_can_keep_reports_separate(self):
        review_duplicate_candidate("OBS-A", "OBS-B", "separate",
                                   "Different events despite similar headlines", self.db)
        self.assertEqual(find_duplicate_candidates(db_path=self.db), [])

    def test_invalid_review_is_rejected(self):
        with self.assertRaises(ValueError):
            review_duplicate_candidate("OBS-A", "OBS-B", "merge", "reason", self.db)


if __name__ == "__main__":
    unittest.main()
