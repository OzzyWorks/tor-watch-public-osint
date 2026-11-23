import tempfile
import unittest
from pathlib import Path

from torwatch.intelligence_storage import init
from torwatch.evidence_assessment import (
    assess_incident_confidence, record_evidence,
)


class EvidenceAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "intel.db"
        con = init(self.db)
        con.execute("""
            INSERT INTO incidents(incident_id,created_at,updated_at)
            VALUES('INC-E','2026-01-01','2026-01-01')
        """)
        con.commit()
        con.close()

    def tearDown(self):
        self.temp.cleanup()

    def test_independent_groups_count_once_and_score_is_explainable(self):
        record_evidence("INC-E", None, "media_report", "syndication-origin",
                        "Reported breach", 60, "Original media report", self.db)
        record_evidence("INC-E", None, "media_report", "syndication-origin",
                        "Republished breach", 60, "Syndicated copy", self.db)
        record_evidence("INC-E", None, "official", "victim-site",
                        "Company confirms incident", 95, "Victim disclosure", self.db)
        result = assess_incident_confidence("INC-E", self.db)
        self.assertEqual(result["confidence"], 42)
        self.assertEqual(result["independent_source_groups"], 2)
        self.assertFalse(result["is_probability"])
        con = init(self.db)
        self.assertEqual(con.execute(
            "SELECT confidence FROM incidents WHERE incident_id='INC-E'"
        ).fetchone()[0], 42)
        con.close()

    def test_attacker_claims_alone_are_capped(self):
        record_evidence("INC-E", None, "attacker_claim", "actor-site",
                        "We stole data", 90, "Unverified actor post", self.db)
        result = assess_incident_confidence("INC-E", self.db)
        self.assertEqual(result["confidence"], 5)

    def test_rationale_and_source_group_are_required(self):
        with self.assertRaises(ValueError):
            record_evidence("INC-E", None, "media_report", "origin", "report", 50, "", self.db)
        with self.assertRaises(ValueError):
            record_evidence("INC-E", None, "media_report", "", "report", 50, "reason", self.db)


if __name__ == "__main__":
    unittest.main()
