import tempfile
import unittest
from pathlib import Path

from torwatch.intelligence_storage import init
from torwatch.evidence_assessment import record_evidence
from torwatch.incident_relations import link_incidents, list_incident_relations


class IncidentRelationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "intel.db"
        con = init(self.db)
        for incident in ("INC-A", "INC-B"):
            con.execute("""
                INSERT INTO incidents(incident_id,created_at,updated_at)
                VALUES(?,?,?)
            """, (incident, "2026-01-01", "2026-01-01"))
        con.commit()
        con.close()
        self.evidence = record_evidence(
            "INC-A", None, "media_report", "origin-a",
            "Both incidents attributed to same actor in report",
            70, "A public report explicitly links the incidents", self.db,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_typed_relation_requires_evidence_and_is_visible_from_both_ends(self):
        relation_id = link_incidents(
            "INC-A", "INC-B", "same_actor", 55,
            "The source explicitly identifies the same actor",
            [self.evidence], self.db,
        )
        from_a = list_incident_relations("INC-A", self.db)
        from_b = list_incident_relations("INC-B", self.db)
        self.assertEqual(from_a[0]["relation_id"], relation_id)
        self.assertEqual(from_b[0]["evidence_ids"], [self.evidence])

    def test_rejects_unsubstantiated_or_invalid_relations(self):
        with self.assertRaises(ValueError):
            link_incidents("INC-A", "INC-B", "same_actor", 55, "reason", [], self.db)
        with self.assertRaises(ValueError):
            link_incidents("INC-A", "INC-A", "same_actor", 55, "reason", [self.evidence], self.db)
        with self.assertRaises(ValueError):
            link_incidents("INC-A", "INC-B", "same_actor", 55, "reason",
                           ["missing-evidence"], self.db)


if __name__ == "__main__":
    unittest.main()
