import tempfile
import unittest
from pathlib import Path

from torwatch.actor_profiles import (
    add_actor_alias, get_actor_profile, link_actor_to_incident, upsert_actor,
)
from torwatch.intelligence_storage import init


class ActorProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "intel.db"
        con = init(self.db)
        con.execute("""
            INSERT INTO incidents(incident_id,created_at,updated_at)
            VALUES('INC-1','2026-01-01','2026-01-01')
        """)
        con.commit()
        con.close()

    def tearDown(self):
        self.temp.cleanup()

    def test_actor_alias_provenance_and_incident_link_round_trip(self):
        actor_id = upsert_actor(
            "Example Ransomware Group", "Publicly reported extortion group",
            {"family": "ransomware"}, "2026-11-20T00:00:00Z", self.db,
        )
        self.assertEqual(
            actor_id,
            upsert_actor(" Example   Ransomware Group ", db_path=self.db),
        )
        self.assertTrue(add_actor_alias(
            actor_id, "Example Crew", "https://example.org/report", 65, self.db,
        ))
        self.assertFalse(add_actor_alias(
            actor_id, "Example Crew", "https://example.org/report", 65, self.db,
        ))
        link_actor_to_incident(
            "INC-1", actor_id, "suspected", 40,
            "Only a third-party report suggests this link",
            ["EVID-1"], self.db,
        )
        profile = get_actor_profile(actor_id, self.db)
        self.assertEqual(profile["canonical_name"], "Example Ransomware Group")
        self.assertEqual(profile["aliases"][0]["source_url"], "https://example.org/report")
        self.assertEqual(profile["incident_relations"][0]["relation_type"], "suspected")
        self.assertEqual(profile["incident_relations"][0]["evidence_ids"], ["EVID-1"])

    def test_alias_requires_https_provenance_and_known_actor(self):
        actor_id = upsert_actor("Actor A", db_path=self.db)
        with self.assertRaises(ValueError):
            add_actor_alias(actor_id, "Alias", "http://example.org", 50, self.db)
        with self.assertRaises(ValueError):
            add_actor_alias("missing", "Alias", "https://example.org", 50, self.db)

    def test_attribution_requires_rationale_and_valid_relation(self):
        actor_id = upsert_actor("Actor B", db_path=self.db)
        with self.assertRaises(ValueError):
            link_actor_to_incident("INC-1", actor_id, "confirmed", 80, "", [], self.db)
        with self.assertRaises(ValueError):
            link_actor_to_incident("INC-1", actor_id, "guessed", 80, "reason", [], self.db)


if __name__ == "__main__":
    unittest.main()
