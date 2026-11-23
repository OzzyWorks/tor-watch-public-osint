import json
import tempfile
import unittest
from pathlib import Path

from torwatch.intelligence_storage import init, save_observation, upsert_source
from torwatch.discovery_engine import discover_patterns


class DiscoveryEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "intel.db"
        con = init(self.db)
        for idx in range(1, 5):
            con.execute("""
                INSERT INTO incidents(incident_id,sector,event_types_json,status,
                    detected_at,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?)
            """, (f"INC-{idx}", "manufacturing", json.dumps(["ransomware"]),
                  "reported", f"2026-11-{idx + 1:02d}T00:00:00Z",
                  "2026-11-01", "2026-11-01"))
        con.execute("""
            INSERT INTO incidents(incident_id,sector,event_types_json,status,
                detected_at,created_at,updated_at)
            VALUES('BASE-1','manufacturing','["ransomware"]','reported',
                   '2026-10-10T00:00:00Z','2026-10-01','2026-10-01')
        """)
        con.commit()
        con.close()
        for source_id, group in (("feed-a", "origin-a"), ("feed-b", "origin-b")):
            upsert_source({"id": source_id, "name": source_id,
                           "provenance_group": group}, self.db)
        for idx in range(1, 5):
            obs_id = f"OBS-{idx}"
            source_id = "feed-a" if idx % 2 else "feed-b"
            save_observation({"observation_id": obs_id, "source_id": source_id,
                              "title": f"Incident report {idx}"}, self.db)
            con = init(self.db)
            con.execute("INSERT INTO incident_observations(incident_id,observation_id) VALUES(?,?)",
                        (f"INC-{idx}", obs_id))
            con.commit()
            con.close()
        save_observation({"observation_id": "OBS-BASE", "source_id": "feed-a",
                          "title": "Baseline incident"}, self.db)
        con = init(self.db)
        con.execute("INSERT INTO incident_observations(incident_id,observation_id) VALUES(?,?)",
                    ("BASE-1", "OBS-BASE"))
        con.commit()
        con.close()

    def tearDown(self):
        self.temp.cleanup()

    def test_detects_rising_pattern_with_coverage_caveat_and_persists(self):
        results = discover_patterns(
            "2026-11-01T00:00:00Z", "2026-11-30T23:59:59Z",
            "2026-10-01T00:00:00Z", "2026-10-31T23:59:59Z", self.db,
        )
        sector = next(x for x in results if x["category"] == "sector")
        self.assertEqual(sector["pattern"], "rising")
        self.assertEqual(sector["observed_count"], 4)
        self.assertEqual(sector["baseline_count"], 1)
        self.assertEqual(len(sector["related_incidents"]), 4)
        con = init(self.db)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM discovery_items").fetchone()[0], len(results))
        con.close()

    def test_empty_baseline_is_labeled_new(self):
        results = discover_patterns(
            "2026-11-01T00:00:00Z", "2026-11-30T23:59:59Z",
            "2026-09-01T00:00:00Z", "2026-09-30T23:59:59Z", self.db,
        )
        self.assertTrue(any(x["pattern"] == "new" for x in results))

    def _add_linked_incident(self, incident_id, event_at, source_id):
        save_observation({
            "observation_id": "OBS-" + incident_id, "source_id": source_id,
            "title": "Additional ransomware report " + incident_id,
        }, self.db)
        con = init(self.db)
        con.execute("""
            INSERT INTO incidents(incident_id,sector,event_types_json,status,
                detected_at,created_at,updated_at)
            VALUES(?,?,?,'reported',?,?,?)
        """, (incident_id, "manufacturing", json.dumps(["ransomware"]),
              event_at, "2026-10-01", "2026-10-01"))
        con.execute("""
            INSERT INTO incident_observations(incident_id,observation_id)
            VALUES(?,?)
        """, (incident_id, "OBS-" + incident_id))
        con.commit()
        con.close()

    def test_recurring_and_anomalous_patterns_are_distinguished(self):
        for idx in (2, 3):
            self._add_linked_incident(
                f"BASE-{idx}", f"2026-10-{10 + idx:02d}T00:00:00Z", "feed-a"
            )
        recurring = discover_patterns(
            "2026-11-01T00:00:00Z", "2026-11-30T23:59:59Z",
            "2026-10-01T00:00:00Z", "2026-10-31T23:59:59Z", self.db,
        )
        sector = next(x for x in recurring if x["category"] == "sector")
        self.assertEqual(sector["pattern"], "recurring")

        for idx in range(5, 9):
            self._add_linked_incident(
                f"INC-{idx}", f"2026-11-{idx + 1:02d}T00:00:00Z",
                "feed-a" if idx % 2 else "feed-b",
            )
        anomalous = discover_patterns(
            "2026-11-01T00:00:00Z", "2026-11-30T23:59:59Z",
            "2026-10-01T00:00:00Z", "2026-10-31T23:59:59Z", self.db,
        )
        sector = next(x for x in anomalous if x["category"] == "sector")
        self.assertEqual(sector["pattern"], "anomalous")


if __name__ == "__main__":
    unittest.main()
