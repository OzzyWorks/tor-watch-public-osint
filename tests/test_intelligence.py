import unittest
from datetime import datetime, timezone
from torwatch.intelligence import normalize_incidents, build_actor_profiles, build_relationships, detect_discoveries


class IntelligenceTests(unittest.TestCase):
    def test_normalizes_incident_without_claiming_official_confirmation(self):
        alerts = [{
            "id": "a1", "title": "Example Corp ransomware data leak",
            "url": "https://news.example/story", "source": "News",
            "published": "2026-11-22T10:00:00Z", "detected_at": "2026-11-22T11:00:00Z",
            "matched_assets": "Example Corp", "reasons": "ransomware | data leak",
            "evidence_strength": 65, "officially_confirmed": False,
        }]
        result = normalize_incidents(alerts)
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["incident_id"].startswith("INC-"))
        self.assertEqual(result[0]["victim"], "Example Corp")
        self.assertIn("ransomware", result[0]["attack_types"])
        self.assertFalse(result[0]["officially_confirmed"])

    def test_stable_id_for_same_article_and_company(self):
        alert = {"title": "Example Corp ransomware attack", "url": "https://news.example/a",
                 "published": "2026-11-22", "matched_assets": ["Example Corp"], "reasons": "ransomware"}
        self.assertEqual(normalize_incidents([alert])[0]["incident_id"],
                         normalize_incidents([alert])[0]["incident_id"])

    def test_actor_is_assigned_only_from_configured_site_host(self):
        groups = [{"name": "Group A", "hosts": ["actor.onion"]}]
        alerts = [{"title": "Victim data leak", "url": "http://actor.onion/post",
                   "published": "2026-11-22", "matched_assets": "Victim Inc",
                   "reasons": "data leak"}]
        incident = normalize_incidents(alerts, groups)[0]
        self.assertEqual(incident["actor"], "Group A")
        self.assertEqual(incident["actor_relation"], "observed_on_configured_actor_site")

    def test_actor_profile_counts_only_explicitly_linked_incidents(self):
        groups = [{"name": "Group A", "hosts": ["actor.onion"]}]
        incidents = [{"actor": "Group A", "victim": "Victim Inc", "attack_types": ["data_leak"],
                      "published_at": "2026-11-22", "detected_at": ""}]
        profiles = build_actor_profiles(groups, incidents, [])
        self.assertEqual(profiles[0]["observed_incident_count"], 1)
        self.assertEqual(profiles[0]["victims"], ["Victim Inc"])

    def test_relationships_explain_shared_attack_pattern_without_actor_attribution(self):
        incidents = [
            {"incident_id": "1", "victim": "A Corp", "published_at": "2026-11-22",
             "attack_types": ["ransomware", "data_leak"], "actor": ""},
            {"incident_id": "2", "victim": "B Corp", "published_at": "2026-11-23",
             "attack_types": ["ransomware", "data_leak"], "actor": ""},
        ]
        links = build_relationships(incidents)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["relation"], "shared_attack_pattern")
        self.assertEqual(links[0]["confidence"], "weak")

    def test_discovery_requires_two_victims_for_actor_burst(self):
        now = datetime(2026, 11, 23, 8, tzinfo=timezone.utc)
        incidents = [
            {"actor": "Group A", "victim": "A Corp", "published_at": "2026-11-22"},
            {"actor": "Group A", "victim": "B Corp", "published_at": "2026-11-21"},
        ]
        found = detect_discoveries(incidents, [], now=now)
        burst = [x for x in found if x["type"] == "multi_victim_actor_activity"]
        self.assertEqual(len(burst), 1)
        self.assertIn("2社", burst[0]["summary"])


if __name__ == "__main__":
    unittest.main()
