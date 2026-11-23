import unittest

from torwatch.normalizer import (
    classify_assertion,
    detect_event_types,
    incident_candidate_key,
    normalize_observation,
    normalize_url,
    observation_id,
    parse_timestamp,
)


class NormalizerTests(unittest.TestCase):
    def test_url_normalization_removes_fragment_and_default_port(self):
        self.assertEqual(
            normalize_url("HTTPS://Example.COM:443/a#section"),
            "https://example.com/a",
        )

    def test_timestamp_normalized_to_utc(self):
        self.assertEqual(
            parse_timestamp("2026-11-23T12:00:00+09:00"),
            "2026-11-23T03:00:00+00:00",
        )
        self.assertIsNone(parse_timestamp("not-a-date"))

    def test_event_types_detect_japanese_and_english(self):
        self.assertEqual(
            detect_event_types("Ransomware attack causes data breach"),
            ["ransomware", "data_breach"],
        )
        self.assertIn("unauthorized_access", detect_event_types("不正アクセスを確認"))

    def test_assertion_types_are_not_conflated(self):
        self.assertEqual(
            classify_assertion("darkweb", "We have hacked Example"),
            "attacker_claim",
        )
        self.assertEqual(
            classify_assertion("media", "Company hit by ransomware"),
            "media_report",
        )
        self.assertEqual(
            classify_assertion("official", "Security notice"),
            "official",
        )

    def test_observation_id_is_stable_and_source_specific(self):
        first = observation_id("feed-a", "https://example.com/post", "Headline")
        self.assertEqual(first, observation_id("feed-a", "https://example.com/post", "Headline"))
        self.assertNotEqual(first, observation_id("feed-b", "https://example.com/post", "Headline"))

    def test_candidate_key_is_not_an_incident_id(self):
        one = incident_candidate_key("Example", ["ransomware"], "2026-11-23")
        two = incident_candidate_key("Example", ["ransomware"], "2026-11-23T10:00:00Z")
        self.assertEqual(one, two)
        self.assertTrue(one.startswith("CAND-"))

    def test_normalize_legacy_feed_item(self):
        item = normalize_observation({
            "source": "BleepingComputer",
            "source_class": "media",
            "title": "Example hit by ransomware",
            "url": "https://EXAMPLE.com/story#top",
            "published": "2026-11-23T10:00:00Z",
            "matched_assets": "Example | Example Japan",
        })
        self.assertEqual(item["source_id"], "BleepingComputer")
        self.assertEqual(item["url"], "https://example.com/story")
        self.assertEqual(item["companies"], ["Example", "Example Japan"])
        self.assertEqual(item["event_types"], ["ransomware"])
        self.assertEqual(item["assertion_type"], "media_report")
        self.assertEqual(len(item["candidate_keys"]), 2)


if __name__ == "__main__":
    unittest.main()
