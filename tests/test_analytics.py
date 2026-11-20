import unittest
from torwatch.analytics import build_company_radar, build_group_activity


class AnalyticsTests(unittest.TestCase):
    def test_company_radar_aggregates_pages_and_events(self):
        pages = [
            {"url":"http://a.onion/","risk":75,"reasons":"company:Example Corp","checked_at":"2026-11-20"},
            {"url":"http://b.onion/","risk":40,"reasons":"company:Example Corp","checked_at":"2026-11-19"},
        ]
        events = [{"url":"http://a.onion/","risk":75,"reasons":"company:Example Corp"}]
        result = build_company_radar(pages, events, [])
        self.assertEqual(result[0]["company"], "Example Corp")
        self.assertEqual(result[0]["monitored_pages"], 2)
        self.assertEqual(result[0]["max_risk"], 75)
        self.assertEqual(result[0]["event_count"], 1)

    def test_group_activity_counts_distinct_changed_pages(self):
        groups = [{"name":"Example Group","hosts":["a.onion","b.onion"]}]
        pages = [
            {"url":"http://a.onion/","risk":80,"checked_at":"2026-11-20"},
            {"url":"http://b.onion/","risk":30,"checked_at":"2026-11-19"},
        ]
        events = [
            {"url":"http://a.onion/","event_type":"changed"},
            {"url":"http://a.onion/","event_type":"changed"},
            {"url":"http://b.onion/","event_type":"new"},
        ]
        result = build_group_activity(pages, events, groups)
        self.assertEqual(result[0]["group"], "Example Group")
        self.assertEqual(result[0]["monitored_sites"], 2)
        self.assertEqual(result[0]["high_risk_sites"], 1)
        self.assertEqual(result[0]["changed_pages"], 2)


if __name__ == "__main__":
    unittest.main()
