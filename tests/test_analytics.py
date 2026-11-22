import unittest
from torwatch.analytics import build_company_radar, build_group_activity, build_incident_correlations, build_executive_summary


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


    def test_correlates_same_company_reports_across_distinct_domains(self):
        alerts = [
            {"matched_assets":"Example Corp","title":"Example Corp hit by ransomware attack","url":"https://news-a.example/story","source":"News A","risk":75,"published":"2026-11-20T10:00:00+00:00","reasons":"incident_term:ransomware"},
            {"matched_assets":"Example Corp","title":"Ransomware attack hits Example Corp","url":"https://news-b.example/report","source":"News B","risk":75,"published":"2026-11-21T10:00:00+00:00","reasons":"incident_term:ransomware"},
        ]
        result = build_incident_correlations(alerts)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["source_count"], 2)
        self.assertIn("独立した裏付けとは限りません", result[0]["caveat"])

    def test_correlation_does_not_merge_different_companies_or_single_domain(self):
        alerts = [
            {"matched_assets":"Example Corp","title":"Example Corp ransomware attack","url":"https://news-a.example/a","risk":75,"published":"2026-11-20","reasons":"ransomware"},
            {"matched_assets":"Other Corp","title":"Other Corp ransomware attack","url":"https://news-b.example/b","risk":75,"published":"2026-11-20","reasons":"ransomware"},
            {"matched_assets":"Example Corp","title":"Example Corp ransomware attack update","url":"https://news-a.example/c","risk":75,"published":"2026-11-20","reasons":"ransomware"},
        ]
        self.assertEqual(build_incident_correlations(alerts), [])

    def test_correlation_ignores_reports_outside_date_window(self):
        alerts = [
            {"matched_assets":"Example Corp","title":"Example Corp ransomware attack","url":"https://news-a.example/a","risk":75,"published":"2026-09-01","reasons":"ransomware"},
            {"matched_assets":"Example Corp","title":"Example Corp ransomware attack","url":"https://news-b.example/b","risk":75,"published":"2026-11-20","reasons":"ransomware"},
        ]
        self.assertEqual(build_incident_correlations(alerts), [])


    def test_executive_summary_explains_critical_findings_without_claiming_confirmation(self):
        summary = build_executive_summary(
            [{"risk":90,"title":"Example leak page","companies":["Example Corp"],"evidence_strength":75}],
            [], [], [], []
        )
        self.assertIn("CRITICAL判定", summary["headline"])
        self.assertEqual(summary["counts"]["critical_pages"], 1)
        self.assertEqual(summary["counts"]["officially_confirmed"], 0)
        self.assertEqual(summary["top_items"][0]["company"], "Example Corp")

    def test_executive_summary_reports_quiet_state_and_collection_errors(self):
        summary = build_executive_summary([], [], [], [{"status":"error"}], [])
        self.assertIn("強い脅威シグナル", summary["headline"])
        self.assertEqual(summary["counts"]["site_errors"], 1)

if __name__ == "__main__":
    unittest.main()
