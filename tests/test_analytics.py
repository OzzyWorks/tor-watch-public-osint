import unittest
from torwatch.analytics import build_company_radar, build_group_activity, build_incident_correlations, build_executive_summary, explain_public_alert, build_company_timeline


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

    def test_company_radar_deduplicates_same_public_headline(self):
        pages=[{"url":"http://a.onion/","risk":50,"reasons":"company:Example Corp","checked_at":"2026-11-22"}]
        alerts=[
            {"matched_assets":"Example Corp","title":"Example Corp ransomware incident","url":"https://news-a.example/a"},
            {"matched_assets":"Example Corp","title":"Example Corp ransomware incident","url":"https://news-b.example/b"},
            {"matched_assets":"Example Corp","title":"A different Example Corp data breach","url":"https://news-c.example/c"},
        ]
        result=build_company_radar(pages,[],alerts)
        self.assertEqual(result[0]["public_reports"],2)

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


    def test_company_timeline_groups_events_and_deduplicates_repeated_public_headlines(self):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        events = [
            {"event_type":"new","url":"http://leak.example/post","title":"Example Corp listing",
             "reasons":"company:Example Corp","detected_at":now},
            {"event_type":"changed","url":"http://leak.example/post","title":"Example Corp listing",
             "reasons":"company:Example Corp","detected_at":now},
        ]
        alerts = [
            {"matched_assets":"Example Corp","title":"Example Corp hit by ransomware",
             "url":"https://news-a.example/a","source":"News A","published":now},
            {"matched_assets":"Example Corp","title":"Example Corp hit by ransomware",
             "url":"https://news-b.example/b","source":"News B","published":now},
        ]
        result = build_company_timeline(events, alerts)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["company"], "Example Corp")
        self.assertEqual(len(result[0]["items"]), 3)
        public = [x for x in result[0]["items"] if x["type"] == "public_report"]
        self.assertEqual(len(public), 1)
        self.assertEqual(len(public[0]["urls"]), 2)

    def test_public_alert_explanation_distinguishes_name_match_from_breach_claim(self):
        name_only = explain_public_alert({"matched_assets":"Example Corp","evidence_strength":15})
        self.assertIn("企業名が登場", name_only["plain_explanation"])
        self.assertIn("対応不要", name_only["recommended_action"])
        breach = explain_public_alert({"matched_assets":"Example Corp","evidence_strength":75})
        self.assertIn("漏洩・侵害関連", breach["plain_explanation"])
        self.assertIn("確定ではありません", breach["plain_explanation"])
        self.assertIn("企業公式", breach["recommended_action"])
        self.assertEqual(breach["matched_company_text"], "Example Corp")

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

    def test_executive_summary_describes_recent_changes(self):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        summary = build_executive_summary(
            [], [{"event_type":"new","url":"https://example.onion/","title":"Example Corp listed",
                  "risk":78,"reasons":"company:Example Corp","detected_at":now}],
            [], [], []
        )
        self.assertEqual(summary["changes_24h"]["total"], 1)
        self.assertEqual(summary["changes_24h"]["counts"]["new"], 1)
        self.assertEqual(summary["changes_24h"]["items"][0]["company"], "Example Corp")

    def test_executive_summary_prioritizes_critical_page_over_public_feed_noise(self):
        summary = build_executive_summary(
            [{"risk":92,"title":"Critical leak listing","url":"http://critical.onion/",
              "companies":["Example Corp"],"evidence_strength":90}],
            [],
            [
                {"matched_assets":"Example Corp","title":"Company mentioned in general article",
                 "url":"https://news.example/a","risk":99,"evidence_strength":10,
                 "evidence_status":"企業名一致のみ"},
                {"matched_assets":"Example Corp","title":"Another unrelated mention",
                 "url":"https://news.example/b","risk":95,"evidence_strength":5,
                 "evidence_status":"企業名一致のみ"},
                {"matched_assets":"Example Corp","title":"Third unrelated mention",
                 "url":"https://news.example/c","risk":90,"evidence_strength":0,
                 "evidence_status":"関連未確認"},
            ],
            [], []
        )
        self.assertEqual(summary["top_items"][0]["kind"], "公開リークサイト監視")
        self.assertEqual(summary["top_items"][0]["title"], "Critical leak listing")


    def test_executive_summary_separates_name_only_from_incident_evidence(self):
        summary = build_executive_summary(
            [], [], [
                {"matched_assets": "Example Corp", "title": "Company mentioned",
                 "risk": 90, "evidence_strength": 10},
                {"matched_assets": "Example Corp", "title": "Company and data size",
                 "risk": 70, "evidence_strength": 30},
                {"matched_assets": "Example Corp", "title": "Company breach report",
                 "risk": 80, "evidence_strength": 65},
            ], [], []
        )
        counts = summary["counts"]
        self.assertEqual(counts["name_only_matches"], 1)
        self.assertEqual(counts["contextual_matches"], 1)
        self.assertEqual(counts["incident_related_mentions"], 1)

if __name__ == "__main__":
    unittest.main()
