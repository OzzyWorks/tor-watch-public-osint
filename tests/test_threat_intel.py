import unittest
from torwatch.threat_intel import _matches, _parse_feed, _risk, _risk_near_matches
from torwatch.risk import score, assess_evidence
from torwatch.crawler import _candidate_links
from bs4 import BeautifulSoup

class ThreatIntelTests(unittest.TestCase):
    def test_evidence_strength_is_separate_from_risk_and_never_confirms_breach(self):
        name_only=assess_evidence(["company:Example Corp"])
        self.assertEqual(name_only["evidence_strength"],15)
        self.assertIn("企業名の一致のみ",name_only["evidence_status"])
        claim=assess_evidence(["company:Example Corp","nearby_claim:data size"])
        self.assertEqual(claim["evidence_strength"],40)
        self.assertIn("未確認",claim["evidence_status"])
        breach=assess_evidence(["company:Example Corp","nearby_breach:leak","nearby_data:customer data"])
        self.assertEqual(breach["evidence_strength"],75)
        self.assertFalse(breach["officially_confirmed"])

    def test_public_report_is_not_treated_as_official_confirmation(self):
        result=assess_evidence(["company_match:Example Corp","incident_term:ransomware"],"public_report")
        self.assertIn("公開報道",result["evidence_status"])
        self.assertFalse(result["officially_confirmed"])

    def test_company_name_match_japanese_and_english(self):
        assets={"names":["楽天証券株式会社","SBI SECURITIES Co., Ltd."],"domains":["sbisec.co.jp"]}
        self.assertIn("楽天証券株式会社",_matches("楽天証券株式会社で情報漏えい",assets))
        self.assertIn("sbisec.co.jp",_matches("Notice for sbisec.co.jp",assets))
        self.assertIn("SBI SECURITIES Co., Ltd.",_matches("SBI SECURITIES Co., Ltd. incident",assets))


    def test_english_legal_suffix_aliases_are_deduplicated(self):
        assets={"names":[
            "Sekisui House","SEKISUI HOUSE, LTD.",
            "Nippon Steel Corporation","NIPPON STEEL CORP.",
        ]}
        text="Sekisui House SEKISUI HOUSE, LTD. Nippon Steel Corporation NIPPON STEEL CORP. ransomware leak data size"
        matches=_matches(text,assets)
        self.assertEqual(matches,["Sekisui House","Nippon Steel Corporation"])
        _,reasons=score(text,[],assets)
        companies=[x for x in reasons if x.startswith("company:")]
        self.assertEqual(companies,[
            "company:Sekisui House","company:Nippon Steel Corporation"
        ])

    def test_rss_risk_requires_incident_terms_near_company(self):
        unrelated = "Sony Group Corporation " + ("ordinary corporate profile " * 80) + " unrelated ransomware report"
        risk, reasons = _risk_near_matches(unrelated, ["Sony Group Corporation"])
        self.assertEqual(risk, 0)

        relevant = "Sony Group Corporation " + ("company update " * 12) + " ransomware data breach exposed customer data"
        risk, reasons = _risk_near_matches(relevant, ["Sony Group Corporation"])
        self.assertEqual(risk, 75)
        self.assertIn("company_context:Sony Group Corporation", reasons)

    def test_rss_risk_ignores_incident_terms_far_from_company_name(self):
        far = "DTS Corporation " + ("ordinary corporate profile " * 25) + " unrelated ransomware data breach"
        risk, reasons = _risk_near_matches(far, ["DTS Corporation"])
        self.assertEqual(risk, 0)
        self.assertNotIn("company_context:DTS Corporation", reasons)

        near = "DTS Corporation " + ("ordinary corporate profile " * 5) + " ransomware data breach"
        risk, reasons = _risk_near_matches(near, ["DTS Corporation"])
        self.assertEqual(risk, 75)
        self.assertIn("company_context:DTS Corporation", reasons)

    def test_rss_risk_is_attributed_only_to_company_near_incident_terms(self):
        text = (
            "Sony Group Corporation "
            + ("ordinary company profile " * 65)
            + "Sekisui House ransomware data breach exposed customer data"
        )
        risk, reasons = _risk_near_matches(
            text, ["Sony Group Corporation", "Sekisui House"]
        )
        self.assertEqual(risk, 75)
        self.assertIn("company_context:Sekisui House", reasons)
        self.assertNotIn("company_context:Sony Group Corporation", reasons)

    def test_risk_requires_incident_language(self):
        score,_=_risk("Oracle software vulnerability advisory")
        self.assertEqual(score,0)
        score,reasons=_risk("Japanese company ransomware data leak report")
        self.assertGreaterEqual(score,70)
        self.assertTrue(reasons)

    def test_company_context_risk_levels(self):
        assets={"names":["Sekisui House","Nippon Steel Corporation"]}
        risk,reasons=score("Sekisui House ransomware leak customer database employee personal data",[],assets)
        self.assertEqual(risk,90)
        self.assertIn("company:Sekisui House",reasons)
        self.assertTrue(any(x.startswith("nearby_breach:") for x in reasons))

    def test_high_risk_evidence_is_not_attributed_to_other_companies_on_same_page(self):
        page = (
            "Sekisui House ransomware leak customer database employee personal data. "
            + ("ordinary company profile " * 50)
            + "Sony Group Corporation announced an ordinary office update."
        )
        risk, reasons = score(
            page, [],
            {"names": ["Sekisui House", "Sony Group Corporation"]}
        )
        self.assertEqual(risk, 90)
        self.assertIn("company:Sekisui House", reasons)
        self.assertNotIn("company:Sony Group Corporation", reasons)

    def test_company_listing_with_data_size_is_medium(self):
        page = "Sekisui House " + ("company profile and business overview " * 8) + "1 TB Data size JP Country"
        risk, reasons = score(page, [], {"names": ["Sekisui House"]})
        self.assertEqual(risk, 55)
        self.assertTrue(any(x.startswith("nearby_claim:data size") for x in reasons))

    def test_risk_evidence_does_not_cross_crawled_page_boundaries(self):
        # A company on the landing page and breach terms on a separate detail
        # page must not be combined into a false HIGH/CRITICAL match.
        page = (
            "Sekisui House corporate profile and company overview "
            "\n\n[TORWATCH_PAGE_BOUNDARY]\n\n"
            "unrelated ransomware leak customer database employee personal data"
        )
        risk, reasons = score(page, [], {"names": ["Sekisui House"]})
        self.assertEqual(risk, 20)
        self.assertIn("company:Sekisui House", reasons)

    def test_risk_evidence_within_one_page_still_scores_high(self):
        page = (
            "Sekisui House ransomware leak customer database employee personal data"
        )
        risk, reasons = score(page, [], {"names": ["Sekisui House"]})
        self.assertEqual(risk, 90)
        self.assertTrue(any(x.startswith("nearby_breach:") for x in reasons))

    def test_generic_employee_and_client_words_do_not_make_critical(self):
        page = "Former clients and employees. Sekisui House " + ("company profile " * 10) + "1 TB Data size leak"
        risk, reasons = score(page, [], {"names": ["Sekisui House"]})
        self.assertEqual(risk, 70)
        self.assertFalse(any(x.startswith("nearby_data:") for x in reasons))

    def test_company_name_alone_is_not_high(self):
        risk,reasons=score("Sekisui House announced a new office.",[],{"names":["Sekisui House"]})
        self.assertLess(risk,70)
        self.assertIn("company:Sekisui House",reasons)

    def test_unrelated_keywords_cannot_make_company_critical(self):
        risk,_=score("database leak customer employee credit card",[],{"names":["Sekisui House"]})
        self.assertLess(risk,70)


    def test_japanese_company_name_requires_nearby_breach_and_data_context(self):
        name_only = "株式会社日立製作所が新サービスを発表しました。"
        risk, reasons = score(name_only, [], {"names": ["株式会社日立製作所"]})
        self.assertEqual(risk, 20)
        self.assertIn("company:株式会社日立製作所", reasons)

        incident = "株式会社日立製作所 ランサムウェア攻撃により顧客情報と従業員情報が流出したと主張"
        risk, reasons = score(incident, [], {"names": ["株式会社日立製作所"]})
        self.assertEqual(risk, 90)
        self.assertIn("company:株式会社日立製作所", reasons)
        self.assertTrue(any(x.startswith("nearby_breach:") for x in reasons))
        self.assertTrue(any(x.startswith("nearby_data:") for x in reasons))

    def test_rss_japanese_multi_company_article_attributes_incident_only_to_nearby_company(self):
        article = (
            "ソニーグループ株式会社は新製品を発表しました。"
            + ("通常の企業ニュースです。" * 30)
            + "株式会社日立製作所でランサムウェアによる情報漏えいが発生したと報じられました。"
        )
        risk, reasons = _risk_near_matches(
            article, ["ソニーグループ株式会社", "株式会社日立製作所"]
        )
        self.assertEqual(risk, 75)
        self.assertIn("company_context:株式会社日立製作所", reasons)
        self.assertNotIn("company_context:ソニーグループ株式会社", reasons)

    def test_rss_company_name_without_incident_language_is_not_alerted(self):
        article = "株式会社DTSは新しい人事制度を発表しました。業績説明会を開催します。"
        matches = _matches(article, {"names": ["株式会社DTS"]})
        self.assertEqual(matches, ["株式会社DTS"])
        risk, reasons = _risk_near_matches(article, matches)
        self.assertEqual(risk, 0)
        self.assertNotIn("company_context:株式会社DTS", reasons)

    def test_detail_crawler_only_follows_same_host_html_links(self):
        html = """<html><body>
        <a href="/post/123">Victim announcement</a>
        <a href="https://evil.example/post/2">external</a>
        <a href="/download/customer-dump.zip">archive</a>
        <a href="/files/database.sql">database</a>
        <a href="/login">login</a>
        <a href="#top">anchor</a>
        </body></html>"""
        soup = BeautifulSoup(html, "html.parser")
        links = _candidate_links("http://exampleonion.onion/", soup)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0][0], "http://exampleonion.onion/post/123")
        self.assertEqual(links[0][1], "Victim announcement")

    def test_parse_rss(self):
        xml=b'''<?xml version="1.0"?><rss version="2.0"><channel><item>
        <title>Company data breach</title><link>https://example.com/a</link>
        <description>Ransomware incident</description><guid>item-1</guid>
        <pubDate>Wed, 18 Nov 2026 10:00:00 GMT</pubDate>
        </item></channel></rss>'''
        items=_parse_feed(xml)
        self.assertEqual(len(items),1)
        self.assertEqual(items[0]["url"],"https://example.com/a")
        self.assertIn("Ransomware",items[0]["summary"])

    def test_parse_atom(self):
        xml=b'''<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
        <entry><title>Security incident</title><link href="https://example.com/b"/>
        <summary>Data breach</summary><id>tag:example.com,2026:b</id></entry></feed>'''
        items=_parse_feed(xml)
        self.assertEqual(items[0]["url"],"https://example.com/b")

if __name__=="__main__":
    unittest.main()
