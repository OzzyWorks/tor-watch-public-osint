import unittest
from torwatch.threat_intel import _matches, _parse_feed, _risk
from torwatch.risk import score
from torwatch.crawler import _candidate_links
from bs4 import BeautifulSoup

class ThreatIntelTests(unittest.TestCase):
    def test_company_name_match_japanese_and_english(self):
        assets={"names":["楽天証券株式会社","SBI SECURITIES Co., Ltd."],"domains":["sbisec.co.jp"]}
        self.assertIn("楽天証券株式会社",_matches("楽天証券株式会社で情報漏えい",assets))
        self.assertIn("sbisec.co.jp",_matches("Notice for sbisec.co.jp",assets))
        self.assertIn("SBI SECURITIES Co., Ltd.",_matches("SBI SECURITIES Co., Ltd. incident",assets))


    def test_rss_risk_requires_incident_terms_near_company(self):
        unrelated = "Sony Group Corporation " + ("ordinary corporate profile " * 80) + " unrelated ransomware report"
        risk, reasons = _risk_near_matches(unrelated, ["Sony Group Corporation"])
        self.assertEqual(risk, 0)

        relevant = "Sony Group Corporation " + ("company update " * 12) + " ransomware data breach exposed customer data"
        risk, reasons = _risk_near_matches(relevant, ["Sony Group Corporation"])
        self.assertEqual(risk, 75)
        self.assertIn("company_context:Sony Group Corporation", reasons)

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

    def test_company_listing_with_data_size_is_medium(self):
        page = "Sekisui House " + ("company profile and business overview " * 8) + "1 TB Data size JP Country"
        risk, reasons = score(page, [], {"names": ["Sekisui House"]})
        self.assertEqual(risk, 55)
        self.assertTrue(any(x.startswith("nearby_claim:data size") for x in reasons))

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
