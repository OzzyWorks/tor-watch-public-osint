import unittest
from torwatch.threat_intel import _matches, _parse_feed, _risk\nfrom torwatch.risk import score

class ThreatIntelTests(unittest.TestCase):
    def test_company_name_match_japanese_and_english(self):
        assets={"names":["楽天証券株式会社","SBI SECURITIES Co., Ltd."],"domains":["sbisec.co.jp"]}
        self.assertIn("楽天証券株式会社",_matches("楽天証券株式会社で情報漏えい",assets))
        self.assertIn("sbisec.co.jp",_matches("Notice for sbisec.co.jp",assets))
        self.assertIn("SBI SECURITIES Co., Ltd.",_matches("SBI SECURITIES Co., Ltd. incident",assets))

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

    def test_company_name_alone_is_not_high(self):
        risk,reasons=score("Sekisui House announced a new office.",[],{"names":["Sekisui House"]})
        self.assertLess(risk,70)
        self.assertIn("company:Sekisui House",reasons)

    def test_unrelated_keywords_cannot_make_company_critical(self):
        risk,_=score("database leak customer employee credit card",[],{"names":["Sekisui House"]})
        self.assertLess(risk,70)

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
