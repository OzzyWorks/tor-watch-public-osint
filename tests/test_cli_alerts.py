import unittest

from torwatch.cli import _has_relevant_change


class RelevantChangeTests(unittest.TestCase):
    def setUp(self):
        self.old = (
            "http://metaencrypter.onion/",
            "Metaencrypter::Home",
            "old-sha",
            "old page text",
            70,
            "company:Sekisui House | company:SEKISUI HOUSE, LTD. | company:Nippon Steel Corporation",
            "2026-11-20T00:00:00+00:00",
        )

    def test_unrelated_new_victim_card_does_not_realert_existing_companies(self):
        reasons = [
            "company:Sekisui House",
            "company:Nippon Steel Corporation",
            "nearby_breach:leak",
            "nearby_claim:data size",
        ]
        self.assertFalse(_has_relevant_change(self.old, 70, reasons))

    def test_legal_suffix_alias_change_is_not_a_new_company(self):
        reasons = [
            "company:Sekisui House",
            "company:Nippon Steel Corporation",
            "nearby_breach:leak",
        ]
        self.assertFalse(_has_relevant_change(self.old, 70, reasons))

    def test_new_watched_company_is_relevant_even_at_same_risk(self):
        reasons = [
            "company:Sekisui House",
            "company:Nippon Steel Corporation",
            "company:Sony Group Corporation",
        ]
        self.assertTrue(_has_relevant_change(self.old, 70, reasons))

    def test_risk_escalation_is_relevant(self):
        reasons = ["company:Sekisui House"]
        self.assertTrue(_has_relevant_change(self.old, 75, reasons))

    def test_first_observation_is_relevant(self):
        self.assertTrue(_has_relevant_change(None, 70, ["company:Sekisui House"]))


if __name__ == "__main__":
    unittest.main()
