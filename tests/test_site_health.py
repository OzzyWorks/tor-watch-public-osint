import tempfile
import unittest
from pathlib import Path

from torwatch import storage
from torwatch.cli import _classify_fetch_error
from torwatch.crawler import _safe_redirect_target


class SiteHealthTests(unittest.TestCase):
    def setUp(self):
        self.original_db = storage.DB
        self.temp = tempfile.TemporaryDirectory()
        storage.DB = Path(self.temp.name) / "history.db"

    def tearDown(self):
        storage.DB = self.original_db
        self.temp.cleanup()

    def test_fetch_errors_are_not_risk_zero(self):
        self.assertEqual(
            _classify_fetch_error(RuntimeError("0x04: Host unreachable")),
            "onion_unreachable",
        )
        self.assertEqual(
            _classify_fetch_error(RuntimeError("HTTP redirect 302 blocked")),
            "http_redirect",
        )
        self.assertEqual(
            _classify_fetch_error(ValueError("監視対象URLがHTMLを返しません")),
            "non_html_response",
        )

    def test_legacy_page_history_backfills_first_failed_health_record(self):
        url = "http://legacyonion.onion/"
        storage.save(url, "Legacy page", "sha", "body", 0, [])
        last_success = storage.get(url)[6]
        storage.record_site_check(
            url, "error", error_type="timeout", error="connection timed out"
        )
        item = storage.list_site_checks()[0]
        self.assertEqual(item["last_success_at"], last_success)
        self.assertEqual(item["title"], "Legacy page")

    def test_redirect_target_stays_on_same_host_and_html_only(self):
        base = "http://exampleonion.onion/"
        self.assertEqual(
            _safe_redirect_target(base, "/news"),
            "http://exampleonion.onion/news",
        )
        self.assertIsNone(
            _safe_redirect_target(base, "https://evil.example/news")
        )
        self.assertIsNone(
            _safe_redirect_target(base, "/download/leak.zip")
        )
        self.assertIsNone(_safe_redirect_target(base, "/login"))

    def test_site_health_keeps_failures_separate_and_resets_on_success(self):
        url = "http://exampleonion.onion/"
        storage.record_site_check(url, "ok", title="Example")
        first = storage.list_site_checks()[0]
        last_success = first["last_success_at"]

        storage.record_site_check(
            url, "error", error_type="timeout", error="connection timed out"
        )
        failed = storage.list_site_checks()[0]
        self.assertEqual(failed["status"], "error")
        self.assertEqual(failed["consecutive_errors"], 1)
        self.assertEqual(failed["last_success_at"], last_success)
        self.assertEqual(failed["error_type"], "timeout")

        storage.record_site_check(
            url, "error", error_type="timeout", error="connection timed out"
        )
        failed_again = storage.list_site_checks()[0]
        self.assertEqual(failed_again["consecutive_errors"], 2)

        storage.record_site_check(url, "ok", title="Example")
        recovered = storage.list_site_checks()[0]
        self.assertEqual(recovered["status"], "ok")
        self.assertEqual(recovered["consecutive_errors"], 0)
        self.assertEqual(recovered["error"], "")
        self.assertEqual(recovered["last_success_at"], recovered["checked_at"])


if __name__ == "__main__":
    unittest.main()
