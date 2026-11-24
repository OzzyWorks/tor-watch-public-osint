import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from torwatch import threat_intel


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size):
        yield self.payload


class FakeSession:
    def __init__(self):
        self.headers = {}
        self.calls = 0

    def get(self, url, timeout, stream):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("simulated source outage")
        return FakeResponse(b"""<?xml version="1.0"?>
        <rss><channel><item>
          <title>Example Corp confirms ransomware data breach</title>
          <link>https://news.example/incident</link>
          <guid>incident-1</guid>
          <pubDate>Sun, 23 Nov 2026 10:00:00 GMT</pubDate>
        </item></channel></rss>""")


class SourceFailureIsolationTests(unittest.TestCase):
    def test_one_failed_feed_does_not_block_later_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp)
            (config_dir / "sources.yml").write_text(yaml.safe_dump({
                "sources": [
                    {"id": "down", "name": "Down Feed", "url": "https://down.example/rss"},
                    {"id": "healthy", "name": "Healthy Feed", "url": "https://healthy.example/rss"},
                ]
            }), encoding="utf-8")
            fake_session = FakeSession()
            with patch.object(threat_intel, "CONFIG", config_dir), \
                 patch.object(threat_intel, "load_assets", return_value={
                     "assets": {"names": ["Example Corp"]}
                 }), \
                 patch.object(threat_intel.requests, "Session", return_value=fake_session), \
                 patch.object(threat_intel, "record_feed_check") as record_health, \
                 patch.object(threat_intel, "add_threat_item", return_value=True), \
                 patch.object(threat_intel, "enqueue_notification", return_value=False):
                results = threat_intel.run_public_monitor()

        self.assertIn("error", results[0])
        self.assertEqual(results[1]["source"], "Healthy Feed")
        self.assertEqual(results[1]["new_alerts"], 1)
        self.assertEqual(fake_session.calls, 2)
        self.assertEqual(record_health.call_count, 2)
        self.assertEqual(record_health.call_args_list[0].args[2], "error")
        self.assertEqual(record_health.call_args_list[1].args[2], "ok")


if __name__ == "__main__":
    unittest.main()
