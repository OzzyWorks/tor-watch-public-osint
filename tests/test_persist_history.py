import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.persist_history import merge_databases
from torwatch.intelligence_storage import init, save_observation, upsert_source
from torwatch.evidence_assessment import record_evidence


LEGACY_SCHEMA = """
CREATE TABLE pages(url TEXT PRIMARY KEY,title TEXT,sha256 TEXT,text TEXT,risk INTEGER,reasons TEXT,checked_at TEXT);
CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,url TEXT,title TEXT,event_type TEXT,risk INTEGER,reasons TEXT,diff TEXT,detected_at TEXT);
CREATE TABLE threat_items(id TEXT PRIMARY KEY,source TEXT,title TEXT,url TEXT,published TEXT,matched_assets TEXT,risk INTEGER,reasons TEXT,status TEXT,detected_at TEXT);
CREATE TABLE notification_queue(id TEXT PRIMARY KEY,message TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,sent_at TEXT,last_error TEXT);
"""


class PersistHistoryTests(unittest.TestCase):
    def test_database_merge_preserves_legacy_and_intelligence_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = root / "remote.db"
            local = root / "local.db"
            output = root / "merged.db"

            for path in (remote, local):
                con = sqlite3.connect(path)
                con.executescript(LEGACY_SCHEMA)
                con.commit()
                con.close()
            con = sqlite3.connect(remote)
            con.execute("""CREATE TABLE feed_checks(source_id TEXT PRIMARY KEY,name TEXT NOT NULL,status TEXT NOT NULL,item_count INTEGER NOT NULL DEFAULT 0,new_alerts INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',checked_at TEXT NOT NULL,last_success_at TEXT,consecutive_errors INTEGER NOT NULL DEFAULT 0)""")
            con.execute("INSERT INTO feed_checks VALUES('feed-old','Old Feed','ok',12,0,'','2026-01-01','2026-01-01',0)")
            con.execute("INSERT INTO pages(url,title,checked_at) VALUES('https://old.example','Old','2026-01-01')")
            con.commit()
            con.close()
            con = sqlite3.connect(local)
            con.execute("""CREATE TABLE feed_checks(source_id TEXT PRIMARY KEY,name TEXT NOT NULL,status TEXT NOT NULL,item_count INTEGER NOT NULL DEFAULT 0,new_alerts INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',checked_at TEXT NOT NULL,last_success_at TEXT,consecutive_errors INTEGER NOT NULL DEFAULT 0)""")
            con.execute("INSERT INTO feed_checks VALUES('feed-new','New Feed','error',0,0,'timeout','2026-01-02','2026-01-01',1)")
            con.execute("INSERT INTO pages(url,title,checked_at) VALUES('https://new.example','New','2026-01-02')")
            con.commit()
            con.close()

            upsert_source({
                "id": "source-a", "name": "Source A", "source_class": "media",
                "provenance_group": "origin-a",
            }, local)
            save_observation({
                "observation_id": "OBS-PERSIST", "source_id": "source-a",
                "source_class": "media", "title": "Example ransomware incident",
                "assertion_type": "media_report",
            }, local)
            con = init(local)
            con.execute("""
                INSERT INTO incidents(incident_id,victim,status,created_at,updated_at)
                VALUES('INC-PERSIST','Example Corp','candidate','2026-01-01','2026-01-01')
            """)
            con.commit()
            con.close()
            record_evidence(
                "INC-PERSIST", "OBS-PERSIST", "media_report", "origin-a",
                "Public report", 60, "Source report", local,
            )

            merge_databases(remote, local, output)

            con = sqlite3.connect(output)
            feeds = {row[0]: row[1] for row in con.execute("SELECT source_id,status FROM feed_checks")}
            self.assertEqual(feeds, {"feed-old": "ok", "feed-new": "error"})
            pages = {row[0] for row in con.execute("SELECT url FROM pages")}
            self.assertEqual(pages, {"https://old.example", "https://new.example"})
            self.assertEqual(con.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 1)
            con.close()


if __name__ == "__main__":
    unittest.main()
