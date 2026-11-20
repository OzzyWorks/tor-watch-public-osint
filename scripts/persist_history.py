"""Merge SQLite monitoring state with origin/main before committing it.

SQLite databases are binary files and cannot be rebased by Git. This script
merges rows from the runner's scan and the latest remote database, then retries
a push if main advances while the commit is being published.
"""
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path

DB = Path("data/history.db")
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"


def run(*args, check=True, capture=False):
    return subprocess.run(
        args, check=check, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def merge_databases(remote_path, local_path, output_path):
    if remote_path.exists() and remote_path.stat().st_size:
        shutil.copy2(remote_path, output_path)
    else:
        shutil.copy2(local_path, output_path)

    con = sqlite3.connect(output_path)
    con.row_factory = sqlite3.Row
    local = sqlite3.connect(local_path)
    local.row_factory = sqlite3.Row
    con.execute("""CREATE TABLE IF NOT EXISTS site_checks(
        url TEXT PRIMARY KEY, status TEXT NOT NULL, title TEXT NOT NULL DEFAULT '',
        error_type TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '',
        checked_at TEXT NOT NULL, last_success_at TEXT,
        consecutive_errors INTEGER NOT NULL DEFAULT 0)""")

    # Keep the newest observation for each monitored URL.
    for row in local.execute("SELECT url,title,sha256,text,risk,reasons,checked_at FROM pages"):
        con.execute("""INSERT INTO pages(url,title,sha256,text,risk,reasons,checked_at)
            VALUES(?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET
            title=excluded.title, sha256=excluded.sha256, text=excluded.text,
            risk=excluded.risk, reasons=excluded.reasons, checked_at=excluded.checked_at
            WHERE COALESCE(excluded.checked_at,'') >= COALESCE(pages.checked_at,'')""",
            tuple(row))

    # Events have independent autoincrement IDs in each runner. Deduplicate by
    # their natural event identity and let SQLite allocate a fresh ID.
    for row in local.execute("SELECT url,title,event_type,risk,reasons,diff,detected_at FROM events"):
        exists = con.execute("""SELECT 1 FROM events
            WHERE url=? AND event_type=? AND detected_at=? LIMIT 1""",
            (row["url"], row["event_type"], row["detected_at"])).fetchone()
        if not exists:
            con.execute("""INSERT INTO events(url,title,event_type,risk,reasons,diff,detected_at)
                VALUES(?,?,?,?,?,?,?)""", tuple(row))

    # Threat items have stable content-derived IDs.
    for row in local.execute("""SELECT id,source,title,url,published,matched_assets,
        risk,reasons,status,detected_at FROM threat_items"""):
        con.execute("""INSERT OR IGNORE INTO threat_items
            (id,source,title,url,published,matched_assets,risk,reasons,status,detected_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)""", tuple(row))

    # Keep the latest per-site fetch status independently from risk observations.
    try:
        site_rows=local.execute("""SELECT url,status,title,error_type,error,checked_at,
            last_success_at,consecutive_errors FROM site_checks""").fetchall()
    except sqlite3.OperationalError:
        site_rows=[]
    for row in site_rows:
        con.execute("""INSERT INTO site_checks
            (url,status,title,error_type,error,checked_at,last_success_at,consecutive_errors)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(url) DO UPDATE SET
            status=excluded.status,title=excluded.title,error_type=excluded.error_type,
            error=excluded.error,checked_at=excluded.checked_at,
            last_success_at=excluded.last_success_at,
            consecutive_errors=excluded.consecutive_errors
            WHERE COALESCE(excluded.checked_at,'') >= COALESCE(site_checks.checked_at,'')""",
            tuple(row))

    # Preserve sent state if either copy has delivered the notification.
    for row in local.execute("""SELECT id,message,status,attempts,created_at,sent_at,last_error
        FROM notification_queue"""):
        existing = con.execute("SELECT status,attempts,sent_at,last_error FROM notification_queue WHERE id=?",
                               (row["id"],)).fetchone()
        if not existing:
            con.execute("""INSERT INTO notification_queue
                (id,message,status,attempts,created_at,sent_at,last_error)
                VALUES(?,?,?,?,?,?,?)""", tuple(row))
        else:
            status = "sent" if "sent" in (existing["status"], row["status"]) else "pending"
            attempts = max(existing["attempts"] or 0, row["attempts"] or 0)
            sent_at = max(existing["sent_at"] or "", row["sent_at"] or "") or None
            last_error = row["last_error"] or existing["last_error"]
            con.execute("""UPDATE notification_queue SET status=?,attempts=?,sent_at=?,last_error=?
                WHERE id=?""", (status, attempts, sent_at, last_error, row["id"]))

    con.commit()
    con.execute("PRAGMA wal_checkpoint(FULL)")
    local.close()
    con.close()


def main():
    DB.parent.mkdir(parents=True, exist_ok=True)
    if not DB.exists():
        raise SystemExit("Monitoring database is missing; refusing to overwrite history.")

    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        snapshot = temp / "runner.db"
        shutil.copy2(DB, snapshot)

        run("git", "config", "user.name", BOT_NAME)
        run("git", "config", "user.email", BOT_EMAIL)

        for attempt in range(1, 4):
            print(f"Persist attempt {attempt}/3")
            run("git", "fetch", "origin", "main")
            remote = temp / "remote.db"
            result = subprocess.run(
                ["git", "show", "origin/main:data/history.db"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            if result.returncode == 0:
                remote.write_bytes(result.stdout)
            else:
                remote.unlink(missing_ok=True)

            merged = temp / "merged.db"
            merge_databases(remote, snapshot, merged)
            shutil.copy2(merged, snapshot)

            run("git", "reset", "--hard", "origin/main")
            DB.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(merged, DB)
            run("git", "add", "data/history.db")
            diff = run("git", "diff", "--cached", "--quiet", check=False)
            if diff.returncode == 0:
                print("Monitoring database unchanged")
                return
            run("git", "commit", "-m", "Persist Tor Watch monitoring state [skip ci]")
            pushed = run("git", "push", "origin", "HEAD:main", check=False)
            if pushed.returncode == 0:
                print("Monitoring database merged and pushed successfully")
                return
            print("Push raced with another update; retrying with latest main")

        raise SystemExit("Could not persist monitoring database after 3 attempts.")


if __name__ == "__main__":
    main()
