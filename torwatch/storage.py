import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB = Path(__file__).resolve().parent.parent / "data" / "history.db"

def init():
    DB.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS pages(
        url TEXT PRIMARY KEY, title TEXT, sha256 TEXT, text TEXT,
        risk INTEGER, reasons TEXT, checked_at TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, title TEXT,
        event_type TEXT, risk INTEGER, reasons TEXT, diff TEXT,
        detected_at TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS threat_items(
        id TEXT PRIMARY KEY, source TEXT, title TEXT, url TEXT,
        published TEXT, matched_assets TEXT, risk INTEGER,
        reasons TEXT, status TEXT, detected_at TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS notification_queue(
        id TEXT PRIMARY KEY, message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
        attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
        sent_at TEXT, last_error TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS site_checks(
        url TEXT PRIMARY KEY, status TEXT NOT NULL, title TEXT NOT NULL DEFAULT '',
        error_type TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '',
        checked_at TEXT NOT NULL, last_success_at TEXT,
        consecutive_errors INTEGER NOT NULL DEFAULT 0)""")
    con.commit()
    return con

def get(url):
    con=init()
    row=con.execute("SELECT url,title,sha256,text,risk,reasons,checked_at FROM pages WHERE url=?",(url,)).fetchone()
    con.close()
    return row

def record_site_check(url,status,title="",error_type="",error=""):
    """Record fetch health separately from a page's risk score."""
    con=init()
    now=datetime.now(timezone.utc).isoformat()
    previous=con.execute(
        "SELECT last_success_at,consecutive_errors,title FROM site_checks WHERE url=?",
        (url,)
    ).fetchone()
    if status == "ok":
        last_success_at=now
        consecutive_errors=0
        error_type=""
        error=""
    else:
        # Backfill the first health record from the last successful page scan
        # created before the site_checks table existed.
        prior_page=con.execute("SELECT checked_at,title FROM pages WHERE url=?",(url,)).fetchone()
        last_success_at=(previous[0] if previous and previous[0] else
                         (prior_page[0] if prior_page else None))
        consecutive_errors=(int(previous[1] or 0)+1) if previous else 1
    prior_page=con.execute("SELECT checked_at,title FROM pages WHERE url=?",(url,)).fetchone()
    stored_title=title or (previous[2] if previous else "") or (prior_page[1] if prior_page else "")
    con.execute("""INSERT INTO site_checks
        (url,status,title,error_type,error,checked_at,last_success_at,consecutive_errors)
        VALUES(?,?,?,?,?,?,?,?)
        ON CONFLICT(url) DO UPDATE SET
        status=excluded.status,
        title=CASE WHEN excluded.title<>'' THEN excluded.title ELSE site_checks.title END,
        error_type=excluded.error_type,error=excluded.error,
        checked_at=excluded.checked_at,last_success_at=excluded.last_success_at,
        consecutive_errors=excluded.consecutive_errors""",
        (url,status,stored_title,error_type,str(error)[:400],now,last_success_at,consecutive_errors))
    con.commit()
    con.close()

def list_site_checks(limit=200):
    con=init()
    rows=con.execute("""SELECT url,status,title,error_type,error,checked_at,
        last_success_at,consecutive_errors FROM site_checks
        ORDER BY CASE WHEN status='error' THEN 0 ELSE 1 END,
        consecutive_errors DESC,checked_at DESC LIMIT ?""",(limit,)).fetchall()
    con.close()
    keys=("url","status","title","error_type","error","checked_at",
          "last_success_at","consecutive_errors")
    return [dict(zip(keys,row)) for row in rows]

def save(url,title,sha,text,risk,reasons):
    con=init()
    con.execute("""INSERT INTO pages VALUES(?,?,?,?,?,?,?)
        ON CONFLICT(url) DO UPDATE SET title=excluded.title,
        sha256=excluded.sha256,text=excluded.text,risk=excluded.risk,
        reasons=excluded.reasons,checked_at=excluded.checked_at""",
        (url,title,sha,text,risk," | ".join(reasons),
         datetime.now(timezone.utc).isoformat()))
    con.commit()
    con.close()

def add_event(url,title,event_type,risk,reasons,diff=""):
    con=init()
    con.execute("""INSERT INTO events(url,title,event_type,risk,reasons,diff,detected_at)
        VALUES(?,?,?,?,?,?,?)""",
        (url,title,event_type,risk," | ".join(reasons),diff,
         datetime.now(timezone.utc).isoformat()))
    con.commit()
    con.close()

def enqueue_notification(notification_id, message):
    con=init()
    cur=con.execute("""INSERT OR IGNORE INTO notification_queue
        (id,message,status,attempts,created_at) VALUES(?,?,'pending',0,?)""",
        (notification_id,message,datetime.now(timezone.utc).isoformat()))
    inserted=cur.rowcount == 1
    con.commit()
    con.close()
    return inserted

def pending_notifications(limit=30):
    con=init()
    rows=con.execute("""SELECT id,message,attempts FROM notification_queue
        WHERE status='pending' ORDER BY created_at LIMIT ?""",(limit,)).fetchall()
    con.close()
    return [{"id":r[0],"message":r[1],"attempts":r[2]} for r in rows]

def mark_notification_sent(notification_id):
    con=init()
    con.execute("""UPDATE notification_queue SET status='sent',sent_at=?,last_error=NULL
        WHERE id=?""",(datetime.now(timezone.utc).isoformat(),notification_id))
    con.commit()
    con.close()

def mark_notification_failed(notification_id,error):
    con=init()
    con.execute("""UPDATE notification_queue SET attempts=attempts+1,last_error=?
        WHERE id=?""",(str(error)[:500],notification_id))
    con.commit()
    con.close()

def add_threat_item(item):
    con=init()
    cur=con.execute("""INSERT OR IGNORE INTO threat_items
        (id,source,title,url,published,matched_assets,risk,reasons,status,detected_at)
        VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (item["id"],item["source"],item["title"],item["url"],
         item.get("published","")," | ".join(item["matched_assets"]),
         item["risk"]," | ".join(item["reasons"]),item["status"],
         datetime.now(timezone.utc).isoformat()))
    inserted=cur.rowcount == 1
    con.commit()
    con.close()
    return inserted

def list_threat_items(limit=100):
    con=init()
    rows=con.execute("""SELECT id,source,title,url,published,matched_assets,
        risk,reasons,status,detected_at FROM threat_items
        ORDER BY detected_at DESC LIMIT ?""",(limit,)).fetchall()
    con.close()
    keys=("id","source","title","url","published","matched_assets",
          "risk","reasons","status","detected_at")
    return [dict(zip(keys,row)) for row in rows]
