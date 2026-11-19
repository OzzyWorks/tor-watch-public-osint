import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB = Path(__file__).resolve().parent.parent / "data" / "history.db"

def init():
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS pages(
        url TEXT PRIMARY KEY, title TEXT, sha256 TEXT, text TEXT,
        risk INTEGER, reasons TEXT, checked_at TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, title TEXT,
        event_type TEXT, risk INTEGER, reasons TEXT, diff TEXT,
        detected_at TEXT)""")
    con.commit()
    return con

def get(url):
    con=init()
    row=con.execute("SELECT url,title,sha256,text,risk,reasons,checked_at FROM pages WHERE url=?",(url,)).fetchone()
    con.close()
    return row

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
