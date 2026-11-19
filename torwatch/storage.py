import sqlite3
from pathlib import Path
from datetime import datetime,timezone
DB=Path(__file__).resolve().parent.parent/"data"/"history.db"
def init():
    c=sqlite3.connect(DB); c.execute("CREATE TABLE IF NOT EXISTS pages(url TEXT PRIMARY KEY,title TEXT,sha256 TEXT,text TEXT,risk INTEGER,reasons TEXT,checked_at TEXT)"); c.commit(); return c
def get(url):
    c=init(); r=c.execute("SELECT url,title,sha256,text,risk,reasons,checked_at FROM pages WHERE url=?",(url,)).fetchone(); c.close(); return r
def save(url,title,sha,text,risk,reasons):
    c=init(); c.execute("INSERT INTO pages VALUES(?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET title=excluded.title,sha256=excluded.sha256,text=excluded.text,risk=excluded.risk,reasons=excluded.reasons,checked_at=excluded.checked_at",(url,title,sha,text,risk," | ".join(reasons),datetime.now(timezone.utc).isoformat())); c.commit(); c.close()
