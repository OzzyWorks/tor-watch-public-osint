import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB=Path("data/history.db")
OUT=Path("web/data.json")
pages=[]
events=[]
threat_alerts=[]
if DB.exists():
    con=sqlite3.connect(DB)
    rows=con.execute("SELECT url,title,risk,reasons,checked_at FROM pages ORDER BY risk DESC,checked_at DESC").fetchall()
    pages=[{"url":r[0],"title":r[1],"risk":r[2],"reasons":r[3],"checked_at":r[4]} for r in rows]
    ev=con.execute("SELECT id,url,title,event_type,risk,reasons,diff,detected_at FROM events ORDER BY id DESC LIMIT 100").fetchall()
    events=[{"id":r[0],"url":r[1],"title":r[2],"event_type":r[3],"risk":r[4],"reasons":r[5],"diff":r[6],"detected_at":r[7]} for r in ev]
    try:
        rows=con.execute("""SELECT id,source,title,url,published,matched_assets,risk,reasons,status,detected_at
            FROM threat_items ORDER BY detected_at DESC LIMIT 100""").fetchall()
        threat_alerts=[{"id":r[0],"source":r[1],"title":r[2],"url":r[3],"published":r[4],
            "matched_assets":r[5],"risk":r[6],"reasons":r[7],"status":r[8],"detected_at":r[9]} for r in rows]
    except sqlite3.OperationalError:
        pass
    con.close()
OUT.write_text(json.dumps({
    "updated_at":datetime.now(timezone.utc).isoformat(),
    "pages":pages,"events":events,"threat_alerts":threat_alerts
},ensure_ascii=False,indent=2),encoding="utf-8")
