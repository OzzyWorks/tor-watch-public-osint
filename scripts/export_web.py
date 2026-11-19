import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB=Path("data/history.db")
OUT=Path("web/data.json")

def _level(risk):
    if risk >= 85: return "CRITICAL"
    if risk >= 70: return "HIGH"
    if risk >= 50: return "MEDIUM"
    return "LOW"

def _reason_fields(raw, risk):
    parts=[x.strip() for x in str(raw or "").split(" | ") if x.strip()]
    companies=[x.split(":",1)[1].strip() for x in parts if x.startswith("company:")]
    return {
        "reason_items":parts,
        "companies":companies,
        "risk_level":_level(risk),
    }

pages=[]
events=[]
threat_alerts=[]
if DB.exists():
    con=sqlite3.connect(DB)
    rows=con.execute("SELECT url,title,risk,reasons,checked_at FROM pages ORDER BY risk DESC,checked_at DESC").fetchall()
    for r in rows:
        item={"url":r[0],"title":r[1],"risk":r[2],"reasons":r[3],"checked_at":r[4]}
        item.update(_reason_fields(r[3],r[2]))
        pages.append(item)
    ev=con.execute("SELECT id,url,title,event_type,risk,reasons,diff,detected_at FROM events ORDER BY id DESC LIMIT 100").fetchall()
    for r in ev:
        item={"id":r[0],"url":r[1],"title":r[2],"event_type":r[3],"risk":r[4],"reasons":r[5],"diff":r[6],"detected_at":r[7]}
        item.update(_reason_fields(r[5],r[4]))
        events.append(item)
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
