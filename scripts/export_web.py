import json,sqlite3
from pathlib import Path
from datetime import datetime,timezone
DB=Path("data/history.db"); OUT=Path("web/data.json")
if DB.exists():
    con=sqlite3.connect(DB)
    rows=con.execute("SELECT url,title,risk,reasons,checked_at FROM pages ORDER BY risk DESC,checked_at DESC").fetchall()
    con.close()
    pages=[{"url":r[0],"title":r[1],"risk":r[2],"reasons":r[3],"checked_at":r[4]} for r in rows]
else: pages=[]
OUT.write_text(json.dumps({"updated_at":datetime.now(timezone.utc).isoformat(),"pages":pages},ensure_ascii=False,indent=2),encoding="utf-8")
