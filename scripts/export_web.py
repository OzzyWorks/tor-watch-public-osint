import json
import sqlite3
import sys
from pathlib import Path
from datetime import datetime, timezone

# When invoked as "python scripts/export_web.py", Python puts scripts/
# rather than the repository root on sys.path.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml
from torwatch.analytics import build_company_radar, build_group_activity, build_incident_correlations, build_executive_summary, explain_public_alert, build_company_timeline
from torwatch.risk import assess_evidence

DB=Path("data/history.db")
OUT=Path("web/data.json")
GROUPS=Path("config/groups.yml")

def _level(risk):
    if risk >= 85: return "CRITICAL"
    if risk >= 70: return "HIGH"
    if risk >= 50: return "MEDIUM"
    return "LOW"

def _reason_fields(raw, risk):
    parts=[x.strip() for x in str(raw or "").split(" | ") if x.strip()]
    companies=[x.split(":",1)[1].strip() for x in parts if x.startswith("company:")]
    return {"reason_items":parts,"companies":companies,"risk_level":_level(risk),**assess_evidence(parts)}

pages=[]
events=[]
threat_alerts=[]
site_health=[]
if DB.exists():
    con=sqlite3.connect(DB)
    con.row_factory=sqlite3.Row
    rows=con.execute("SELECT url,title,risk,reasons,checked_at FROM pages ORDER BY risk DESC,checked_at DESC").fetchall()
    for r in rows:
        item={"url":r["url"],"title":r["title"],"risk":r["risk"],"reasons":r["reasons"],"checked_at":r["checked_at"]}
        item.update(_reason_fields(r["reasons"],r["risk"]))
        pages.append(item)
    ev=con.execute("SELECT id,url,title,event_type,risk,reasons,diff,detected_at FROM events ORDER BY id DESC LIMIT 500").fetchall()
    for r in ev:
        item={"id":r["id"],"url":r["url"],"title":r["title"],"event_type":r["event_type"],"risk":r["risk"],"reasons":r["reasons"],"diff":r["diff"],"detected_at":r["detected_at"]}
        item.update(_reason_fields(r["reasons"],r["risk"]))
        events.append(item)
    try:
        rows=con.execute("""SELECT id,source,title,url,published,matched_assets,risk,reasons,status,detected_at
            FROM threat_items ORDER BY detected_at DESC LIMIT 200""").fetchall()
        threat_alerts=[{**dict(r),**assess_evidence(str(r["reasons"] or "").split(" | "), "public_report")} for r in rows]
        threat_alerts=[{**item,**explain_public_alert(item)} for item in threat_alerts]
    except sqlite3.OperationalError:
        pass
    try:
        rows=con.execute("""SELECT url,status,title,error_type,error,checked_at,
            last_success_at,consecutive_errors FROM site_checks
            ORDER BY CASE WHEN status='error' THEN 0 ELSE 1 END,
            consecutive_errors DESC,checked_at DESC""").fetchall()
        site_health=[dict(r) for r in rows]
        for item in site_health:
            history=con.execute("""SELECT status,error_type,checked_at
                FROM site_check_history WHERE url=?
                ORDER BY checked_at DESC LIMIT 6""",(item["url"],)).fetchall()
            item["history"]=[dict(x) for x in history]
    except sqlite3.OperationalError:
        pass
    con.close()

group_config=yaml.safe_load(GROUPS.read_text(encoding="utf-8")) if GROUPS.exists() else {"groups":[]}
company_radar=build_company_radar(pages,events,threat_alerts)
group_activity=build_group_activity(pages,events,group_config.get("groups",[]))
incident_correlations=build_incident_correlations(threat_alerts)
company_timeline=build_company_timeline(events,threat_alerts)
executive_summary=build_executive_summary(pages,events,threat_alerts,site_health,incident_correlations)
OUT.write_text(json.dumps({
    "updated_at":datetime.now(timezone.utc).isoformat(),
    "pages":pages,"events":events,"threat_alerts":threat_alerts,
    "site_health":site_health,
    "company_radar":company_radar,"group_activity":group_activity,
    "incident_correlations":incident_correlations,"company_timeline":company_timeline,"executive_summary":executive_summary
},ensure_ascii=False,indent=2),encoding="utf-8")
