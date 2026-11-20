"""Build company and ransomware-group intelligence summaries from stored observations."""
from collections import defaultdict
from urllib.parse import urlparse


def _companies(raw):
    parts = raw if isinstance(raw, list) else str(raw or "").split(" | ")
    return list(dict.fromkeys(
        p.split(":", 1)[1].strip() for p in parts
        if str(p).startswith("company:") and p.split(":", 1)[1].strip()
    ))


def _level(risk):
    if risk >= 85: return "CRITICAL"
    if risk >= 70: return "HIGH"
    if risk >= 50: return "MEDIUM"
    return "LOW"


def build_company_radar(pages, events, threat_alerts):
    stats = {}
    for page in pages:
        for company in _companies(page.get("reasons")):
            item = stats.setdefault(company, {
                "company": company, "max_risk": 0, "risk_level": "LOW",
                "monitored_pages": 0, "high_risk_pages": 0,
                "last_seen": "", "event_count": 0, "public_reports": 0
            })
            item["monitored_pages"] += 1
            item["max_risk"] = max(item["max_risk"], int(page.get("risk") or 0))
            item["high_risk_pages"] += int(int(page.get("risk") or 0) >= 70)
            item["last_seen"] = max(item["last_seen"], page.get("checked_at") or "")
    for event in events:
        for company in _companies(event.get("reasons")):
            if company in stats:
                stats[company]["event_count"] += 1
    for alert in threat_alerts:
        for company in str(alert.get("matched_assets") or "").split(" | "):
            if company in stats:
                stats[company]["public_reports"] += 1
    for item in stats.values():
        item["risk_level"] = _level(item["max_risk"])
    return sorted(stats.values(), key=lambda x: (-x["max_risk"], -x["event_count"], x["company"]))


def build_group_activity(pages, events, groups):
    host_to_name = {}
    for group in groups or []:
        name = str(group.get("name") or "Unknown")
        for host in group.get("hosts", []) or []:
            host_to_name[str(host).lower()] = name
    stats = {}
    for page in pages:
        host = (urlparse(str(page.get("url") or "")).hostname or "").lower()
        name = host_to_name.get(host, "未分類")
        item = stats.setdefault(name, {
            "group": name, "monitored_sites": 0, "high_risk_sites": 0,
            "max_risk": 0, "last_seen": "", "changed_pages": 0
        })
        item["monitored_sites"] += 1
        risk = int(page.get("risk") or 0)
        item["max_risk"] = max(item["max_risk"], risk)
        item["high_risk_sites"] += int(risk >= 70)
        item["last_seen"] = max(item["last_seen"], page.get("checked_at") or "")
    changed = defaultdict(set)
    for event in events:
        if event.get("event_type") in ("new", "changed", "reclassified"):
            host = (urlparse(str(event.get("url") or "")).hostname or "").lower()
            name = host_to_name.get(host, "未分類")
            changed[name].add(event.get("url"))
    for name, urls in changed.items():
        if name in stats:
            stats[name]["changed_pages"] = len(urls)
    return sorted(stats.values(), key=lambda x: (-x["high_risk_sites"], -x["max_risk"], x["group"]))
