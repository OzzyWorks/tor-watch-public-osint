"""Build company and ransomware-group intelligence summaries from stored observations."""
from collections import defaultdict
from urllib.parse import urlparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import re


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


def _published_datetime(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(raw)
            return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, OverflowError):
            return None


def _incident_signals(alert):
    text = " ".join((
        str(alert.get("title") or ""),
        str(alert.get("reasons") or ""),
    )).casefold()
    groups = {
        "ransomware": ("ransomware", "ランサムウェア"),
        "data_breach": ("data breach", "breach", "情報漏えい", "情報漏洩", "侵害"),
        "data_leak": ("data leak", "leak", "情報流出", "データ流出", "流出"),
        "exfiltration": ("exfiltrat", "窃取", "stolen data"),
        "unauthorized_access": ("不正アクセス", "unauthorized access"),
    }
    return {key for key, terms in groups.items() if any(term in text for term in terms)}


def _title_tokens(alert, company):
    title = str(alert.get("title") or "").casefold()
    name = str(company or "").casefold()
    if name:
        title = title.replace(name, " ")
    return {
        token for token in re.findall(r"[a-z0-9]{3,}|[\\u3040-\\u30ff\\u3400-\\u9fff]{2,}", title)
        if token not in {"the", "and", "for", "with", "from", "after", "about", "this", "that"}
    }


def build_incident_correlations(threat_alerts, max_days=30, min_similarity=0.25):
    """Conservatively group same-company reports with shared incident signals.

    This is a candidate corroboration view, not proof of independent reporting.
    """
    records = []
    for alert in threat_alerts or []:
        raw_companies = alert.get("matched_assets") or []
        companies = raw_companies if isinstance(raw_companies, list) else str(raw_companies).split(" | ")
        when = _published_datetime(alert.get("published")) or _published_datetime(alert.get("detected_at"))
        host = (urlparse(str(alert.get("url") or "")).hostname or "").lower()
        signals = _incident_signals(alert)
        if not host or not signals:
            continue
        for company in dict.fromkeys(str(x).strip() for x in companies if str(x).strip()):
            records.append({
                "company": company, "title": str(alert.get("title") or "(タイトルなし)"),
                "url": str(alert.get("url") or ""), "source": str(alert.get("source") or host),
                "domain": host, "risk": int(alert.get("risk") or 0),
                "published": str(alert.get("published") or alert.get("detected_at") or ""),
                "when": when, "signals": signals,
                "tokens": _title_tokens(alert, company),
            })

    parent = list(range(len(records)))
    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    def join(a, b):
        ra, rb = root(a), root(b)
        if ra != rb:
            parent[rb] = ra

    for i, left in enumerate(records):
        for j in range(i + 1, len(records)):
            right = records[j]
            if left["company"].casefold() != right["company"].casefold():
                continue
            if left["domain"] == right["domain"] or not (left["signals"] & right["signals"]):
                continue
            if left["when"] and right["when"] and abs((left["when"] - right["when"]).days) > max_days:
                continue
            union = left["tokens"] | right["tokens"]
            similarity = len(left["tokens"] & right["tokens"]) / len(union) if union else 0
            if similarity >= min_similarity:
                join(i, j)

    clusters = defaultdict(list)
    for i, record in enumerate(records):
        clusters[root(i)].append(record)

    output = []
    for members in clusters.values():
        domains = sorted({x["domain"] for x in members})
        if len(domains) < 2:
            continue
        ordered = sorted(members, key=lambda x: (x["when"] or datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
        output.append({
            "company": ordered[0]["company"],
            "title": ordered[0]["title"],
            "source_count": len(domains),
            "item_count": len(members),
            "sources": sorted({x["source"] for x in members}),
            "domains": domains,
            "max_risk": max(x["risk"] for x in members),
            "latest": ordered[0]["published"],
            "items": [{"title": x["title"], "source": x["source"], "url": x["url"], "published": x["published"]} for x in ordered],
            "caveat": "複数ドメインで検出。転載・同一情報源の再配信を含む可能性があり、独立した裏付けとは限りません。",
        })
    return sorted(output, key=lambda x: (-x["source_count"], -x["max_risk"], x["company"]))
