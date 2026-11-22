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
        token for token in re.findall(r"[a-z0-9]{3,}|[\u3040-\u30ff\u3400-\u9fff]{2,}", title)
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


def build_executive_summary(pages, events, threat_alerts, site_health, correlations):
    """Create a concise, plain-language operational summary."""
    pages = pages or []
    events = events or []
    threat_alerts = threat_alerts or []
    site_health = site_health or []
    correlations = correlations or []
    critical = [x for x in pages if int(x.get("risk") or 0) >= 85]
    high = [x for x in pages if 70 <= int(x.get("risk") or 0) < 85]
    public_high = [x for x in threat_alerts if int(x.get("risk") or 0) >= 65]
    errors = [x for x in site_health if x.get("status") == "error"]
    confirmed = [x for x in threat_alerts if x.get("officially_confirmed") is True]

    if critical:
        headline = f"要確認：監視ページでCRITICAL判定が{len(critical)}件"
        interpretation = "監視対象ページに強い脅威シグナルがあります。ただし企業の実被害・情報流出が確定した意味ではありません。"
        action = "CRITICALページの企業名・掲載内容・更新日時を確認し、企業公式発表など一次情報と照合してください。"
    elif correlations:
        headline = f"要確認：複数媒体で同一企業のインシデント候補が{len(correlations)}件"
        interpretation = "複数ドメインの記事が同じ企業・事件を示す可能性があります。転載や同一発表の再配信もあり得ます。"
        action = "候補記事の原典をたどり、企業公式発表など一次情報で裏取りしてください。"
    elif high or public_high:
        headline = f"注意：高リスク候補を検出（監視ページ{len(high)}件・公開報道{len(public_high)}件）"
        interpretation = "注意を要する一致がありますが、自動検出だけで被害を断定できません。"
        action = "対象企業と検出根拠を確認し、公式発表・一次情報で裏取りしてください。"
    else:
        headline = "現在、強い脅威シグナルは検出されていません"
        interpretation = "被害がないことの証明ではありません。監視対象・公開情報源・取得できた範囲での結果です。"
        action = "通常監視を継続し、取得エラーがある場合は復旧状況を確認してください。"

    # Summarize meaningful changes observed in the last 24 hours.
    now = datetime.now(timezone.utc)
    recent_events = []
    for event in events:
        when = _published_datetime(event.get("detected_at"))
        if when and now - when <= __import__("datetime").timedelta(hours=24) and when <= now:
            recent_events.append((when, event))
    event_labels = {
        "new": "新規ページ検出",
        "changed": "ページ内容の更新",
        "reclassified": "リスク判定の変更",
    }
    change_counts = {
        key: sum(1 for _, event in recent_events if event.get("event_type") == key)
        for key in event_labels
    }
    recent_changes = []
    for when, event in sorted(recent_events, key=lambda pair: pair[0], reverse=True)[:5]:
        companies = _companies(event.get("reasons"))
        recent_changes.append({
            "type": event.get("event_type") or "unknown",
            "label": event_labels.get(event.get("event_type"), "監視イベント"),
            "company": "、".join(companies) if companies else "企業名の一致なし",
            "title": str(event.get("title") or event.get("url") or "タイトルなし"),
            "url": str(event.get("url") or ""),
            "risk": int(event.get("risk") or 0),
            "detected_at": when.isoformat(),
        })

    top_items = []
    for item in sorted(threat_alerts, key=lambda x: int(x.get("risk") or 0), reverse=True):
        if len(top_items) == 3:
            break
        top_items.append({
            "kind": "公開報道・情報",
            "company": str(item.get("matched_assets") or "企業名の一致なし"),
            "title": str(item.get("title") or "タイトルなし"),
            "risk": int(item.get("risk") or 0),
            "evidence_strength": int(item.get("evidence_strength") or 0),
            "url": str(item.get("url") or ""),
            "status": str(item.get("evidence_status") or "公式確認なし"),
        })
    for item in sorted(pages, key=lambda x: int(x.get("risk") or 0), reverse=True):
        if len(top_items) == 3:
            break
        top_items.append({
            "kind": "公開リークサイト監視",
            "company": "、".join(item.get("companies") or []) or "企業名の一致なし",
            "title": str(item.get("title") or item.get("url") or "タイトルなし"),
            "risk": int(item.get("risk") or 0),
            "evidence_strength": int(item.get("evidence_strength") or 0),
            "url": str(item.get("url") or ""),
            "status": str(item.get("evidence_status") or "企業公式の確認なし"),
        })
    return {
        "headline": headline,
        "interpretation": interpretation,
        "priority_action": action,
        "counts": {
            "critical_pages": len(critical),
            "high_pages": len(high),
            "public_reports": len(threat_alerts),
            "multi_source_candidates": len(correlations),
            "site_errors": len(errors),
            "officially_confirmed": len(confirmed),
        },
        "top_items": top_items,
        "changes_24h": {
            "total": len(recent_events),
            "counts": change_counts,
            "items": recent_changes,
        },
        "scope_note": "自動検出・候補抽出です。企業の被害確定には企業公式発表など一次情報による確認が必要です。",
    }
