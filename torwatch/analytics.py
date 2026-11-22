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
    report_keys = defaultdict(set)
    for alert in threat_alerts:
        raw = alert.get("matched_assets") or ""
        companies = raw if isinstance(raw, list) else str(raw).split(" | ")
        title = re.sub(r"[^a-z0-9\u3040-\u30ff\u3400-\u9fff]+", "", str(alert.get("title") or "").casefold())
        url = str(alert.get("url") or "")
        fingerprint = title or url
        for company in companies:
            company = str(company).strip()
            if company in stats and fingerprint:
                report_keys[company].add(fingerprint)
    for company, fingerprints in report_keys.items():
        stats[company]["public_reports"] = len(fingerprints)
    for item in stats.values():
        item["risk_level"] = _level(item["max_risk"])
    return sorted(stats.values(), key=lambda x: (-x["max_risk"], -x["event_count"], x["company"]))



def build_company_timeline(events, threat_alerts, max_items=8):
    """Build a deduplicated, dated activity timeline per matched company."""
    grouped = defaultdict(dict)

    def add(company, record, fingerprint):
        if not company:
            return
        previous = grouped[company].get(fingerprint)
        if previous is None:
            grouped[company][fingerprint] = record
            return
        # Merge syndication links even when one copy has a later timestamp.
        for url in record.get("urls", []):
            if url and url not in previous["urls"]:
                previous["urls"].append(url)
        for source in record.get("sources", []):
            if source and source not in previous["sources"]:
                previous["sources"].append(source)
        if record["when"] > previous["when"]:
            merged_urls = previous["urls"]
            merged_sources = previous["sources"]
            grouped[company][fingerprint] = record
            grouped[company][fingerprint]["urls"] = merged_urls
            grouped[company][fingerprint]["sources"] = merged_sources

    for event in events or []:
        kind = str(event.get("event_type") or "")
        if kind not in ("new", "changed", "reclassified"):
            continue
        when = _published_datetime(event.get("detected_at"))
        if not when:
            continue
        title = str(event.get("title") or event.get("url") or "タイトルなし")
        url = str(event.get("url") or "")
        for company in _companies(event.get("reasons")):
            fingerprint = ("monitor", url, kind)
            add(company, {
                "company": company, "type": kind,
                "label": {"new": "リークサイト新規掲載", "changed": "リークサイト掲載内容の更新",
                          "reclassified": "監視ページのリスク再判定"}[kind],
                "title": title, "when": when, "date": when.isoformat(),
                "source": "公開リークサイト監視", "sources": ["公開リークサイト監視"],
                "url": url, "urls": [url] if url else [],
                "note": "監視ページ上の変化。企業の被害確定を意味しません。",
            }, fingerprint)

    for alert in threat_alerts or []:
        when = _published_datetime(alert.get("published")) or _published_datetime(alert.get("detected_at"))
        if not when:
            continue
        raw = alert.get("matched_assets") or ""
        companies = raw if isinstance(raw, list) else str(raw).split(" | ")
        title = str(alert.get("title") or alert.get("url") or "タイトルなし")
        url = str(alert.get("url") or "")
        source = str(alert.get("source") or (urlparse(url).hostname or "公開情報"))
        for company in dict.fromkeys(str(x).strip() for x in companies if str(x).strip()):
            normalized = re.sub(r"[^a-z0-9\u3040-\u30ff\u3400-\u9fff]+", "", title.casefold())
            fingerprint = ("public", normalized or url)
            add(company, {
                "company": company, "type": "public_report",
                "label": "公開報道・セキュリティ情報",
                "title": title, "when": when, "date": when.isoformat(),
                "source": source, "sources": [source],
                "url": url, "urls": [url] if url else [],
                "note": "公開記事・情報源での言及。企業公式の被害確認は未確認です。",
            }, fingerprint)

    output = []
    for company, records in grouped.items():
        items = sorted(records.values(), key=lambda x: x["when"], reverse=True)[:max_items]
        for item in items:
            item.pop("when", None)
        if items:
            output.append({"company": company, "event_count": len(records), "items": items})
    return sorted(output, key=lambda x: (x["items"][0]["date"] if x["items"] else "", x["company"]), reverse=True)


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



def explain_public_alert(alert):
    """Translate a public-feed match into a cautious, actionable Japanese explanation."""
    strength = int(alert.get("evidence_strength") or 0)
    raw_assets = alert.get("matched_assets") or ""
    companies = raw_assets if isinstance(raw_assets, list) else str(raw_assets).split(" | ")
    company = "、".join(dict.fromkeys(str(x).strip() for x in companies if str(x).strip()))
    if strength <= 0:
        level = "関連未確認"
        explanation = "監視対象企業との一致を確認できていません。記事は参考情報で、対象企業の事案とは判断できません。"
        action = "企業別アラートとしては扱わず、必要なら記事の原文で対象企業を確認してください。"
    elif strength <= 15:
        level = "低・企業名一致のみ"
        explanation = "記事に企業名が登場した段階です。漏洩・侵害を示す具体的な記載は検出されていません。"
        action = "原文の文脈を確認。企業名が別文脈で使われているだけなら対応不要です。"
    elif strength <= 40:
        level = "限定的・情報記載あり"
        explanation = "企業名の近くに情報種別やデータ量の記載がありますが、漏洩・侵害を裏付ける内容とは限りません。"
        action = "原文で企業名と情報記載の関係を確認し、具体的な漏洩主張があるかを見ます。"
    else:
        level = "要確認・侵害関連の記載"
        explanation = "企業名の近くに漏洩・侵害関連の記載があります。公開情報源の記事・主張を検出したもので、実被害や情報流出の確定ではありません。"
        action = "記事の原典と公表日時を確認し、企業公式のお知らせ・適時開示・注意喚起と照合してください。"
    return {
        "matched_company_text": company or "企業名の一致なし",
        "attention_level": level,
        "plain_explanation": explanation,
        "recommended_action": action,
        "official_confirmation_note": "企業公式の被害確認は未確認",
    }


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
    # Keep simple company-name matches separate from incident-related evidence.
    name_only = [x for x in threat_alerts if 0 < int(x.get("evidence_strength") or 0) <= 15]
    contextual = [x for x in threat_alerts if 15 < int(x.get("evidence_strength") or 0) <= 40]
    incident_related = [x for x in threat_alerts if int(x.get("evidence_strength") or 0) > 40]

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

    # Rank all candidate types together so the headline's most serious finding
    # is also the first item the operator sees. Public-feed risk scores are not
    # directly comparable to leak-page scores, so use evidence strength there.
    candidates = []
    for item in pages:
        candidates.append({
            "kind": "公開リークサイト監視",
            "company": "、".join(item.get("companies") or []) or "企業名の一致なし",
            "title": str(item.get("title") or item.get("url") or "タイトルなし"),
            "risk": int(item.get("risk") or 0),
            "evidence_strength": int(item.get("evidence_strength") or 0),
            "url": str(item.get("url") or ""),
            "status": str(item.get("evidence_status") or "企業公式の確認なし"),
            "priority": 1000 + int(item.get("risk") or 0),
        })
    for item in threat_alerts:
        explanation = explain_public_alert(item)
        strength = int(item.get("evidence_strength") or 0)
        candidates.append({
            "kind": "公開報道・情報",
            "company": str(item.get("matched_assets") or "企業名の一致なし"),
            "title": str(item.get("title") or "タイトルなし"),
            "risk": int(item.get("risk") or 0),
            "evidence_strength": strength,
            "url": str(item.get("url") or ""),
            "status": str(item.get("evidence_status") or "公式確認なし"),
            **explanation,
            "priority": strength,
        })
    top_items = sorted(
        candidates,
        key=lambda x: (x["priority"], x["evidence_strength"], x["risk"]),
        reverse=True,
    )[:3]
    for item in top_items:
        item.pop("priority", None)
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
            "name_only_matches": len(name_only),
            "contextual_matches": len(contextual),
            "incident_related_mentions": len(incident_related),
        },
        "top_items": top_items,
        "changes_24h": {
            "total": len(recent_events),
            "counts": change_counts,
            "items": recent_changes,
        },
        "scope_note": "自動検出・候補抽出です。企業の被害確定には企業公式発表など一次情報による確認が必要です。",
    }
