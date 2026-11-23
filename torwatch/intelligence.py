"""Conservative public-source cyber incident intelligence.

This module turns collected article metadata into stable incident observations,
actor profiles, relationships and discovery candidates. It never treats an
attacker's claim as official confirmation and never fetches linked leak files.
"""
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from hashlib import sha256
from urllib.parse import urlparse
import re


SIGNALS = {
    "ransomware": ("ransomware", "ランサムウェア"),
    "data_breach": ("data breach", "breach", "情報漏えい", "情報漏洩", "侵害"),
    "data_leak": ("data leak", "leak", "情報流出", "データ流出", "流出"),
    "exfiltration": ("exfiltrat", "窃取", "stolen data"),
    "unauthorized_access": ("不正アクセス", "unauthorized access"),
}


def parse_datetime(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(raw)
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            return None


def _companies(raw):
    values = raw if isinstance(raw, list) else str(raw or "").split(" | ")
    return list(dict.fromkeys(str(x).strip() for x in values if str(x).strip()))


def _signals(alert):
    text = " ".join((str(alert.get("title") or ""), str(alert.get("reasons") or ""))).casefold()
    return sorted(key for key, terms in SIGNALS.items() if any(term in text for term in terms))


def _clean(value):
    return re.sub(r"[^a-z0-9\u3040-\u30ff\u3400-\u9fff]+", "", str(value or "").casefold())


def _actor_host_map(groups):
    result = {}
    for group in groups or []:
        name = str(group.get("name") or "").strip()
        if not name:
            continue
        for host in group.get("hosts", []) or []:
            result[str(host).lower()] = name
    return result


def normalize_incidents(alerts, groups=None):
    """Create one normalized incident observation per company/article pair."""
    host_map = _actor_host_map(groups)
    incidents = []
    for alert in alerts or []:
        title = str(alert.get("title") or "(タイトルなし)")
        url = str(alert.get("url") or "")
        host = (urlparse(url).hostname or "").lower()
        signals = _signals(alert)
        if not signals:
            continue
        published = str(alert.get("published") or "")
        detected = str(alert.get("detected_at") or "")
        when = parse_datetime(published) or parse_datetime(detected)
        companies = _companies(alert.get("matched_assets"))
        actor = host_map.get(host)
        if not companies:
            companies = ["企業未特定"]
        for company in companies:
            seed = "|".join((_clean(company), (when.date().isoformat() if when else "undated"), _clean(title), ",".join(signals)))
            incident_id = "INC-" + sha256(seed.encode("utf-8")).hexdigest()[:16].upper()
            strength = int(alert.get("evidence_strength") or 0)
            incidents.append({
                "incident_id": incident_id,
                "victim": company,
                "title": title,
                "url": url,
                "source": str(alert.get("source") or host or "unknown"),
                "source_domain": host,
                "published_at": published,
                "detected_at": detected,
                "occurred_at": "",
                "attack_types": signals,
                "actor": actor or "",
                "actor_relation": "observed_on_configured_actor_site" if actor else "unknown",
                "confidence": max(0, min(100, strength)),
                "evidence_status": str(alert.get("evidence_status") or alert.get("attention_level") or "未評価"),
                "officially_confirmed": bool(alert.get("officially_confirmed", False)),
                "date_key": when.date().isoformat() if when else "",
            })
    return sorted(incidents, key=lambda x: (x["published_at"] or x["detected_at"], x["victim"]), reverse=True)


def build_actor_profiles(groups, incidents, events=None):
    """Build profiles from configured identities and explicitly observed activity."""
    profiles = []
    for group in groups or []:
        name = str(group.get("name") or "").strip()
        if not name:
            continue
        hosts = sorted(set(str(x).lower() for x in group.get("hosts", []) or []))
        related = [x for x in incidents or [] if x.get("actor") == name]
        host_events = [
            x for x in events or []
            if (urlparse(str(x.get("url") or "")).hostname or "").lower() in hosts
        ]
        profiles.append({
            "name": name,
            "aliases": list(group.get("aliases") or []),
            "hosts": hosts,
            "description": str(group.get("description") or ""),
            "observed_incident_count": len(related),
            "victims": sorted(set(x["victim"] for x in related if x["victim"] != "企業未特定")),
            "attack_types": sorted(set(t for x in related for t in x.get("attack_types", []))),
            "site_event_count": len(host_events),
            "last_observed": max(
                [str(x.get("published_at") or x.get("detected_at") or "") for x in related]
                + [str(x.get("detected_at") or "") for x in host_events],
                default="",
            ),
            "attribution_note": "登録済み公開サイトとの対応関係に基づく集計。個別事件の攻撃主体を確定するものではありません。",
        })
    return sorted(profiles, key=lambda x: (-x["observed_incident_count"], -x["site_event_count"], x["name"]))


def build_relationships(incidents, max_days=30):
    """Return explainable candidate links; do not merge separate incidents."""
    rows = [x for x in incidents or [] if x.get("victim") != "企業未特定"]
    links = []
    for i, left in enumerate(rows):
        left_date = parse_datetime(left.get("published_at")) or parse_datetime(left.get("detected_at"))
        for right in rows[i + 1:]:
            if left["incident_id"] == right["incident_id"]:
                continue
            right_date = parse_datetime(right.get("published_at")) or parse_datetime(right.get("detected_at"))
            if left_date and right_date and abs((left_date - right_date).days) > max_days:
                continue
            relation = ""
            confidence = "low"
            explanation = ""
            if left["victim"].casefold() == right["victim"].casefold():
                shared = sorted(set(left.get("attack_types", [])) & set(right.get("attack_types", [])))
                if shared:
                    relation, confidence = "same_victim_related_reports", "candidate"
                    explanation = "同一企業と共通する攻撃種別。記事の重複・同一事件の可能性があります。"
            elif left.get("actor") and left.get("actor") == right.get("actor"):
                relation, confidence = "shared_observed_actor_site", "candidate"
                explanation = "同じ登録済み公開リークサイトに関連付けられています。個別事件の攻撃主体は未確定です。"
            else:
                shared = sorted(set(left.get("attack_types", [])) & set(right.get("attack_types", [])))
                if len(shared) >= 2:
                    relation, confidence = "shared_attack_pattern", "weak"
                    explanation = "攻撃種別に共通点があります。一般的な手口の一致だけでは同一攻撃者を意味しません。"
            if relation:
                links.append({
                    "left_incident_id": left["incident_id"],
                    "right_incident_id": right["incident_id"],
                    "left_victim": left["victim"],
                    "right_victim": right["victim"],
                    "relation": relation,
                    "confidence": confidence,
                    "shared_signals": sorted(set(left.get("attack_types", [])) & set(right.get("attack_types", []))),
                    "explanation": explanation,
                })
    return links[:500]


def detect_discoveries(incidents, actors, now=None):
    """Generate small, evidence-backed discovery cards from the available archive."""
    now = now or datetime.now(timezone.utc)
    recent_cutoff = now - timedelta(days=7)
    prior_cutoff = now - timedelta(days=37)
    discoveries = []
    by_actor = defaultdict(list)
    for item in incidents or []:
        actor = item.get("actor")
        when = parse_datetime(item.get("published_at")) or parse_datetime(item.get("detected_at"))
        if actor and when and recent_cutoff <= when <= now:
            by_actor[actor].append(item)
    for actor, items in by_actor.items():
        victims = sorted(set(x["victim"] for x in items if x["victim"] != "企業未特定"))
        if len(victims) >= 2:
            discoveries.append({
                "discovery_id": "actor-burst-" + sha256(actor.encode("utf-8")).hexdigest()[:10],
                "type": "multi_victim_actor_activity",
                "priority": "high" if len(victims) >= 3 else "medium",
                "title": f"{actor}に関連する複数企業の掲載を7日以内に観測",
                "summary": f"登録済み公開サイトとの関連がある情報から、異なる企業{len(victims)}社を検出しました。",
                "evidence": {"actor": actor, "victims": victims, "incident_count": len(items)},
                "caveat": "公開サイトとの対応関係に基づく観測です。個別事件の攻撃主体や被害の真偽は別途確認が必要です。",
            })
    # Archive novelty is deliberately labelled as first observed in this dataset,
    # not as a newly created or newly active criminal group.
    known_actor_names = {x.get("name") for x in actors or []}
    for actor in actors or []:
        if actor.get("observed_incident_count", 0) and actor.get("name") in known_actor_names:
            discoveries.append({
                "discovery_id": "actor-observed-" + sha256(actor["name"].encode("utf-8")).hexdigest()[:10],
                "type": "actor_archive_activity",
                "priority": "low",
                "title": f"{actor['name']}の活動情報をアーカイブ内で確認",
                "summary": f"関連事件候補{actor['observed_incident_count']}件、公開サイト上の変化{actor['site_event_count']}件。",
                "evidence": {"actor": actor["name"], "incident_count": actor["observed_incident_count"], "site_event_count": actor["site_event_count"]},
                "caveat": "初回観測はこのシステムの保存範囲内での初回であり、攻撃グループの新規活動を意味しません。",
            })
    # Detect broad volume changes only when there is enough comparable history.
    dated = []
    for item in incidents or []:
        when = parse_datetime(item.get("published_at")) or parse_datetime(item.get("detected_at"))
        if when:
            dated.append(when)
    recent_count = sum(recent_cutoff <= x <= now for x in dated)
    prior_count = sum(prior_cutoff <= x < recent_cutoff for x in dated)
    expected = prior_count / 30 * 7
    if recent_count >= 3 and expected >= 1 and recent_count >= expected * 2:
        discoveries.append({
            "discovery_id": "volume-spike-" + now.strftime("%Y%m%d"),
            "type": "incident_volume_change",
            "priority": "medium",
            "title": "公開情報で観測される事件候補が増加",
            "summary": f"直近7日{recent_count}件、直前30日の週換算平均{expected:.1f}件。",
            "evidence": {"recent_7d": recent_count, "prior_30d": prior_count, "expected_7d": round(expected, 1)},
            "caveat": "公開情報の取得量・情報源の稼働状況による変動を含み、実際の攻撃件数の増加とは限りません。",
        })
    return sorted(discoveries, key=lambda x: ({"high": 0, "medium": 1, "low": 2}.get(x["priority"], 3), x["type"], x["title"]))
