"""Canonical, conservative normalization helpers for public cyber observations.

This module does not assert that two observations describe the same incident.
It creates stable observation identifiers and reviewable incident-candidate keys.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import re
from urllib.parse import urlsplit, urlunsplit


_EVENT_TERMS = {
    "ransomware": ("ransomware", "ランサムウェア"),
    "data_breach": ("data breach", "breach", "情報漏えい", "情報漏洩", "情報流出"),
    "data_leak": ("data leak", "leak site", "データ流出", "漏えい", "漏洩"),
    "unauthorized_access": ("unauthorized access", "不正アクセス"),
    "service_disruption": ("service disruption", "outage", "サービス停止"),
}

_ASSERTION_TERMS = {
    "official": ("official statement", "当社は", "弊社は", "お知らせ", "プレスリリース"),
    "attacker_claim": ("we have hacked", "we hacked", "ransomware group claims", "犯行声明"),
    "media_report": ("reports", "reported", "報道", "と報じた"),
}


def normalize_text(value: object) -> str:
    """Normalize whitespace and case while preserving Japanese characters."""
    return re.sub(r"\s+", " ", str(value or "")).strip().casefold()


def normalize_url(value: object) -> str:
    """Canonicalize a URL conservatively; remove fragments and default ports."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return raw
        host = parts.hostname.casefold()
        port = parts.port
        if port and not ((parts.scheme == "http" and port == 80) or
                         (parts.scheme == "https" and port == 443)):
            host = f"{host}:{port}"
        path = parts.path or "/"
        return urlunsplit((parts.scheme.casefold(), host, path, parts.query, ""))
    except ValueError:
        return raw


def parse_timestamp(value: object) -> str | None:
    """Return an ISO-8601 UTC timestamp, or None when parsing is uncertain."""
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def detect_event_types(title: object, summary: object = "") -> list[str]:
    text = f"{normalize_text(title)} {normalize_text(summary)}"
    return [
        event_type for event_type, terms in _EVENT_TERMS.items()
        if any(term in text for term in terms)
    ]


def classify_assertion(source_class: object, title: object, summary: object = "") -> str:
    """Classify assertion provenance; government advisories are not victim confirmation."""
    source = normalize_text(source_class)
    text = f"{normalize_text(title)} {normalize_text(summary)}"
    if source in {"official", "affected_org"}:
        return "official"
    if source in {"government", "government_advisory", "vulnerability_advisory"}:
        return "government_advisory"
    if any(term in text for term in _ASSERTION_TERMS["attacker_claim"]):
        return "attacker_claim"
    if any(term in text for term in _ASSERTION_TERMS["official"]):
        return "official_candidate"
    if source in {"media", "news", "rss"} or any(
        term in text for term in _ASSERTION_TERMS["media_report"]
    ):
        return "media_report"
    return "unverified"


def observation_id(source_id: object, url: object, title: object = "") -> str:
    """Stable ID for one source observation, not for an incident."""
    identity = "|".join((
        normalize_text(source_id),
        normalize_url(url),
        normalize_text(title),
    ))
    return "OBS-" + sha256(identity.encode("utf-8")).hexdigest()[:24]


def incident_candidate_key(
    victim: object, event_types: list[str], published_at: object = ""
) -> str:
    """Review key only; matching keys do not prove two reports are the same incident."""
    timestamp = parse_timestamp(published_at)
    day = timestamp[:10] if timestamp else "undated"
    identity = "|".join((
        normalize_text(victim),
        ",".join(sorted(set(event_types or []))),
        day,
    ))
    return "CAND-" + sha256(identity.encode("utf-8")).hexdigest()[:20]


def normalize_observation(item: dict) -> dict:
    """Map a legacy/public feed item into the canonical observation shape."""
    source_id = item.get("source_id") or item.get("source") or "unknown"
    url = normalize_url(item.get("url"))
    title = str(item.get("title") or "").strip()
    summary = str(item.get("summary") or item.get("description") or "").strip()
    published_at = parse_timestamp(item.get("published_at") or item.get("published"))
    observed_at = parse_timestamp(item.get("observed_at") or item.get("detected_at"))
    source_class = item.get("source_class") or "unknown"
    companies = item.get("companies") or item.get("matched_assets") or []
    if isinstance(companies, str):
        companies = [part.strip() for part in companies.split("|") if part.strip()]
    companies = list(dict.fromkeys(str(x).strip() for x in companies if str(x).strip()))
    event_types = detect_event_types(title, summary)
    return {
        "observation_id": observation_id(source_id, url, title),
        "source_id": str(source_id),
        "source_class": str(source_class),
        "url": url,
        "title": title,
        "summary": summary,
        "published_at": published_at,
        "observed_at": observed_at,
        "language": str(item.get("language") or "unknown"),
        "companies": companies,
        "event_types": event_types,
        "assertion_type": classify_assertion(source_class, title, summary),
        "candidate_keys": [
            incident_candidate_key(company, event_types, published_at)
            for company in companies
        ],
    }
