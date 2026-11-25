"""Conservative duplicate/syndication candidates; observations are never merged automatically."""
from __future__ import annotations

import hashlib
import re
from difflib import SequenceMatcher
from datetime import datetime, timezone

from .intelligence_storage import init
from .normalizer import normalize_url


def _title_key(value: str) -> str:
    value = str(value or "").casefold()
    value = re.sub(r"[^\w\u3040-\u30ff\u3400-\u9fff]+", " ", value)
    return " ".join(value.split())


def _within_window(left: str | None, right: str | None, days: int = 14) -> bool:
    if not left or not right:
        return True
    try:
        a = datetime.fromisoformat(left.replace("Z", "+00:00"))
        b = datetime.fromisoformat(right.replace("Z", "+00:00"))
        if a.tzinfo is None:
            a = a.replace(tzinfo=timezone.utc)
        if b.tzinfo is None:
            b = b.replace(tzinfo=timezone.utc)
        return abs((a - b).total_seconds()) <= days * 86400
    except (TypeError, ValueError):
        return True


def _pair_key(one: str, two: str) -> tuple[str, str, str]:
    left, right = sorted((one, two))
    digest = hashlib.sha256((left + "|" + right).encode("utf-8")).hexdigest()
    return left, right, "DUP-" + digest[:24].upper()


def find_duplicate_candidates(limit: int = 300, db_path=None) -> list[dict]:
    """Find review candidates using exact canonical URLs or near-identical titles."""
    con = init(db_path)
    rows = con.execute("""
        SELECT o.observation_id,o.source_id,o.title,o.url,o.published_at,o.observed_at,
               s.name AS source_name,s.provenance_group
        FROM observations o LEFT JOIN intel_sources s ON s.source_id=o.source_id
        ORDER BY COALESCE(o.published_at,o.observed_at,o.created_at) DESC
        LIMIT ?
    """, (max(2, min(int(limit), 500)),)).fetchall()
    reviewed = {
        row["pair_key"]: row["decision"]
        for row in con.execute("SELECT pair_key,decision FROM observation_duplicate_reviews")
    }
    con.close()
    items = [dict(row) for row in rows]
    results = []
    for index, left in enumerate(items):
        left_url = normalize_url(left.get("url"))
        left_title = _title_key(left.get("title"))
        left_time = left.get("published_at") or left.get("observed_at")
        if len(left_title) < 18 and not left_url:
            continue
        for right in items[index + 1:]:
            if left["source_id"] == right["source_id"]:
                continue
            right_time = right.get("published_at") or right.get("observed_at")
            if not _within_window(left_time, right_time):
                continue
            right_url = normalize_url(right.get("url"))
            right_title = _title_key(right.get("title"))
            exact_url = bool(left_url and right_url and left_url == right_url)
            similarity = SequenceMatcher(None, left_title, right_title).ratio() if left_title and right_title else 0.0
            if not exact_url and (len(left_title) < 18 or similarity < 0.94):
                continue
            a, b, pair_key = _pair_key(left["observation_id"], right["observation_id"])
            decision = reviewed.get(pair_key)
            if decision == "separate":
                continue
            results.append({
                "pair_key": pair_key,
                "observation_id": a,
                "candidate_observation_id": b,
                "match_reason": "exact_canonical_url" if exact_url else "near_identical_title",
                "title_similarity": round(similarity, 4),
                "same_provenance_group": bool(
                    left.get("provenance_group")
                    and left.get("provenance_group") == right.get("provenance_group")
                ),
                "decision": decision or "candidate",
                "observations": [
                    {
                        "observation_id": item["observation_id"],
                        "title": item.get("title") or "",
                        "source_id": item.get("source_id") or "",
                        "source_name": item.get("source_name") or item.get("source_id") or "",
                        "url": item.get("url") or "",
                        "published_at": item.get("published_at") or item.get("observed_at") or "",
                        "provenance_group": item.get("provenance_group") or "",
                    }
                    for item in (left, right)
                ],
            })
    return sorted(results, key=lambda item: (
        item["match_reason"] != "exact_canonical_url", -item["title_similarity"], item["pair_key"]
    ))


def review_duplicate_candidate(observation_id: str, candidate_observation_id: str,
                               decision: str, rationale: str, db_path=None) -> None:
    """Persist an explicit keep-separate or same-incident-candidate decision."""
    if decision not in {"separate", "same_incident_candidate"}:
        raise ValueError("decision must be separate or same_incident_candidate")
    if not str(rationale or "").strip():
        raise ValueError("rationale is required")
    left, right, pair_key = _pair_key(observation_id, candidate_observation_id)
    if left == right:
        raise ValueError("an observation cannot be compared with itself")
    con = init(db_path)
    con.execute("""
        INSERT INTO observation_duplicate_reviews
          (pair_key,observation_id,candidate_observation_id,decision,rationale,reviewed_at)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(pair_key) DO UPDATE SET decision=excluded.decision,
          rationale=excluded.rationale,reviewed_at=excluded.reviewed_at
    """, (pair_key, left, right, decision, rationale.strip(),
          datetime.now(timezone.utc).isoformat()))
    con.commit()
    con.close()
