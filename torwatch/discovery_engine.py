"""Coverage-aware discovery of new, recurring, rising and anomalous incident patterns."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .intelligence_storage import init


def _load_window(con, start: str, end: str) -> tuple[list[dict], set[str]]:
    rows = con.execute("""
        SELECT i.incident_id,i.sector,i.event_types_json,i.status,
               COALESCE(i.detected_at,i.first_seen_at,i.published_at) AS event_at
        FROM incidents i
        WHERE COALESCE(i.detected_at,i.first_seen_at,i.published_at) >= ?
          AND COALESCE(i.detected_at,i.first_seen_at,i.published_at) <= ?
        ORDER BY event_at,i.incident_id
    """, (start, end)).fetchall()
    incidents = [dict(row) for row in rows]
    ids = [row["incident_id"] for row in incidents]
    if not ids:
        return incidents, set()
    placeholders = ",".join("?" for _ in ids)
    sources = con.execute(f"""
        SELECT DISTINCT s.provenance_group
        FROM incident_observations io
        JOIN observations o ON o.observation_id=io.observation_id
        JOIN intel_sources s ON s.source_id=o.source_id
        WHERE io.incident_id IN ({placeholders}) AND s.provenance_group!=''
    """, ids).fetchall()
    return incidents, {row["provenance_group"] for row in sources}


def _patterns(incidents: list[dict]) -> dict[str, list[dict]]:
    groups = {}
    for incident in incidents:
        try:
            event_types = json.loads(incident.get("event_types_json") or "[]")
        except (TypeError, ValueError):
            event_types = []
        keys = []
        if incident.get("sector"):
            keys.append(("sector", str(incident["sector"]).casefold()))
        keys.extend(("event_type", str(value).casefold()) for value in event_types)
        for category, key in keys:
            groups.setdefault((category, key), []).append(incident)
    return groups


def discover_patterns(current_start: str, current_end: str,
                      baseline_start: str, baseline_end: str,
                      db_path=None) -> list[dict]:
    """Compare equal-style windows and persist discoveries with source-coverage caveats."""
    con = init(db_path)
    current, current_sources = _load_window(con, current_start, current_end)
    baseline, baseline_sources = _load_window(con, baseline_start, baseline_end)
    current_groups = _patterns(current)
    baseline_groups = _patterns(baseline)
    discoveries = []
    for key in sorted(set(current_groups) | set(baseline_groups)):
        category, value = key
        observed = len(current_groups.get(key, []))
        previous = len(baseline_groups.get(key, []))
        if observed == 0:
            continue
        coverage_ratio = (
            len(current_sources) / len(baseline_sources) if baseline_sources else
            (1.0 if current_sources else 0.0)
        )
        expected = previous * coverage_ratio
        if previous == 0:
            pattern = "new"
        elif observed >= max(5, expected * 3):
            pattern = "anomalous"
        elif observed >= max(3, expected * 2):
            pattern = "rising"
        else:
            pattern = "recurring"
        current_ids = [x["incident_id"] for x in current_groups.get(key, [])]
        baseline_ids = [x["incident_id"] for x in baseline_groups.get(key, [])]
        confidence = 40 + min(30, len(current_sources) * 10) + min(20, len(baseline_sources) * 5)
        if len(current_sources) < 2:
            confidence = min(confidence, 45)
        if len(baseline_sources) < 2:
            confidence = min(confidence, 55)
        coverage_notes = (
            f"Current window: {len(current_sources)} independent source groups; "
            f"baseline: {len(baseline_sources)}. "
            f"Coverage-adjusted expected count: {expected:.2f}."
        )
        if coverage_ratio > 1.25 or (baseline_sources and coverage_ratio < 0.75):
            coverage_notes += " Source coverage changed materially; interpret volume changes cautiously."
        title = f"{pattern.title()}: {value.replace('_', ' ')}"
        rationale = (
            f"Observed {observed} incidents versus {previous} in baseline; "
            f"coverage-adjusted expectation {expected:.2f}. "
            f"Pattern category: {category}."
        )
        identity = "|".join((pattern, category, value, current_start, current_end, baseline_start, baseline_end))
        discovery_id = "DSC-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24].upper()
        con.execute("""
            INSERT INTO discovery_items
              (discovery_id,category,title,summary,period_start,period_end,
               baseline_start,baseline_end,observed_count,expected_count,
               confidence,rationale,coverage_notes,related_incidents_json,created_at,status)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(discovery_id) DO UPDATE SET
              observed_count=excluded.observed_count,expected_count=excluded.expected_count,
              confidence=excluded.confidence,rationale=excluded.rationale,
              coverage_notes=excluded.coverage_notes,
              related_incidents_json=excluded.related_incidents_json
        """, (
            discovery_id, pattern, title,
            f"{observed} incidents in the current window; {previous} in the baseline.",
            current_start, current_end, baseline_start, baseline_end,
            observed, expected, confidence, rationale, coverage_notes,
            json.dumps(current_ids, ensure_ascii=False),
            datetime.now(timezone.utc).isoformat(), "new",
        ))
        discoveries.append({
            "discovery_id": discovery_id, "pattern": pattern, "category": category,
            "value": value, "observed_count": observed, "baseline_count": previous,
            "expected_count": round(expected, 2), "confidence": confidence,
            "coverage_notes": coverage_notes, "rationale": rationale,
            "related_incidents": current_ids, "baseline_incidents": baseline_ids,
        })
    con.commit()
    con.close()
    return discoveries
