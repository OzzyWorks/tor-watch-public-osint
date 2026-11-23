"""Turn normalized public observations into reviewable incident candidates and discoveries."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone, time as dt_time

from .intelligence_storage import init
from .incident_timeline import attach_observation
from .evidence_assessment import record_evidence, assess_incident_confidence
from .discovery_engine import discover_patterns


def _incident_id(candidate_key: str) -> str:
    digest = hashlib.sha256(candidate_key.encode("utf-8")).hexdigest()[:24]
    return "INC-" + digest.upper()


def _evidence_rating(reliability: str, assertion_type: str) -> int:
    base = {"high": 75, "medium": 60, "low": 40}.get(reliability, 50)
    if assertion_type == "attacker_claim":
        return min(base, 35)
    if assertion_type == "official":
        return max(base, 80)
    if assertion_type == "government_advisory":
        return max(base, 75)
    return base


def run_intelligence_pipeline(db_path=None, observation_limit: int = 10000) -> dict:
    con = init(db_path)
    rows = con.execute("""
        SELECT observation_id,source_id,source_class,title,summary,url,
               published_at,observed_at,assertion_type,payload_json
        FROM observations
        ORDER BY COALESCE(published_at,observed_at,created_at) DESC
        LIMIT ?
    """, (max(1, min(int(observation_limit), 10000)),)).fetchall()
    source_rows = con.execute("""
        SELECT source_id,name,source_class,reliability,provenance_group
        FROM intel_sources
    """).fetchall()
    sources = {row["source_id"]: dict(row) for row in source_rows}
    con.close()

    touched_incidents = set()
    linked = 0
    created = 0
    for row in rows:
        observation = dict(row)
        try:
            payload = json.loads(observation.pop("payload_json") or "{}")
        except (TypeError, ValueError):
            payload = {}
        companies = payload.get("companies") or []
        event_types = payload.get("event_types") or []
        candidate_keys = payload.get("candidate_keys") or []
        source = sources.get(observation["source_id"], {})
        provenance = source.get("provenance_group") or ("source:" + observation["source_id"])
        evidence_type = observation.get("assertion_type") or "unverified"
        if evidence_type not in {"official", "government_advisory", "media_report", "attacker_claim"}:
            evidence_type = "unverified"
        rating = _evidence_rating(source.get("reliability", "unrated"), evidence_type)

        for index, candidate_key in enumerate(candidate_keys):
            if index >= len(companies) or not candidate_key:
                continue
            victim = str(companies[index])
            incident_id = _incident_id(str(candidate_key))
            now = datetime.now(timezone.utc).isoformat()
            con = init(db_path)
            cur = con.execute("""
                INSERT OR IGNORE INTO incidents
                  (incident_id,victim,event_types_json,status,severity,confidence,
                   first_seen_at,published_at,detected_at,summary,created_at,updated_at)
                VALUES(?,?,?,'candidate','unknown',0,?,?,?,?,?,?)
            """, (
                incident_id, victim, json.dumps(event_types, ensure_ascii=False),
                observation.get("published_at") or observation.get("observed_at"),
                observation.get("published_at"), observation.get("observed_at"),
                observation.get("title") or "", now, now,
            ))
            created += int(cur.rowcount == 1)
            con.execute("""
                INSERT OR IGNORE INTO incident_candidate_keys(candidate_key,incident_id,created_at)
                VALUES(?,?,?)
            """, (str(candidate_key), incident_id, now))
            con.commit()
            con.close()

            attach_observation(
                incident_id, observation["observation_id"], "candidate", 20,
                "Shared review key (victim, detected event types, UTC publication day); "
                "candidate grouping is not proof of a single incident.",
                db_path,
            )
            record_evidence(
                incident_id, observation["observation_id"], evidence_type,
                provenance, observation.get("title") or observation.get("url") or "Public observation",
                rating,
                "Automated source-class/reliability rating; independent analyst review is required.",
                db_path,
            )
            touched_incidents.add(incident_id)
            linked += 1

    for incident_id in sorted(touched_incidents):
        assess_incident_confidence(incident_id, db_path)

    today = datetime.now(timezone.utc).date()
    current_start_dt = datetime.combine(today - timedelta(days=30), dt_time.min, tzinfo=timezone.utc)
    current_end_dt = datetime.combine(today, dt_time.max, tzinfo=timezone.utc)
    baseline_start_dt = current_start_dt - timedelta(days=30)
    baseline_end_dt = current_start_dt - timedelta(microseconds=1)
    current_start = current_start_dt.isoformat()
    current_end = current_end_dt.isoformat()
    baseline_start = baseline_start_dt.isoformat()
    baseline_end = baseline_end_dt.isoformat()
    discoveries = discover_patterns(
        current_start, current_end, baseline_start, baseline_end, db_path
    )
    return {
        "observations_processed": len(rows),
        "incidents_created": created,
        "observation_links": linked,
        "incidents_assessed": len(touched_incidents),
        "discoveries": len(discoveries),
        "discovery_items": discoveries,
    }


if __name__ == "__main__":
    result = run_intelligence_pipeline()
    print("Intelligence pipeline:", json.dumps(result, ensure_ascii=False))
