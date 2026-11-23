"""Source-preserving incident timelines built from linked observations."""
from __future__ import annotations

from .intelligence_storage import init


ALLOWED_LINK_TYPES = {"candidate", "corroborates", "official_statement", "disputes", "updates"}


def attach_observation(incident_id: str, observation_id: str, relation_type: str = "candidate",
                      confidence: int = 0, rationale: str = "", db_path=None) -> None:
    if relation_type not in ALLOWED_LINK_TYPES:
        raise ValueError("unsupported incident-observation relation_type")
    score = int(confidence)
    if not 0 <= score <= 100:
        raise ValueError("confidence must be between 0 and 100")
    con = init(db_path)
    con.execute("""
        INSERT INTO incident_observations
          (incident_id,observation_id,relation_type,confidence,rationale)
        VALUES(?,?,?,?,?)
        ON CONFLICT(incident_id,observation_id) DO UPDATE SET
          relation_type=excluded.relation_type,
          confidence=excluded.confidence,
          rationale=excluded.rationale
    """, (incident_id, observation_id, relation_type, score, str(rationale or "").strip()))
    con.commit()
    con.close()


def build_incident_timeline(incident_id: str, db_path=None) -> list[dict]:
    """Return dated source events in chronological order, retaining assertion distinctions."""
    con = init(db_path)
    rows = con.execute("""
        SELECT o.observation_id,o.source_id,s.name AS source_name,s.provenance_group,
               o.source_class,o.title,o.url,o.summary,o.published_at,o.observed_at,
               o.assertion_type,io.relation_type,io.confidence AS link_confidence,
               io.rationale AS link_rationale,o.created_at
        FROM incident_observations io
        JOIN observations o ON o.observation_id=io.observation_id
        LEFT JOIN intel_sources s ON s.source_id=o.source_id
        WHERE io.incident_id=?
    """, (incident_id,)).fetchall()
    con.close()
    events = []
    for row in rows:
        event = dict(row)
        event["timestamp"] = event.get("published_at") or event.get("observed_at") or event.get("created_at")
        event["time_basis"] = (
            "published_at" if event.get("published_at") else
            "observed_at" if event.get("observed_at") else "recorded_at"
        )
        events.append(event)
    return sorted(events, key=lambda item: (item.get("timestamp") or "", item["observation_id"]))
