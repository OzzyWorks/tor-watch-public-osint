"""Typed, evidence-backed relationships between distinct incident records."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .intelligence_storage import init


RELATION_TYPES = {
    "same_incident_candidate", "same_actor", "shared_ttp",
    "shared_vulnerability", "temporal_cluster",
}


def link_incidents(incident_id: str, related_incident_id: str, relation_type: str,
                   confidence: int, rationale: str, evidence_ids: list[str],
                   db_path=None) -> str:
    if incident_id == related_incident_id:
        raise ValueError("incident relation requires two distinct incidents")
    if relation_type not in RELATION_TYPES:
        raise ValueError("unsupported incident relation type")
    score = int(confidence)
    if not 0 <= score <= 100:
        raise ValueError("confidence must be between 0 and 100")
    if not str(rationale or "").strip():
        raise ValueError("rationale is required")
    ids = sorted({str(value).strip() for value in (evidence_ids or []) if str(value).strip()})
    if not ids:
        raise ValueError("at least one evidence reference is required")
    left, right = sorted((incident_id, related_incident_id))
    relation_id = "REL-" + hashlib.sha256(
        "|".join((left, right, relation_type)).encode("utf-8")
    ).hexdigest()[:24].upper()
    con = init(db_path)
    placeholders = ",".join("?" for _ in ids)
    rows = con.execute(
        f"SELECT evidence_id,incident_id FROM evidence WHERE evidence_id IN ({placeholders})",
        ids,
    ).fetchall()
    valid = {row["evidence_id"]: row["incident_id"] for row in rows}
    if len(valid) != len(ids) or not any(
        owner in {incident_id, related_incident_id} for owner in valid.values()
    ):
        con.close()
        raise ValueError("evidence must exist and support at least one endpoint incident")
    con.execute("""
        INSERT INTO incident_relations
          (relation_id,incident_id,related_incident_id,relation_type,confidence,
           rationale,evidence_ids_json,created_at)
        VALUES(?,?,?,?,?,?,?,?)
        ON CONFLICT(relation_id) DO UPDATE SET
          confidence=excluded.confidence,rationale=excluded.rationale,
          evidence_ids_json=excluded.evidence_ids_json
    """, (relation_id, incident_id, related_incident_id, relation_type, score,
          rationale.strip(), json.dumps(ids), datetime.now(timezone.utc).isoformat()))
    con.commit()
    con.close()
    return relation_id


def list_incident_relations(incident_id: str, db_path=None) -> list[dict]:
    con = init(db_path)
    rows = con.execute("""
        SELECT relation_id,incident_id,related_incident_id,relation_type,
               confidence,rationale,evidence_ids_json,created_at
        FROM incident_relations
        WHERE incident_id=? OR related_incident_id=?
        ORDER BY created_at,relation_id
    """, (incident_id, incident_id)).fetchall()
    con.close()
    result = []
    for row in rows:
        item = dict(row)
        item["evidence_ids"] = json.loads(item.pop("evidence_ids_json"))
        result.append(item)
    return result
