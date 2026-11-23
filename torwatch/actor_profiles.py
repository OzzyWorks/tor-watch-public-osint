"""Evidence-aware threat actor profiles and incident attribution records."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from .intelligence_storage import init


RELATION_TYPES = {"claimed", "reported", "suspected", "confirmed"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_name(value: str) -> str:
    return re.sub(r"\\s+", " ", str(value or "")).strip()


def _actor_id(canonical_name: str) -> str:
    digest = hashlib.sha256(canonical_name.casefold().encode("utf-8")).hexdigest()[:20]
    return "ACT-" + digest.upper()


def upsert_actor(canonical_name: str, description: str = "", profile: dict | None = None,
                 observed_at: str | None = None, db_path=None) -> str:
    """Create/update a canonical actor profile; does not imply attribution to any incident."""
    name = _canonical_name(canonical_name)
    if not name:
        raise ValueError("canonical_name is required")
    actor_id = _actor_id(name)
    now = _now()
    con = init(db_path)
    con.execute("""
        INSERT INTO actors(actor_id,canonical_name,description,first_seen_at,last_seen_at,
                           profile_json,updated_at)
        VALUES(?,?,?,?,?,?,?)
        ON CONFLICT(actor_id) DO UPDATE SET
          description=CASE WHEN excluded.description!='' THEN excluded.description
                           ELSE actors.description END,
          first_seen_at=CASE
            WHEN actors.first_seen_at IS NULL THEN excluded.first_seen_at
            WHEN excluded.first_seen_at IS NULL THEN actors.first_seen_at
            WHEN excluded.first_seen_at < actors.first_seen_at THEN excluded.first_seen_at
            ELSE actors.first_seen_at END,
          last_seen_at=CASE
            WHEN actors.last_seen_at IS NULL THEN excluded.last_seen_at
            WHEN excluded.last_seen_at IS NULL THEN actors.last_seen_at
            WHEN excluded.last_seen_at > actors.last_seen_at THEN excluded.last_seen_at
            ELSE actors.last_seen_at END,
          profile_json=excluded.profile_json, updated_at=excluded.updated_at
    """, (actor_id, name, description, observed_at, observed_at,
          json.dumps(profile or {}, ensure_ascii=False, sort_keys=True), now))
    con.commit()
    con.close()
    return actor_id


def add_actor_alias(actor_id: str, alias: str, source_url: str,
                    confidence: int, db_path=None) -> bool:
    """Record an alias with its public provenance; aliases may be ambiguous across actors."""
    value = _canonical_name(alias)
    url = str(source_url or "").strip()
    score = int(confidence)
    if not value or not url.startswith("https://"):
        raise ValueError("alias and an HTTPS provenance URL are required")
    if not 0 <= score <= 100:
        raise ValueError("confidence must be between 0 and 100")
    con = init(db_path)
    exists = con.execute("SELECT 1 FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
    if not exists:
        con.close()
        raise ValueError("unknown actor_id")
    cur = con.execute("""
        INSERT OR IGNORE INTO actor_aliases(actor_id,alias,source_url,confidence)
        VALUES(?,?,?,?)
    """, (actor_id, value, url, score))
    con.commit()
    inserted = cur.rowcount == 1
    con.close()
    return inserted


def link_actor_to_incident(incident_id: str, actor_id: str, relation_type: str,
                           confidence: int, rationale: str, evidence_ids=None,
                           db_path=None) -> None:
    """Store a qualified attribution. A claim/reported link is not a confirmation."""
    if relation_type not in RELATION_TYPES:
        raise ValueError("unsupported actor relation_type")
    score = int(confidence)
    if not 0 <= score <= 100:
        raise ValueError("confidence must be between 0 and 100")
    evidence = sorted({str(x) for x in (evidence_ids or []) if str(x).strip()})
    if not str(rationale or "").strip():
        raise ValueError("rationale is required")
    con = init(db_path)
    con.execute("""
        INSERT INTO incident_actors
          (incident_id,actor_id,relation_type,confidence,rationale,evidence_ids_json)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(incident_id,actor_id,relation_type) DO UPDATE SET
          confidence=excluded.confidence, rationale=excluded.rationale,
          evidence_ids_json=excluded.evidence_ids_json
    """, (incident_id, actor_id, relation_type, score, rationale.strip(),
          json.dumps(evidence, ensure_ascii=False)))
    con.commit()
    con.close()


def get_actor_profile(actor_id: str, db_path=None) -> dict | None:
    con = init(db_path)
    actor = con.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
    if actor is None:
        con.close()
        return None
    result = dict(actor)
    result["profile"] = json.loads(result.pop("profile_json"))
    result["aliases"] = [
        dict(row) for row in con.execute(
            "SELECT alias,source_url,confidence FROM actor_aliases WHERE actor_id=? ORDER BY alias",
            (actor_id,),
        ).fetchall()
    ]
    result["incident_relations"] = [
        {**dict(row), "evidence_ids": json.loads(row["evidence_ids_json"])}
        for row in con.execute("""
            SELECT incident_id,relation_type,confidence,rationale,evidence_ids_json
            FROM incident_actors WHERE actor_id=? ORDER BY incident_id
        """, (actor_id,)).fetchall()
    ]
    con.close()
    return result
