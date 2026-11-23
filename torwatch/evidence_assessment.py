"""Explainable evidence-strength scoring; this is not a probability estimate."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .intelligence_storage import init


# Conservative maximum contribution per independent origin group.
_WEIGHTS = {
    "official": 35,
    "government_advisory": 25,
    "media_report": 15,
    "attacker_claim": 5,
    "unverified": 5,
}


def record_evidence(incident_id: str, observation_id: str | None, evidence_type: str,
                    source_independence_group: str, assertion: str, confidence: int,
                    rationale: str, db_path=None) -> str:
    score = int(confidence)
    if not 0 <= score <= 100:
        raise ValueError("confidence must be between 0 and 100")
    if not str(rationale or "").strip():
        raise ValueError("rationale is required")
    if not str(source_independence_group or "").strip():
        raise ValueError("source independence group is required")
    identity = "|".join((incident_id, observation_id or "", evidence_type,
                         source_independence_group, assertion))
    evidence_id = "EVD-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24].upper()
    con = init(db_path)
    con.execute("""
        INSERT OR IGNORE INTO evidence
          (evidence_id,incident_id,observation_id,evidence_type,
           source_independence_group,assertion,confidence,rationale,created_at)
        VALUES(?,?,?,?,?,?,?,?,?)
    """, (evidence_id, incident_id, observation_id, evidence_type,
          source_independence_group, assertion, score, rationale.strip(),
          datetime.now(timezone.utc).isoformat()))
    con.commit()
    con.close()
    return evidence_id


def assess_incident_confidence(incident_id: str, db_path=None) -> dict:
    """Count each provenance group once, using its strongest evidence class."""
    con = init(db_path)
    rows = con.execute("""
        SELECT evidence_id,evidence_type,source_independence_group,assertion,
               confidence,rationale
        FROM evidence WHERE incident_id=?
        ORDER BY created_at,evidence_id
    """, (incident_id,)).fetchall()
    con.close()
    groups = {}
    for row in rows:
        item = dict(row)
        group = item["source_independence_group"]
        base_weight = _WEIGHTS.get(item["evidence_type"], 5)
        weight = round(base_weight * item["confidence"] / 100)
        current = groups.get(group)
        if current is None or weight > current["weight"]:
            groups[group] = {"weight": weight, "base_weight": base_weight, "evidence": item}
    score = min(100, sum(item["weight"] for item in groups.values()))
    attacker_only = bool(groups) and all(
        item["weight"] <= _WEIGHTS["attacker_claim"] for item in groups.values()
    )
    if attacker_only:
        score = min(score, 15)
    rationale_parts = [
        f"{group}: {item['evidence']['evidence_type']} "
        f"(base {item['base_weight']} × evidence rating {item['evidence']['confidence']}%) "
        f"+{item['weight']} ({item['evidence']['rationale']})"
        for group, item in sorted(groups.items())
    ]
    if not groups:
        rationale_parts.append("No recorded evidence; confidence remains 0")
    elif attacker_only:
        rationale_parts.append("Attacker claims alone are capped at 15/100")
    rationale_parts.append(
        "Score measures documented evidence strength, not the probability that an incident occurred"
    )
    con = init(db_path)
    con.execute("UPDATE incidents SET confidence=?,updated_at=? WHERE incident_id=?",
                (score, datetime.now(timezone.utc).isoformat(), incident_id))
    con.commit()
    con.close()
    return {
        "incident_id": incident_id,
        "confidence": score,
        "independent_source_groups": len(groups),
        "evidence_ids": [dict(row)["evidence_id"] for row in rows],
        "rationale": rationale_parts,
        "is_probability": False,
    }
