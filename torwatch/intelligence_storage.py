"""Additive SQLite storage for the intelligence engine.

Legacy tables are left untouched. All source observations and analysis records are
stored separately so an incorrect correlation can be revised without losing evidence.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from . import storage as legacy_storage


def _default_db() -> Path:
    return legacy_storage.DB


def init(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Create the additive intelligence schema and return an open connection."""
    path = Path(db_path) if db_path is not None else Path(_default_db())
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript("""
    CREATE TABLE IF NOT EXISTS intelligence_schema_version (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS intel_sources (
        source_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'unknown',
        source_class TEXT NOT NULL DEFAULT 'unknown',
        reliability TEXT NOT NULL DEFAULT 'unrated',
        language TEXT NOT NULL DEFAULT 'unknown',
        enabled INTEGER NOT NULL DEFAULT 1,
        provenance_group TEXT NOT NULL DEFAULT '',
        last_success_at TEXT,
        last_error TEXT,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS observations (
        observation_id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        source_class TEXT NOT NULL DEFAULT 'unknown',
        url TEXT NOT NULL DEFAULT '',
        title TEXT NOT NULL DEFAULT '',
        summary TEXT NOT NULL DEFAULT '',
        published_at TEXT,
        observed_at TEXT,
        assertion_type TEXT NOT NULL DEFAULT 'unverified',
        language TEXT NOT NULL DEFAULT 'unknown',
        payload_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        FOREIGN KEY(source_id) REFERENCES intel_sources(source_id)
    );
    CREATE INDEX IF NOT EXISTS idx_observations_published
        ON observations(published_at DESC);
    CREATE INDEX IF NOT EXISTS idx_observations_source
        ON observations(source_id, observed_at DESC);
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        victim TEXT NOT NULL DEFAULT '',
        country TEXT NOT NULL DEFAULT '',
        sector TEXT NOT NULL DEFAULT '',
        event_types_json TEXT NOT NULL DEFAULT '[]',
        status TEXT NOT NULL DEFAULT 'unconfirmed',
        severity TEXT NOT NULL DEFAULT 'unknown',
        confidence INTEGER NOT NULL DEFAULT 0 CHECK(confidence BETWEEN 0 AND 100),
        first_seen_at TEXT,
        published_at TEXT,
        detected_at TEXT,
        summary TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS incident_observations (
        incident_id TEXT NOT NULL,
        observation_id TEXT NOT NULL,
        relation_type TEXT NOT NULL DEFAULT 'candidate',
        confidence INTEGER NOT NULL DEFAULT 0 CHECK(confidence BETWEEN 0 AND 100),
        rationale TEXT NOT NULL DEFAULT '',
        PRIMARY KEY(incident_id, observation_id),
        FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
        FOREIGN KEY(observation_id) REFERENCES observations(observation_id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS evidence (
        evidence_id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        observation_id TEXT,
        evidence_type TEXT NOT NULL DEFAULT 'other',
        source_independence_group TEXT NOT NULL DEFAULT '',
        assertion TEXT NOT NULL DEFAULT '',
        confidence INTEGER NOT NULL DEFAULT 0 CHECK(confidence BETWEEN 0 AND 100),
        rationale TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
        FOREIGN KEY(observation_id) REFERENCES observations(observation_id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS actors (
        actor_id TEXT PRIMARY KEY,
        canonical_name TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL DEFAULT '',
        first_seen_at TEXT,
        last_seen_at TEXT,
        profile_json TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS actor_aliases (
        actor_id TEXT NOT NULL,
        alias TEXT NOT NULL,
        source_url TEXT NOT NULL DEFAULT '',
        confidence INTEGER NOT NULL DEFAULT 0 CHECK(confidence BETWEEN 0 AND 100),
        PRIMARY KEY(actor_id, alias),
        FOREIGN KEY(actor_id) REFERENCES actors(actor_id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS incident_actors (
        incident_id TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        relation_type TEXT NOT NULL CHECK(relation_type IN
            ('claimed','reported','suspected','confirmed')),
        confidence INTEGER NOT NULL DEFAULT 0 CHECK(confidence BETWEEN 0 AND 100),
        rationale TEXT NOT NULL DEFAULT '',
        evidence_ids_json TEXT NOT NULL DEFAULT '[]',
        PRIMARY KEY(incident_id, actor_id, relation_type),
        FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
        FOREIGN KEY(actor_id) REFERENCES actors(actor_id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS incident_relations (
        relation_id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        related_incident_id TEXT NOT NULL,
        relation_type TEXT NOT NULL,
        confidence INTEGER NOT NULL DEFAULT 0 CHECK(confidence BETWEEN 0 AND 100),
        rationale TEXT NOT NULL DEFAULT '',
        evidence_ids_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        CHECK(incident_id <> related_incident_id),
        FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
        FOREIGN KEY(related_incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS discovery_items (
        discovery_id TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        summary TEXT NOT NULL DEFAULT '',
        period_start TEXT,
        period_end TEXT,
        baseline_start TEXT,
        baseline_end TEXT,
        observed_count INTEGER,
        expected_count REAL,
        confidence INTEGER NOT NULL DEFAULT 0 CHECK(confidence BETWEEN 0 AND 100),
        rationale TEXT NOT NULL DEFAULT '',
        coverage_notes TEXT NOT NULL DEFAULT '',
        related_incidents_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'new'
    );
    CREATE TABLE IF NOT EXISTS observation_duplicate_reviews (
        pair_key TEXT PRIMARY KEY,
        observation_id TEXT NOT NULL,
        candidate_observation_id TEXT NOT NULL,
        decision TEXT NOT NULL CHECK(decision IN ('separate','same_incident_candidate')),
        rationale TEXT NOT NULL DEFAULT '',
        reviewed_at TEXT NOT NULL,
        CHECK(observation_id < candidate_observation_id),
        FOREIGN KEY(observation_id) REFERENCES observations(observation_id) ON DELETE CASCADE,
        FOREIGN KEY(candidate_observation_id) REFERENCES observations(observation_id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS incident_candidate_keys (
        candidate_key TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
    );
    """)
    con.execute(
        "INSERT OR IGNORE INTO intelligence_schema_version(version, applied_at) VALUES(1, ?)",
        (datetime.now(timezone.utc).isoformat(),),
    )
    con.commit()
    return con


def upsert_source(source: dict, db_path: str | Path | None = None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    con = init(db_path)
    con.execute("""
        INSERT INTO intel_sources
        (source_id,name,category,source_class,reliability,language,enabled,
         provenance_group,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?)
        ON CONFLICT(source_id) DO UPDATE SET
          name=excluded.name, category=excluded.category,
          source_class=excluded.source_class, reliability=excluded.reliability,
          language=excluded.language, enabled=excluded.enabled,
          provenance_group=excluded.provenance_group, updated_at=excluded.updated_at
    """, (
        str(source.get("id") or source.get("source_id") or "unknown"),
        str(source.get("name") or source.get("id") or "Unknown source"),
        str(source.get("category") or "unknown"),
        str(source.get("source_class") or "unknown"),
        str(source.get("reliability") or "unrated"),
        str(source.get("language") or "unknown"),
        int(bool(source.get("enabled", True))),
        str(source.get("provenance_group") or ""),
        now,
    ))
    con.commit()
    con.close()


def save_observation(item: dict, db_path: str | Path | None = None) -> bool:
    """Insert an observation once. Returns False for an already-seen ID."""
    now = datetime.now(timezone.utc).isoformat()
    source_id = str(item.get("source_id") or "unknown")
    con = init(db_path)
    # Unknown sources are registered conservatively instead of losing the observation.
    con.execute("""
        INSERT OR IGNORE INTO intel_sources
        (source_id,name,updated_at) VALUES(?,?,?)
    """, (source_id, source_id, now))
    cur = con.execute("""
        INSERT OR IGNORE INTO observations
        (observation_id,source_id,source_class,url,title,summary,published_at,
         observed_at,assertion_type,language,payload_json,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        str(item["observation_id"]), source_id,
        str(item.get("source_class") or "unknown"),
        str(item.get("url") or ""), str(item.get("title") or ""),
        str(item.get("summary") or ""), item.get("published_at"),
        item.get("observed_at"), str(item.get("assertion_type") or "unverified"),
        str(item.get("language") or "unknown"),
        json.dumps(item, ensure_ascii=False, sort_keys=True), now,
    ))
    con.commit()
    inserted = cur.rowcount == 1
    con.close()
    return inserted


def list_observations(limit: int = 100, db_path: str | Path | None = None) -> list[dict]:
    con = init(db_path)
    rows = con.execute("""
        SELECT observation_id,source_id,source_class,url,title,summary,published_at,
               observed_at,assertion_type,language,payload_json,created_at
        FROM observations ORDER BY COALESCE(published_at, observed_at, created_at) DESC
        LIMIT ?
    """, (max(1, min(int(limit), 1000)),)).fetchall()
    con.close()
    result = []
    for row in rows:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        result.append(item)
    return result
