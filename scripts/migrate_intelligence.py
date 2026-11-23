"""Idempotently backfill legacy public RSS alerts into intelligence observations."""
from __future__ import annotations

from pathlib import Path

import yaml

from torwatch.intelligence_storage import save_observation, upsert_source
from torwatch.normalizer import normalize_observation
from torwatch.threat_intel import recent_public_alerts
from torwatch.config import CONFIG


def migrate_items(items: list[dict], sources: list[dict], db_path=None) -> int:
    """Backfill legacy alert rows without modifying or deleting the originals."""
    by_name = {}
    for source in sources or []:
        upsert_source(source, db_path=db_path)
        by_name[str(source.get("name") or source.get("id") or "")] = source

    inserted = 0
    for item in items or []:
        source_name = str(item.get("source") or "legacy_unknown")
        source = by_name.get(source_name, {})
        normalized = normalize_observation({
            "source_id": source.get("id") or source_name,
            "source_class": source.get("source_class") or "unknown",
            "language": source.get("language") or "unknown",
            "url": item.get("url"),
            "title": item.get("title"),
            "published": item.get("published"),
            "detected_at": item.get("detected_at"),
            "matched_assets": item.get("matched_assets"),
            "summary": item.get("summary") or "",
        })
        # Preserve legacy risk/status/reasons in the immutable payload for traceability.
        normalized["legacy_alert"] = {
            "id": item.get("id"),
            "risk": item.get("risk"),
            "reasons": item.get("reasons"),
            "status": item.get("status"),
        }
        inserted += int(save_observation(normalized, db_path=db_path))
    return inserted


def main() -> int:
    source_path = Path(CONFIG) / "sources.yml"
    config = yaml.safe_load(source_path.read_text(encoding="utf-8")) or {}
    count = migrate_items(recent_public_alerts(limit=10000), config.get("sources", []))
    print(f"Intelligence migration: {count} new observations")
    return count


if __name__ == "__main__":
    main()
