# Tor Watch Intelligence Engine — Phase 1–3 Specification

## Scope
This specification covers the first nine roadmap items: collection/source inventory, canonical observations and incidents, actor profiles, incident timelines, evidence confidence, duplicate corroboration, cross-incident relationships, and discovery signals. Investment analysis is explicitly out of scope.

## Design principles
1. Preserve every source observation; never overwrite source evidence with an analyst interpretation.
2. Distinguish an attacker's claim, independent reporting, and an affected organization's official statement.
3. Treat automated incident matching and actor attribution as candidates, never as facts.
4. Keep incident severity separate from evidence confidence.
5. Record why a discovery was generated, the comparison window, and source-coverage limitations.
6. Continue using SQLite and preserve legacy `pages`, `events`, and `threat_items` tables during migration.
7. Collect public metadata only. Do not download leaked files, contact threat actors, bypass access controls, or crawl unregistered onion services.

## Canonical data flow
`source -> observation -> incident candidate -> reviewed incident -> actor/entity relations -> correlation -> discovery`

### Observation
An immutable record of a single source item: stable ID, source ID, URL, title, published/observed timestamps, language, source class, raw metadata, and extraction notes.

### Incident
A normalized case record with victim/entity, country, sector, event types, first-seen/published/detected timestamps, status, and confidence. Incident IDs are internal identifiers; candidate matching must not automatically prove two reports describe the same event.

### Evidence and confidence
Store evidence items with source class, canonical URL, source independence group, evidence type, and assertion. Confidence is an explainable assessment, not a probability. Syndicated copies count as one origin. Severity and confidence are separate fields.

### Actor attribution
Relations use `claimed`, `reported`, `suspected`, or `confirmed`, with supporting evidence references. Similar tooling or TTPs alone must not establish actor identity.

### Incident relations
Typed edges include `same_incident_candidate`, `same_actor`, `shared_ttp`, `shared_vulnerability`, and `temporal_cluster`. Every edge carries confidence, rationale, and evidence references.

### Discovery
Each discovery includes category, title, summary, affected period, baseline period, observed and expected counts, source-coverage notes, confidence, rationale, and related incident IDs. A source-volume increase must be distinguished from an incident-rate increase.

## Phases and acceptance criteria
### Phase 1 — Foundation (items 1–3)
- Inventory current collectors, storage, export, UI, and tests.
- Expand sources through configuration and isolated per-source failure handling.
- Normalize observations and incident candidates without deleting legacy history.

### Phase 2 — Investigation (items 4–6)
- Maintain actor profiles and aliases with provenance.
- Build incident timelines from dated observations and official statements.
- Assess evidence confidence with source independence and explicit rationale.

### Phase 3 — Discovery (items 7–9)
- Detect duplicate/syndicated reports conservatively and allow separation.
- Build typed, evidence-backed relations between distinct incidents.
- Detect new, recurring, rising, and anomalous patterns with coverage-aware baselines.

## Implemented investigation and discovery behavior
- Actor profiles are canonical-name records with aliases, public HTTPS provenance, and separate 'claimed', 'reported', 'suspected', or 'confirmed' incident links. Creating a profile does not attribute an incident.
- Incident timelines retain the original observation, publication/observation timestamp, source class, assertion type, provenance group, and the reason for each incident link.
- Evidence strength counts each independent provenance group once. Contribution weights are conservative (official 35, government advisory 25, media report 15, attacker claim 5), multiplied by the recorded evidence rating. Attacker-only evidence is capped at 15/100. This is an explainable strength score, not a probability.
- Duplicate candidates are generated only for matching canonical URLs or near-identical titles (similarity at least 0.94) within 14 days. Observations are never merged automatically; a reviewer can explicitly keep a pair separate.
- Incident relationships are typed and require evidence references plus a rationale. Evidence must belong to one of the linked incidents.
- Discovery compares stable 30-calendar-day windows. It labels patterns as new, recurring, rising, or anomalous, adjusts expected counts for the number of independent source groups, and records coverage caveats.
- The scheduled Pages workflow runs migration, candidate generation, evidence assessment, and discovery before exporting intelligence_discoveries and intelligence_incidents to the dashboard. The dashboard presents discoveries and investigation candidates separately from monitoring severity.

## Out of scope
Investment decisions, portfolio recommendations, leaked-file acquisition, attacker interaction, credential collection, access-control bypass, and unbounded crawling.

## Rollout
Additive SQLite migrations only. Keep existing exports backward-compatible. Each roadmap item is complete only after unit tests and the relevant GitHub Actions run succeed. Feature scope freezes after item 9 of this intelligence-engine roadmap. No additional feature scope is added after acceptance; only defects and security fixes remain in scope.
