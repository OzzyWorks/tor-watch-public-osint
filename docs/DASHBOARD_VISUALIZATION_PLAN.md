# Dashboard Visualization Roadmap

## Goal
Turn the existing information-rich dashboard into a visual threat-intelligence overview that answers, at a glance:
1. What changed?
2. Which companies/sectors are most represented in the observed data?
3. Which incidents, actors, and reports may be connected?
4. What needs human verification?

This is a presentation project only. It does not add collectors, change risk scoring, or expand the intelligence engine.

## Fixed scope: 4 milestones

| # | Milestone | Deliverables | Acceptance |
|---|---|---|---|
| 1 | Executive overview | Visual KPI tiles; 30-day/24-hour activity trend; clear status and coverage caveats | Uses exported data only; empty/insufficient history is labelled; mobile layout works |
| 2 | Company and sector overview | Ranked company bars; sector/category distribution where source data supports it; activity comparison | No inferred sector labels; unknown values remain explicit; charts link to underlying records |
| 3 | Incident relationship view | Interactive SVG relationship map for existing typed, evidence-backed relations; readable incident/actor/source detail list | Every edge shows relation type and evidence/rationale; no unsupported actor attribution; list fallback works |
| 4 | Final integration and release | Responsive/accessibility pass; data-shape and rendering tests; Pages deployment verification | Existing monitoring panels remain available; Actions and Pages deployment succeed |

## Visual design direction
- Dark analyst-console aesthetic, but with stronger hierarchy, restrained accent colours, larger charts, and more whitespace.
- Summary first; detail panels below.
- Prefer charts and compact visual comparisons over repeated text rows.
- Keep the existing collapsible monitoring-health section.
- Mobile-first responsive behavior: charts stack and relationship details remain readable without horizontal scrolling.

## Data and safety rules
- Use only fields already exported by `scripts/export_web.py`, adding export fields only when the underlying database already contains them.
- Never fabricate counts, baselines, sectors, or relationships.
- Distinguish collection health, threat severity, and evidence strength.
- Label automated results as candidates; public reporting is not proof of victim impact.
- Relationship edges must retain their type, rationale, and evidence references.
- No new data sources, collection behavior, risk model, or investment analysis.

## Execution rules
- Complete milestones in order; do not add extra feature tasks.
- Each milestone is one bounded PR or a small number of directly related commits.
- Run unit tests and dashboard validation before merging.
- Stop after milestone 4. Afterwards, only fix defects or security issues.

## Progress
- [x] Plan fixed and committed to the visualization branch.
- [ ] 1/4 Executive overview.
- [ ] 2/4 Company and sector overview.
- [ ] 3/4 Incident relationship view.
- [ ] 4/4 Final integration and release.
