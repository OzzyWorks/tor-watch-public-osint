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
| 1 | Executive overview | Existing executive summary retained; 14-day daily event trend; clear status and coverage caveats | Uses exported data only; empty/insufficient history is labelled; mobile layout works |
| 2 | Company and sector overview | Ranked company bars; sector/category distribution where source data supports it; activity comparison | No inferred sector labels; unknown values remain explicit; charts link to underlying records |
| 3 | Incident relationship view | SVG relationship map for available candidate relations; visible relation type and rationale list | Displayed edges are labelled as candidates; rationale is visible where supplied; no unsupported actor attribution |
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
- [x] 1/4 Executive overview: existing executive summary plus 14-day event trend.
- [x] 2/4 Company and sector overview: company ranking, source-backed sector distribution, and group activity bars.
- [x] 3/4 Incident relationship view: SVG candidate network with relation-type/rationale detail.
- [x] 4/4 Final integration and release: unit tests and dashboard data/JavaScript validation passed; GitHub Pages deployment completed successfully.
