# Dashboard Visualization Roadmap

## Phase 1 — Overview and relationship map (completed 4/4)
The first release established the executive summary, event trend, company/sector/group comparisons, and evidence-backed candidate relationship map. It is documented in the original milestone table below.

## Phase 2 — Interactive analysis (this PR)
Goal: move from static charts to a dashboard where an analyst can change the time window and compare event activity and evidence depth without adding new collection or scoring logic.

| # | Deliverable | Acceptance |
|---|---|---|
| 1 | Linked 7/14/30/90-day period selector for trend, event mix, and daily activity calendar | All three views use the same selected period and exported event history only |
| 2 | Event-type composition chart | Counts distinguish new, changed, reclassified, and other events |
| 3 | Daily activity calendar | Zero-event days are visible; tooltips expose exact date and count |
| 4 | Evidence-depth scatter plot | Axes show independent source count and evidence count; bubble size shows observation count; colour shows the existing 0–100 evidence-strength value |
| 5 | External visualization validation | CI syntax-checks both inline dashboard JavaScript and the external visualization module |

## Data and interpretation rules
- Use only fields already exported by `scripts/export_web.py`.
- The period selector filters only event-history views; lifetime company, sector, group, and incident summaries remain explicitly separate.
- The 500-event export limit is disclosed where it affects the selected-period view.
- Evidence strength is an explainable assessment, not a probability. It must not be described as victim impact or breach likelihood.
- Empty history is labelled rather than fabricated. No inferred sectors, baselines, or relationships.
- No new collectors, data sources, risk scoring, actor attribution, or investment analysis.

## Visual design direction
- Dark analyst-console style with stronger hierarchy, larger visual comparisons, and mobile-first responsive layout.
- Summary first, interactive period controls directly above the charts, detail panels below.
- Keep monitoring health collapsed by default.
- Charts must remain readable on narrow screens and expose exact values through tooltips or adjacent labels.

## Original Phase 1 acceptance
| # | Milestone | Result |
|---|---|---|
| 1 | Executive overview: executive summary and 14-day daily event trend | Complete |
| 2 | Company and sector overview: company ranking, source-backed sector distribution, group activity | Complete |
| 3 | Incident relationship view: SVG candidate network with relation-type/rationale detail | Complete |
| 4 | Final integration and release: responsive layout, tests, Pages deployment | Complete |

## Execution boundary
This phase is a bounded presentation and validation change. Do not add more features after these deliverables; afterwards, only fix defects, accessibility regressions, or security issues.
