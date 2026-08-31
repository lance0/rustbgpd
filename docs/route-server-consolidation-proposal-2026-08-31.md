# Route-server documentation consolidation proposal — 2026-08-31

> **Document class: HISTORICAL.** This page preserves a dated documentation analysis; its repository and website snapshots bound every recommendation.

**Status:** proposal only. No consolidation, redirect, move, rename, or source-page
edit is authorized by this document.

This analysis covers rustbgpd at
`096a8c1426d946114504f7df4d1716f07f671f9c` and the rbgp.rs ingestion site at
`c3de966a20acfd83ffe71007e3d69bd127e27553`.

## URL and mirror constraints

| Source document | rbgp.rs treatment | Constraint |
|-----------------|-------------------|------------|
| [`cookbook/route-server.md`](cookbook/route-server.md) | Native page at `/docs/cookbook/route-server` | Keep the source path and the `shadow-trial` anchor |
| [`cookbook/route-server-migration.md`](cookbook/route-server-migration.md) | Native page at `/docs/cookbook/route-server-migration` | Keep the source path and the `cutover-checklist` anchor |
| [`cookbook/route-server-shadow-pilot.md`](cookbook/route-server-shadow-pilot.md) | Native page at `/docs/cookbook/route-server-shadow-pilot` | Keep the source path; it owns open-ended, non-authoritative evaluation |
| [`cookbook/ixp-filter-pipeline.md`](cookbook/ixp-filter-pipeline.md) | Native page at `/docs/cookbook/ixp-filter-pipeline` | Keep the source path; it owns the ARouteServer workflow |
| [`ixp-evaluation.md`](ixp-evaluation.md) | Not ingested; mirrored pages rewrite its link to GitHub | Do not move native instructions here |
| [`cookbook/ixp-manager-route-server.md`](cookbook/ixp-manager-route-server.md) | Not ingested; mirrored pages rewrite its link to GitHub | Do not move native instructions here |

The rbgp.rs site snapshot is a static export, and its `next.config.ts` and
`vercel.json` define no redirects. A future consolidation therefore must
preserve the existing native paths and anchors instead of assuming an HTTP
redirect can repair a move.

## One candidate worth considering

The detailed procedure under
[`route-server.md` — Shadow trial](cookbook/route-server.md#shadow-trial) and
the procedure under
[`route-server-migration.md` — Cutover checklist](cookbook/route-server-migration.md#cutover-checklist)
genuinely overlap. Both instruct the reader to:

- shadow-peer on a non-production listener;
- inspect received, sent, and explained route views;
- compare advertised views with `rbgp diff advertised`; and
- keep route and session counters quiet before changing authority.

### Proposed future edit

If approved in a later PR:

1. Make `route-server-migration.md#cutover-checklist` the canonical detailed
   procedure for a planned incumbent replacement.
2. Retain `route-server.md#shadow-trial` as a short routing stub. It should send
   planned cutovers to the migration checklist, send open-ended evaluations to
   the shadow-pilot guide, and keep the basic pre-production safety reminder.
3. Preserve the route-server-only checks when moving the shared detail:
   Add-Path versus per-client-best validation and before/after `rbgp doctor`
   support bundles.
4. Keep both filenames and both existing headings so current native URLs and
   unknown external deep links continue to resolve.

### Tradeoff and stop conditions

The gain is one canonical cutover checklist. The cost is that the hand-written
route-server recipe stops being self-contained for incumbent replacement and
requires one additional navigation step.

Reject the consolidation if it would remove either anchor, omit either unique
check, weaken the non-production-listener boundary, or make the standing shadow
pilot read like an implicit commitment to cut over.

No file or HTTP redirect is required if both paths and anchors remain. Deleting
the old `shadow-trial` anchor would require redirect support the site does not
currently have and would still risk unknown external deep links.

## Retain as distinct

| Apparent overlap | Decision | Why |
|------------------|----------|-----|
| IXP evaluation versus the five operator guides | Keep distinct | The evaluation is a capability scorecard with evidence links, not a deployment procedure |
| Three-way provisioning orientation repeated at entry points | Keep | The local reminder prevents selecting two mutually exclusive sources of configuration authority |
| Route-server IRR summary versus the IXP filter pipeline | Keep | The short section is a prerequisite pointer; the pipeline owns the procedure |
| Filtered-route summaries in the ARouteServer and IXP Manager guides | Keep | Both already delegate to the route-server guide's canonical troubleshooting detail |
| Migration baseline versus the route-server recipe | Keep | The compact target shape is needed beside vendor mappings and already points to the full recipe |
| Shadow pilot versus migration | Keep distinct | One supports weeks or months of receive-only evaluation with no planned authority transfer; the other ends in staged cutover |
| Shadow-pilot deny-all configuration and ARouteServer overlay | Keep | These are safety-critical, mode-specific artifacts rather than duplicate production configuration |
| IXP Manager Birdwatcher guidance versus ARouteServer Alice-LG guidance | Keep distinct | They serve different consumers and have different alias, activation, and reload contracts |
| IXP Manager no-shadow boundary repeated in the shadow-pilot guide | Keep | Repetition preserves an operator-visible limitation at both decision points |

## Human decisions required

1. Approve or reject the one surgical checklist consolidation.
2. Decide whether one-click navigation from the hand-written route-server
   recipe is an acceptable cost for a single canonical cutover procedure.
3. If approved, authorize a separate content PR that preserves both paths,
   both anchors, every safety boundary, and the two route-server-only checks.
4. Treat any future site-wide redirect facility as separate work; it is not
   needed for, and should not be bundled with, this proposal.

Until those decisions are made, all six documents remain the current source of
truth for their existing scope.
