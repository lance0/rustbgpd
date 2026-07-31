# ADR-0110: IRR/PeeringDB-driven filtering pipeline — ride arouteserver, defer native ingestion

**Status:** Accepted (phase-1 renderer shipped as `tools/rs-config-render`; the
M90 arouteserver/BIRD-vs-rustbgpd filtering differential is archived in
`docs/INTEROP.md`; native ingestion remains demand-gated)
**Date:** 2026-07-17

## Context

The single biggest gap between rustbgpd and the incumbent IXP route-server
stack (BIRD + arouteserver) is not a protocol feature — it is the
data-driven filtering pipeline. MANRS IXP Programme Action 1 and RFC 7948
§4.6.2 expect a route server to accept from each member only routes whose
prefixes and origin ASNs are authorized by that member's registered IRR
objects (as-set/route-set, merged with RPKI ROAs), with max-prefix ceilings
sourced from PeeringDB when not explicitly configured — all refreshed on a
schedule. No major IXP operates a route server without this loop.

rustbgpd ships the **matcher** but none of the **ingest**. The `.rpol`
substrate already holds and evaluates generated filters efficiently:
`prefix-set` (trie-backed, `ge`/`le` bounds), `asn-set`, `community-set`,
and external `dataset` files bound via `[policy.datasets.<name>]` that swap
atomically on refresh (generation bump, dependency-scoped peer refresh,
prior snapshot retained on a failed load). Config reload is
parse-then-swap: a candidate config is built and validated, and only
committed on success — a bad `.rpol` file is a hard load error that leaves
the running policy untouched. `rustbgpd --check` validates a candidate
offline and `--diff` previews what a reload would change. What does not
exist anywhere in the tree: bgpq4/IRRd invocation, RPSL/whois parsing,
PeeringDB API access, or any scheduled filter regeneration. Operators must
hand-author every prefix-set.

What the incumbents actually run: **arouteserver** resolves each client's
as-set via bgpq4 against IRRd mirrors (NTT by default, with failover),
merges RPKI ROAs as route objects, pulls max-prefix and as-set names from
PeeringDB net objects, caches everything with per-source expiries
(12–24 h), and renders per-daemon configuration from Jinja2 template
packages — for exactly two targets, BIRD and OpenBGPD. The deployment loop
at real IXPs is cron: regenerate → daemon parse-check (`bird -p` /
`bgpd -n`) → swap → reload; on any data-source failure arouteserver exits
non-zero and the last good config stays live (fail-stale, never
fail-open). Its `tag`/`tag_and_reject` reject policies attach a
reject-reason community consumed by Alice-LG and InvalidRoutesReporter.

Two structural facts constrain the options:

1. **arouteserver has no plugin path.** A target is a hard-coded builder
   subclass plus an in-tree template package plus an integration-test
   suite (~900 checks for BIRD, ~450 for OpenBGPD). Adding rustbgpd means
   a PR into `pierky/arouteserver` accepted at the maintainer's
   discretion. The only precedent — Netnod's GoBGP fork, built for their
   production dual-vendor RS platform — has been "hopefully merged
   upstream in the future" per the upstream README for years and never
   merged. Gating adoption on upstream acceptance is gating it on a
   variable this project does not control.
2. **arouteserver exposes its fully-resolved data model.** The
   `template-context` builder dumps every variable the target templates
   consume — the expanded per-client IRR prefix/origin sets, PeeringDB
   max-prefix values, community plan, client list, all knobs from
   `general.yml`/`clients.yml` — as a documented, renderable context. A
   tool that consumes this dump inherits arouteserver's entire ingest
   pipeline (bgpq4 plumbing, IRRd failover, PeeringDB auth/caching, RPKI
   merge, EuroIX/IX-F client import) without touching upstream. bgpq4
   itself also emits JSON (`-j`) and a user-defined format (`-F`), so a
   direct bgpq4-to-rpol converter is equally mechanical if ever needed.

## Options

### A. Become an arouteserver output target (upstream)

Write the builder subclass, a full Jinja2 template package emitting
rustbgpd TOML + `.rpol`, and the integration suite; PR it upstream.

- **For:** maximum ecosystem credibility — "supported by arouteserver" is
  the sentence IXP operators want to read; zero ingest code to maintain
  here; every arouteserver feature and future fix flows for free.
- **Against:** blocked on upstream review with no plugin escape hatch and
  a negative precedent (GoBGP); the review bar (CI parity with ~900 BIRD
  checks) is a large up-front spend that produces nothing usable until
  merged; a maintained fork à la Netnod is a permanent rebase treadmill —
  the worst of both worlds for a solo maintainer.

### B. Native ingestion pipeline

A rustbgpd-side tool or daemon feature that invokes bgpq4 (or speaks
RPSL/whois natively), queries the PeeringDB API, and regenerates rpol
prefix-set/asn-set overlays and max-prefix values on a timer with atomic
apply through the existing reload seam.

- **For:** full control; no external Python dependency; daemon-native UX
  (one binary, one config); could eventually exceed arouteserver (live
  RTR-coupled refresh, per-term hit-counter-driven staleness insight).
- **Against:** rebuilds, alone, what a well-maintained upstream project
  already does for the whole industry — IRRd source failover, PeeringDB
  API keys/throttling/caching, RPKI-as-route-object merge, bogon
  curation, EuroIX import, and the long tail of IXP-operational knobs
  (RTT communities, client blacklists, reject-cause maps). That is a
  permanent parallel-maintenance surface against moving external data
  sources, plus a new supply-chain trust boundary (remote IRR/PeeringDB
  data flowing into policy) to secure from scratch. Largest
  time-to-credible-deployment of the three; an IXP evaluating rustbgpd
  would still have to abandon its existing arouteserver workflow.

### C. Hybrid: render from arouteserver's context now, native pieces only on demand

Ship an external renderer (working name `rs-config-render`, under
`tools/`) that consumes `arouteserver template-context` output and emits
rustbgpd configuration: generated `.rpol` files (per-client prefix/origin
sets, hygiene terms, community plan) plus the TOML neighbor/max-prefix
skeleton. Document the cron loop using the daemon's existing gates. Offer
the template package upstream *after* it is proven, as a fait accompli
with a pilot transcript — the strongest possible PR, and useful even if
never merged.

- **For:** shortest time-to-credible-deployment — the IXP keeps its
  existing `general.yml`/`clients.yml`, adds one render step, and its
  operational loop (cron, parse-check, fail-stale) transfers verbatim;
  no upstream gate on the critical path; the renderer is a template, not
  an ingest engine — small, testable, boring; every arouteserver data
  feature is inherited.
- **Against:** the pipeline depends on arouteserver (Python) and bgpq4
  remaining healthy — acceptable: they are the industry substrate, and
  the dependency is generate-time, not runtime; `template-context`
  output shape is not a semver-stable API, so the renderer needs a
  context-fingerprint check the way arouteserver fingerprints its own
  templates; "not listed on arouteserver's supported-speakers page" until
  an upstream merge happens.

## Decision

**Option C.** Concretely:

1. **The apply seam is the existing overlay machinery — no new daemon
   mechanism.** Generated artifacts are ordinary `.rpol` files (and
   `dataset` snapshot files where churn is high) referenced from a stable
   hand-written TOML; refresh is the proven loop
   `render → rustbgpd --check → swap → SIGHUP`, with the parse-then-swap
   commit guaranteeing a bad render can never evict working policy.
   Nothing in the daemon learns to speak to IRR or PeeringDB.
2. **Fail-stale, never fail-open; staleness is alarmed, not tolerated
   silently.** A render failure (arouteserver non-zero exit, bgpq4
   timeout, PeeringDB outage, context-fingerprint mismatch, `--check`
   failure) leaves the last good config live and untouched — matching
   incumbent practice. An **empty or shrunken-to-implausibility
   generated set aborts the render** rather than deploying (an empty
   per-client prefix-set under a default-reject term is fail-closed for
   that client; an empty set feeding an accept-shaped term would be
   fail-open — the renderer refuses both by aborting, and per-client
   generated policy always ends default-reject). The renderer writes a
   receipt (timestamp, per-source data ages, set cardinalities) beside
   its output; the daemon exposes dataset/overlay generation age so a
   pipeline stuck for more than N refresh intervals pages someone
   instead of rotting.
3. **Native ingestion is deferred behind a demand trigger, not planned.**
   The un-defer trigger is a concrete deployment that cannot run the
   arouteserver toolchain (platform constraint or policy) — not
   aesthetics. If it fires, the first native piece is a bgpq4-JSON→rpol
   converter (mechanical; the JSON shape is the same one arouteserver
   parses) and the second is PeeringDB max-prefix fetch; full RPSL/whois
   parsing is expected never to clear the bar.
4. **Upstreaming is phase-last and optional.** After a pilot proves the
   template package, offer it to `pierky/arouteserver`. Merged: rustbgpd
   appears in the supported-speakers matrix. Not merged: the renderer
   keeps working from `template-context`, and the docs say so plainly.

### Capability checklist: arouteserver features → rustbgpd primitives

What the generated configuration needs from the daemon, axis by axis from
arouteserver's supported-speakers matrix. Status reflects current daemon and
renderer truth separately where the daemon primitive ships but the renderer
still refuses an untranslated mode.

| arouteserver feature | rustbgpd primitive | Status |
|---|---|---|
| Path-hiding mitigation (RFC 7947 §2.3) | `per_client_best` + Add-Path send (`add_path.send`/`send_max`) | Shipped (ADR-0101) |
| AS_PATH/MED/NEXT_HOP transparency | `route_server_client` transport seam | Shipped (ADR-0039/0101) |
| IRR prefix filters (RFC 7948 §4.6.2) | generated `prefix-set` / `dataset` per client, trie-matched | Shipped substrate; sets are generated content |
| IRR origin-AS enforcement | `route.origin-as` accessor (`==`/`!=`/asn-set `in`, three-valued on absent origin) + indexed `asn-set` | Shipped (#757; the gap claimed in earlier drafts was stale — verified end-to-end with docs and tests) |
| RPKI ROA validation via RTR (RFC 6811/8097) | `[rpki.cache_servers]`, `route.rpki == valid\|invalid\|not-found`, `OV_*` ext-community tagging | Shipped |
| RPKI ROAs merged as route objects | generator-side (arouteserver does the merge) | N/A to daemon |
| Max-prefix, per client per family | `max_prefixes_ipv4`/`_ipv6` (+aggregate), Cease/1 with RFC 4486 data | Shipped (ADR-0108), including ARouteServer's OpenBGPD-style timed `restart` action with checked minute-to-second conversion |
| NEXT_HOP enforcement, `strict` | pre-policy ownership gate | Shipped (`next_hop_ownership = "strict_peer"`; ADR-0107) |
| NEXT_HOP enforcement, `same-as` | fleet inventory mode | **Gap:** explicitly deferred by ADR-0107 until the inventory exists; renderer must reject `next_hop.policy: same-as` until then |
| Max AS_PATH length | `match_as_path_length_le` / `route.as-path.len` | Shipped |
| Invalid/private/bogon ASNs, transit-free ASNs, never-via-RS ASNs (PeeringDB) | generated `asn-set` + `route.as-path contains` terms | Shipped substrate; sets are generated content |
| Bogon prefixes | generated `prefix-set` (hygiene example already ships one) | Shipped substrate |
| Reject-AS_SET segments | `route.as-path matches "\\{"` hygiene term | Shipped |
| Control communities: announce/do-not-announce/prepend to any/peer; NO_EXPORT/NO_ADVERTISE add | community-based announcement control | Shipped: standard and large announce/suppress/override forms, large-community prepend, egress scrub, and route-granular grouped sharing; policy can add the well-known communities |
| RTT-based communities | none — no RTT source in the daemon | **Permanent reject** (recorded in ADR-0101); renderer errors if the site config uses them |
| Informational communities (IRRDB pass/fail tags, custom) | rpol `add community`/`large-community`/`ext-community` | Shipped |
| Reject policy `reject` | default-reject term tail | Shipped |
| Reject policy `tag` (keep, low pref, reason community) | `set local-pref` + `add community`, no reject | Expressible in daemon policy; renderer still refuses this mode until its tag translation semantics are defined |
| Reject policy `tag_and_reject` (BIRD-only; feeds Alice-LG) | native reject-reason retention plus renderer reason-community translation | Native bounded retention, `PolicyService.ListRejectedRoutes`, CLI, and the Birdwatcher filtered view are shipped; the separate noexport view is backed by export-explain truth; renderer still refuses `tag` and `tag_and_reject` until the community translation semantics exist |
| BLACKHOLE handling (RFC 7999) + propagation control | `honor_blackhole`, policy next-hop rewrite; per-client propagation via control communities | Shipped, including control-community propagation. ADR-0107 makes BLACKHOLE explicitly not an ownership bypass |
| GRACEFUL_SHUTDOWN recv (RFC 8326) | `honor_graceful_shutdown` | Shipped |
| `--perform-graceful-shutdown` of the RS itself | generator emits a temporary config; daemon needs nothing new | N/A to daemon |
| ADD_PATH (RFC 7911) | `add_path` per neighbor/group | Shipped |
| Passive/active sessions, GTSM, multihop | listener + socket knobs (ADR-0016/0019) | Shipped |
| RFC 8950 IPv6 next hop for IPv4 | extended-nexthop (ADR-0037) | Shipped (BIRD-1.x and OpenBGPD lack this) |
| 16/32-bit ASN community forms, large communities (RFC 8092) | standard/extended/large community model | Shipped |
| Client blacklists | omit neighbor from generated TOML | Trivial |
| Operator local-customization hooks (`.local` files) | rpol `import` + `rpol_roots` for policy; **TOML has no include** — the renderer owns the whole TOML and must provide merge-in points itself | Design point for the renderer, not a daemon gap |

Summary: the daemon primitives needed for a pilot are shipped except the
explicitly deferred NEXT_HOP same-AS inventory mode. The renderer remains
fail-closed on `tag` and `tag_and_reject` because their translation semantics
are not implemented. The external IXP pilot and optional upstream contribution
are still pending; active ceilings remain accepted-route-only.

### Delivery plan

**Phase 1 — pilot-ready renderer (each bullet files as one issue):**

1. `rs-config-render` under `tools/`: consume `arouteserver
   template-context` output, emit `config.toml` + per-client `.rpol`
   (basic filters, IRR prefix/origin sets, max-prefix, RPKI knobs,
   `reject`/`tag` policies), refuse unsupported knobs loudly
   (RTT communities, `same-as`, `tag`, `tag_and_reject`), fingerprint the
   consumed context shape, abort on empty/implausible sets, write the
   refresh receipt. *Delivered: `tools/rs-config-render/` (reject
   policy only; `tag` and `tag_and_reject` are refused pending renderer
   translation semantics).*
2. Refresh-loop cookbook: cron cadence, `--check` gate, SIGHUP,
   fail-stale semantics, staleness alerting; extends the existing
   route-server example. *Delivered:
   `docs/cookbook/ixp-filter-pipeline.md` §3 — fail-stale cron loop,
   per-exit-code alerting matrix, cadence guidance, freshness-metric
   wiring.*
3. Differential interop lab (M-series): one `general.yml`/`clients.yml`
   drives both a BIRD instance (via arouteserver proper) and rustbgpd
   (via the renderer); a canned announcement set must produce identical
   accept/reject verdicts across both, with the daemon's explain output
   naming the generated term for every rejection. *Delivered: M90 proves
   11/11 verdict parity, exact generated policy/term attribution, and a
   red-producing policy mutation.*
4. Overlay/dataset freshness observability: expose generation timestamp
   and age for reloaded policy artifacts, so "pipeline stuck" is a
   metric, not a surprise. *Delivered:*
   `bgp_policy_generation_loaded_timestamp_seconds` (last successful
   full policy apply) and
   `bgp_policy_dataset_loaded_timestamp_seconds{dataset}` (last
   accepted dataset swap), both frozen across rejected loads;
   alert expressions in `OPERATIONS.md` ("Policy artifact
   freshness").

**Phase 2 — external proof and upstream:** run the still-pending IXP pilot,
retain its transcript, then optionally offer the proven template package and
builder upstream.

**Phase 3 — demand-gated:** bgpq4-JSON→rpol native converter; PeeringDB
max-prefix autofetch; NEXT_HOP same-AS once the ADR-0107 inventory
exists.

## Non-goals

- Reimplementing IRR resolution (RPSL parsing, whois transport, IRRd
  mirroring) or PeeringDB sync inside the daemon or the renderer — the
  renderer starts strictly downstream of arouteserver's resolved context.
- A daemon-resident scheduler for filter refresh; cron plus the reload
  seam is the industry loop and already fail-stale.
- Maintaining a long-lived arouteserver fork.
- RTT-based community steering (no RTT source; recorded permanent reject).
- Generalizing the renderer beyond route-server deployments (no RR/EVPN
  templating).

## Consequences

- Time-to-credible-IXP-pilot collapses to renderer + lab work on our
  side; the operator-visible story is "keep your arouteserver workflow,
  point it at rustbgpd."
- The project takes a generate-time dependency on arouteserver/bgpq4 —
  the same dependency every incumbent deployment already carries — and a
  fingerprint check absorbs `template-context` shape drift.
- The residual gaps stay explicit: ADR-0107 same-AS remains deferred;
  renderer `tag` and `tag_and_reject` translation remains fail-closed;
  external pilot/upstream work remains pending; native ingestion remains
  demand-gated.
- Security boundary is explicit: external registry data enters only as
  generated sets behind a validating renderer and the daemon's
  parse-then-swap gate; a compromised or empty upstream answer can
  withhold updates (stale, alarmed) but cannot open the filter.
- If upstream accepts the target later, the renderer's template package
  is the contribution; if not, nothing here is wasted.

## References

- MANRS IXP Programme, Action 1 (filtering of route announcements)
- RFC 7947 (route-server operation), RFC 7948 §4.6.2, §4.8 (operations)
- arouteserver: <https://github.com/pierky/arouteserver>, supported
  speakers/features matrix at
  <https://arouteserver.readthedocs.io/en/latest/SUPPORTED_SPEAKERS.html>,
  usage/deployment loop at
  <https://arouteserver.readthedocs.io/en/latest/USAGE.html>
- bgpq4: <https://github.com/bgp/bgpq4> (JSON `-j`, user format `-F`)
- Netnod GoBGP target fork (unmerged precedent):
  <https://github.com/netnod/arouteserver>
- [ADR-0101](0101-route-server-profile.md) — route-server profile,
  arouteserver-target deferral and RTT-community reject
- [ADR-0107](0107-route-server-next-hop-ownership.md) — NEXT_HOP
  ownership (`strict_peer` shipped; same-AS deferred)
- [ADR-0108](0108-per-family-max-prefix-limits.md) — per-family max-prefix and timed restart
