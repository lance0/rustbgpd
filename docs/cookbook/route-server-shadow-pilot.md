# Route-server shadow pilot — a standing non-authoritative deployment

> **Document class: CURRENT.**

The [migration cookbook](route-server-migration.md)'s shadow trial is a
step on the way to a cutover. This runbook is its standing big sibling:
rustbgpd runs for weeks or months beside a production BIRD or OpenBGPD
route server as a **non-authoritative second opinion** — no member
relies on it, no cutover is planned or implied, and tearing it down
restores the exchange to exactly its prior state. The goal is evidence:
does rustbgpd's view of your exchange match your incumbent's, on your
members, continuously?

What this pilot is **not**: a migration (no member session moves), a
benchmark (the performance receipts already exist and are linked, not
re-run here), or a commitment in either direction. rustbgpd is public
alpha; the support and proof boundaries in [`SUPPORT.md`](../../SUPPORT.md)
apply to everything below.

## Which mode are you in

rustbgpd route servers are provisioned in one of three mutually exclusive
modes — hand-written, ARouteServer-driven, IXP Manager-driven — chosen in
the [cookbook's fork](README.md#ixp-provisioning-three-modes). The pilot
posture below (an export chain that sends nothing, verified on every
revision) is expressed differently in each, and one of them cannot
express it at all. Decide this first:

| Your provisioning source | How the shadow is provisioned | Where the receive-only posture lives |
|---|---|---|
| None — you author members and policy | The hand-written [shadow config](#the-shadow-config) below: `examples/route-server/config.toml` reshaped, `rustbgpd --check --strict` on every revision | `export_chain = ["shadow-receive-only"]`, a deny-all TOML policy |
| arouteserver `general.yml`/`clients.yml` | The [IXP filter pipeline](ixp-filter-pipeline.md) render with a site-local overlay: `rs-config-render … --extra-rpol shadow-receive-only.rpol --merge-toml shadow-hooks.toml` → `--check --strict` → swap → SIGHUP ([below](#the-same-posture-from-arouteserver-data)) | The overlay's deny-all `.rpol` policy, which the renderer prepends to every member's export chain and attests in `render-receipt.json` |
| IXP Manager v7.4 | **Not from the IXP Manager path.** `rs-config-render --input-format ixp-manager-v2` refuses the site-local overlays, the Foil export has no receive-only knob, and the activation helper publishes only unmodified receipted candidates — so a candidate rendered from IXP Manager is always a production-posture, transparent route server. The pilot itself is the hand-written shadow (or the arouteserver overlay, if the site also runs arouteserver). What the IXP Manager path contributes to a pilot is a standing **render-and-check dry run** of your real member export ([below](#ixp-manager-sites-the-dry-run-that-is-also-evidence)) | The hand-written deny-all chain; the IXP Manager candidate is rendered, checked, and kept — never activated — during the pilot |

Whichever mode, the shadow runs on its own host with the daemon shipped in
the release tarball or package ([`deployment.md`](../how-to/deployment.md)), and
the operations below — topologies, verification, the comparison loop,
monitoring, teardown, data return — are identical.

## Zero blast radius, precisely

"Non-authoritative" is a config property here, not a promise:

- **No member relies on it.** Every member's production session to the
  incumbent is untouched. The shadow's sessions are additional, on the
  shadow's own host; the hand-written config also puts them on a
  non-production listener (`listen_port = 1179` below) so nothing can
  collide with TCP/179 on any host it shares. (The render modes emit
  `listen_port = 179` and are not hand-edited — give the shadow its own
  address.)
- **Receive-only from the operator's view.** The export chain is a
  single explicit deny-all policy (`shadow-receive-only`: no statements,
  `default_action = "deny"` in TOML; `term everything { reject }` in
  `.rpol`). Zero UPDATE messages leave the daemon toward any member —
  sessions carry OPEN and KEEPALIVE only. This is stronger than "members
  should filter it": there is nothing to filter.
- **The failure mode of a misedit is still silence.** With
  `ebgp_requires_policy = true` (RFC 8212,
  [ADR-0112](../adr/0112-rfc-8212-ebgp-requires-policy.md)) — set in the
  hand-written config and emitted by both renderers — deleting or
  misnaming the export chain does not fall back to permit-all: the
  reserved deny is installed and `rustbgpd --check` names the gap.
- **Verified, not asserted.** Every config revision must pass
  `rustbgpd --check --strict <config>` (exit 0 — warnings fail). At
  runtime, `rbgp rib sent <member>` must be empty for every member,
  `rbgp rib --prefix <p> advertised <member> --explain` shows the gate
  ladder stopping with `[STOP] export_policy` at the
  `shadow-receive-only` term, and the member's own session shows zero
  received prefixes. In the arouteserver mode, additionally confirm the
  receipt: `render-receipt.json` → `site_local.final_neighbors[*].export_policy_chain`
  begins with `shadow-receive-only` for every member.

The worst the shadow can do, by construction: hold a TCP session and
send keepalives. It never originates, propagates, or withdraws a route
anywhere.

## Two tap topologies

### A — member-fed: volunteers peer with the shadow

Volunteer members add a second BGP session to the shadow listener. The
shadow receives their real announcements first-hand and runs the exact
import hygiene the operator intends — or already runs on the incumbent:
IXPs on arouteserver render the same member filters with
[`rs-config-render`](../../tools/rs-config-render/README.md) and the
overlay below, so the shadow's import side is the production filter set
to the byte, attested by the same receipt.

This is the richest evidence: per-member received views, per-member
rejection ledgers, and real best-path selection over the volunteer set.
Its coverage is the volunteer set — comparisons involving routes from
non-volunteer members will show them missing on the shadow side, which
is expected and explainable (see the diff notes below).

### B — incumbent-fed: no member involvement at all

The incumbent route server peers with the shadow as if the shadow were
one more member (most route servers already carry a collector or
monitor session of this shape). The shadow receives the incumbent's
post-policy advertised view — one merged best-path feed — and applies
the intended import hygiene on top.

What this yields: a standing answer to *"what would my intended filters
reject that production carries today?"* (RPKI-invalids, hygiene
violations that predate the current filter set), plus daemon behavior
at the exchange's real table size. What it cannot yield: per-member
granularity or independent best-path evidence, because the incumbent's
own selection and export policy already ran. Members cannot even
observe that the shadow exists.

The two topologies compose: start with B (zero coordination), add A
taps as members volunteer. In both, MRT and BMP captures are used on
the **comparison side** (snapshots of the incumbent, next section) —
they are not a daemon input.

## The shadow config

Complete and validated (`rustbgpd --check --strict` exit 0 on the exact
text below). It is [`examples/route-server/config.toml`](../../examples/route-server/config.toml)
reshaped for the pilot: keep your intended production import hygiene;
only the listener and the export posture differ. Substitute addresses,
ASNs, and your real member filter set.

```toml
# Shadow-pilot route server: non-authoritative, receive-only.
# Derived from examples/route-server/config.toml — keep your intended
# production import hygiene; only the export posture and listener differ.

[global]
asn = 65500
router_id = "198.51.100.240"
# Non-production listener: never collides with the incumbent's TCP/179.
listen_port = 1179
# RFC 8212: with this on, losing the export chain below means the
# reserved deny — the failure mode of a misedit is still "send nothing".
ebgp_requires_policy = true

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

# Owner-only local socket (default mode 0600): clients are authorized as the
# implicit "local-operator" principal — no [security.grpc] block needed.
[global.telemetry.grpc_uds]
path = "/var/lib/rustbgpd/grpc.sock"

# --- RPKI origin validation (your intended production feed) ---

[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"

# --- Import: the exact hygiene you intend to run in production ---

[policy.definitions.reject-rpki-invalid]
[[policy.definitions.reject-rpki-invalid.statements]]
match_rpki_validation = "invalid"
action = "deny"

[policy.definitions.reject-long-prefixes]
default_action = "permit"
[[policy.definitions.reject-long-prefixes.statements]]
prefix = "0.0.0.0/0"
ge = 25
le = 32
action = "deny"
[[policy.definitions.reject-long-prefixes.statements]]
prefix = "::/0"
ge = 49
le = 128
action = "deny"

[policy.definitions.prefer-rpki-valid]
[[policy.definitions.prefer-rpki-valid.statements]]
match_rpki_validation = "valid"
action = "permit"
set_local_pref = 200
[[policy.definitions.prefer-rpki-valid.statements]]
match_rpki_validation = "not_found"
action = "permit"
set_local_pref = 100

# --- Export: deny everything. This is the shadow posture. ---
#
# No statements, default deny: zero UPDATEs leave this daemon toward
# any member. Verify after every config change:
#   rustbgpd --check --strict shadow.toml   # must exit 0
#   rbgp rib sent <member>                  # must be empty
[policy.definitions.shadow-receive-only]
default_action = "deny"

[policy]
import_chain = [
    "reject-rpki-invalid",
    "reject-long-prefixes",
    "prefer-rpki-valid",
]
export_chain = ["shadow-receive-only"]

# --- Volunteer member taps (one block per volunteer) ---

[[neighbors]]
address = "198.51.100.2"
remote_asn = 64501
description = "member-alpha-shadow-tap"
hold_time = 90
families = ["ipv4_unicast", "ipv6_unicast"]
route_server_client = true
role = "route_server"
max_prefixes = 50000

[[neighbors]]
address = "198.51.100.3"
remote_asn = 64502
description = "member-beta-shadow-tap"
hold_time = 90
families = ["ipv4_unicast", "ipv6_unicast"]
route_server_client = true
per_client_best = true
role = "route_server"
max_prefixes = 50000
```

Volunteer taps can also be added and removed at runtime without a
reload (`rbgp neighbor <addr> add ...` — see the
[route-server cookbook](route-server.md)).

### The same posture from arouteserver data

If the incumbent's member filters come from arouteserver, do not
hand-author them for the shadow: render them. The
[IXP filter pipeline](ixp-filter-pipeline.md) is unchanged except for two
small site-local files, which the renderer validates, compiles, attests
in the receipt, and places *before* the generated transparent export on
every member's chain. They are the shadow posture, verified exactly as
shown (both files render against the checked-in M90 site context and the
result passes `rustbgpd --check --strict`):

```rpol
# shadow-receive-only.rpol — the route server sends nothing to anyone.
policy shadow-receive-only {
    term everything { reject }
}
```

```toml
# shadow-hooks.toml — hook it into the global export chain.
[policy]
export_chain = ["shadow-receive-only"]
```

```console
$ arouteserver template-context --output context.yml
$ rs-config-render --context context.yml --out-dir candidate \
    --rtr-cache 127.0.0.1:3323 \
    --extra-rpol shadow-receive-only.rpol --merge-toml shadow-hooks.toml
rendered 7 file(s) + receipt into candidate — gate with `rustbgpd --check --strict candidate/config.toml` before swapping
$ rustbgpd --check --strict candidate/config.toml
config OK: candidate/config.toml
$ grep export_policy_chain candidate/config.toml
export_policy_chain = ["shadow-receive-only", "rs-transparent-export"]
export_policy_chain = ["shadow-receive-only", "rs-transparent-export"]
export_policy_chain = ["shadow-receive-only", "rs-transparent-export"]
```

`render-receipt.json` carries a `site_local` block with the source and
emitted hashes of the overlay and the final per-member chains — archive
it with each dated comparison report, it is the proof that the shadow's
import side was the production filter set and its export side was deny.
Refresh on the incumbent's cadence exactly as the pipeline's cron does;
the renderer refuses the overlay (exit 2, nothing written) if it ever
names an unknown policy, collides with a generated name, or tries a
modification the renderer will not carry (next-hop changes, AS prepends,
community removals, BLACKHOLE-marker synthesis).

The observer exception below, in this mode: the observer must itself be
an arouteserver client (the renderer only hooks known client addresses),
and instead of the global hook you list every *member* in
`shadow-hooks.toml` and leave the observer out —

```toml
# shadow-hooks.toml, observer form: every member gets the deny-all hook;
# the operator-owned observer is the one rendered client without it.
[[neighbors]]
address = "198.51.100.2"
export_policy_chain = ["shadow-receive-only"]

[[neighbors]]
address = "198.51.100.3"
export_policy_chain = ["shadow-receive-only"]
```

— which renders the observer's chain as the bare transparent export and
every member's as `["shadow-receive-only", "rs-transparent-export"]`
(verified on the M90 context; generate the file from `clients.yml`).

### IXP Manager sites: the dry run that is also evidence

An IXP Manager v7.4 site runs the zero-blast-radius shadow hand-written,
as above. Separately, and from day one, run the
[IXP Manager recipe](ixp-manager-route-server.md)'s render step against
your real export — fetch the Foil JSON, `rs-config-render
--input-format ixp-manager-v2 … --check-with rustbgpd` — on the same
cadence as your BIRD route servers regenerate. **Do not activate it.**
What you keep is a standing trail of `render-receipt.json` files
(counts, refusal status, strict-check pass against the exact daemon
version) or of refusals naming a member record the bounded subset
cannot express. Both are pilot findings about *your* data, and the
candidate is byte-for-byte what a later cutover would activate. The
members it describes never see it: the candidate is never published,
no `rustbgpd@<handle>` unit is started, no lock is taken in IXP
Manager.

A second router handle in IXP Manager driven by the lifecycle is a
different thing: a production-posture transparent route server for every
member who peers with it — the migration cookbook's
[shadow trial](route-server-migration.md), not this pilot.

## The standing comparison loop

The pilot's product is a trail of dated comparison artifacts, produced
on a cadence (weekly is a reasonable default, plus after member or
filter changes). Four evidence classes, cheapest first:

**Count views.** Per volunteer member, compare what the shadow retained
against what the incumbent shows for the same session:

```console
$ rbgp rib recv 198.51.100.2          # shadow's received view
$ rbgp rib received 198.51.100.2 --rejected   # what hygiene dropped, with reasons
```

The pair (accepted + rejected-with-reason) must account for everything
the member announced; a count that matches the incumbent's received
count only after adding the rejections is the expected steady state
when the shadow's hygiene is stricter than production.

**The rejection ledger — the second opinion itself.** Retained rejected
routes carry canonical reason tokens (`policy_reject`, `as_path_loop`,
…) and are queryable without knowing prefixes in advance; the
`bgp_rejected_routes_retained{peer}` gauge trends it. In topology B
this runs against the whole exchange feed: every retained rejection is
a route production currently carries that the intended filter set would
not. That list, exported periodically (`--json`), is the pilot's most
directly actionable artifact for the operator. (With arouteserver-rendered
filters the `policy_reject` detail names the generated term —
`rs-hygiene:…` or the member's `client-…` policy — so the ledger reads in
the incumbent's own vocabulary.)

**Per-member spot checks.** For a handful of prefixes per volunteer,
walk the export gate ladder:

```console
$ rbgp rib --prefix 203.0.113.0/24 advertised 198.51.100.3 --explain
```

Every rung above `export_policy` — best-path selection, split horizon,
family negotiation — evaluates for real against the live staging body;
the ladder then stops at the `shadow-receive-only` term, which is the
receive-only posture working as configured. A spot check that stops
anywhere else, or selects a different best path than the incumbent
shows for the same prefix, is a finding.

**The full advertised-view diff.** `rbgp diff advertised`
([`docs/how-to/ribdiff.md`](../how-to/ribdiff.md)) compares the shadow's live
Adj-RIB-Out against a snapshot of the incumbent's — fail-closed,
exit-code gateable. A receive-only shadow has an empty Adj-RIB-Out, so
this needs one deliberate exception: an **observer session** the
operator controls (a collector box, or the incumbent host itself) that
peers as a member of *both* route servers and announces nothing. In the
shadow config, that one neighbor — and only that one — gets the
intended transparent export instead of the deny-all:

```toml
[[neighbors]]
address = "198.51.100.250"
remote_asn = 65510
description = "operator-observer"
route_server_client = true
role = "route_server"
# The one deliberate exception to shadow-receive-only: the observer is
# operator-owned and announces nothing, so this changes what no member sees.
export_policy_chain = ["rs-transparent-export"]
```

(`rs-transparent-export` is the declared permit-all from the
[route-server example](../../examples/route-server/config.toml); add its
definition alongside the others — the shadow config plus this block and
that definition passes `--check --strict` as one file. In the arouteserver
mode use the observer form of `shadow-hooks.toml` above.) The
blast-radius argument is intact: the only session that receives anything
is operator-owned. Then:

1. Snapshot the incumbent's advertised view **toward the observer**
   using whichever producer fits — the `birdc` / `vtysh` / `gobgp`
   adapters, `rbgp diff snapshot from-mrt`, or a BMP capture via
   `rbgp diff snapshot from-bmp` — exactly as documented in the
   [migration cookbook's capture section](route-server-migration.md#capturing-the-incumbents-advertised-view).
2. Compare:

   ```console
   $ rbgp diff advertised --neighbor 198.51.100.250 --against incumbent.ndjson
   $ echo $?   # 0 in sync, 1 divergent (listed), 2 comparison refused
   ```

3. Archive the `--json` report with a date. The report is
   self-describing (normalization, ignored attributes, live-source
   notes), so it stands alone as evidence later.

Expected divergences to pre-explain rather than chase: in topology A,
routes from non-volunteer members appear `incumbent-only` (the shadow
never received them); deliberate hygiene tightenings (e.g. ROV where
production has none) appear `incumbent-only` with the rejection ledger
naming the reason. Anything not explainable from those two lists is a
finding — the project wants it (see data return below).

## Resource envelope

Provision the shadow host like the incumbent's and check the nearest
measured shape. The receipts are dated same-host runs, not universal
claims; each links its full method, configs, and raw artifacts:

- At **700 route-server clients × 400,400 IPv4 routes with live
  churn** (the July 2026 same-host matrix, v0.61.0 exact-tag refresh,
  runs A/B): settled RSS **412 / 410 MiB** after the reload leg, peak
  590 / 577 MiB. In the same runs BIRD 3.3.1 settled at 425 / 417 MiB
  and kept a clear advantage on the flapstorm leg (337 / 292 vs
  rustbgpd's 440 / 502 MiB settled) —
  [receipt, refresh section](../perf/ixp-matrix-2026-07.md#v0610-refresh-2026-07-27)
  and [original memory table](../perf/ixp-matrix-2026-07.md#memory).
- At **200 clients × 115k routes** (same matrix, scale-ladder rung,
  single run): ~432 MB process-tree RSS —
  [receipt](../perf/ixp-matrix-2026-07.md#scale-ladder-context).
- The shipped default allocator is jemalloc; the same receipt documents
  why (a stock-glibc build ratcheted across reload cycles).

Reload, convergence, and propagation behavior at these shapes lives in
the same receipt; the [performance evidence index](../perf/README.md)
states the wins and the losses together. Do not size from any single
headline number — read the receipt for the shape closest to your
member count.

## Monitoring during the pilot

The [route-server cookbook's watch table](route-server.md#watch)
applies unchanged; the Grafana overview dashboard and alert rules are
in [`GRAFANA.md`](../how-to/grafana.md). Pilot-specific notes:

- `bgp_session_state_transitions_total` flat outside member churn is
  the primary health signal — a shadow that flaps its taps is
  disturbing volunteers' routers even while sending no routes.
- `bgp_rejected_routes_retained{peer}` trending is the second-opinion
  signal, not an error: alert on sudden *changes*, not on nonzero.
- In the arouteserver mode, alert on the age of `render-receipt.json`
  and on `bgp_policy_generation_loaded_timestamp_seconds` exactly as the
  pipeline does — a shadow whose filters silently stopped refreshing is
  comparing against stale intent.
- Route pilot alerts to whoever runs the pilot, not the production
  on-call — nothing here can page-worthily affect members.
- Bracket the pilot with support bundles: `rbgp doctor --output ...`
  ([OPERATIONS.md](../reference/operations.md#support-bundles-and-triage-checks-rbgp-doctor))
  at start, on a weekly cadence, and at every incident. The bundle is
  redacted at collection (no raw config file, no secrets; metrics,
  events, and descriptions scrubbed client-side) — review it anyway
  before it leaves your site.

## Teardown

Nothing depends on the shadow, so teardown is unceremonious and total:

1. Produce a final doctor bundle and a final dated diff report — the
   pilot's close-out artifacts. In the render modes, archive the last
   `render-receipt.json` with them.
2. Stop the daemon. No member session moves; no member routing changes.
3. Volunteers delete their shadow-tap session; the incumbent operator
   deletes the feed/observer session. Both are ordinary neighbor
   removals on their side.
4. Delete the shadow's `runtime_state_dir` (journal, event history,
   MRT dumps, crash reports) — and its candidate/receipt directories —
   once the close-out artifacts are archived.
5. Confirm the exchange's state is prior state: incumbent session
   counts and member `PfxRcd` are what they were before step 1 of the
   pilot. Nothing in arouteserver or IXP Manager was changed by the
   pilot (the overlay lives beside `clients.yml`, not in it; the IXP
   Manager dry run never took a lock or published a candidate).

## What a pilot cannot get yet

Stated plainly, each verified at this commit, so the site decides with
the facts rather than discovering them mid-pilot:

- **A receive-only shadow from the IXP Manager path.** Covered above:
  IXP Manager mode refuses the site-local overlays, the activation helper
  publishes only unmodified receipted candidates, and there is no
  receive-only knob in the Foil export. The pilot for an IXP Manager site
  is hand-written (or arouteserver-rendered); the IXP Manager path
  contributes the dry run.
- **A divergence-free looking glass.** The
  [pinned contract](../../tests/compat/ixp-manager-birdseye/contract.json)
  records verified IXP Manager 7.4 Bird's Eye API compatibility with
  documented BIRD-internal divergences (`runtime_compatibility: true`):
  the birdwatcher adapter serves Alice-LG's documented
  [Birdwatcher subset](ixp-filter-pipeline.md#6-looking-glass-alice-lg-via-the-birdwatcher-adapter)
  (status, peers, accepted, filtered, noexport — enough to show
  volunteers their own shadow view) and the Bird's Eye surface IXP Manager
  v7.4.0 consumes, with the divergences documented in the
  [IXP Manager recipe's boundary](ixp-manager-route-server.md#the-boundary).
  Full-table counts, live hold/keepalive countdowns, and any Bird's Eye
  client other than the pinned IXP Manager consumer are outside what is
  proven, and protocol aliases reload only on an operator `SIGHUP` (or a
  sidecar restart for direct aliases) when a member is added. A pilot
  should not promise members a drop-in looking
  glass.
- **Anything beyond the local host from the activation tooling.**
  `rs-config-render activate` and `ixp-manager-lifecycle` act on one
  host: local state directories, a local executable as the activation
  command, one fence per host, no remote activation, no cross-host
  coordination. Two hosts are two independent lifecycles.
- **Automatic housekeeping of activation state.** Every activated
  generation is retained under `<runtime>/activation/generations/` until
  an operator runs the opt-in, dry-run-by-default
  [`rs-config-render prune`](../../tools/rs-config-render/README.md#pruning-retained-generations);
  exit 5 (`ManualRecovery`) leaves a fence that blocks
  every later run until an operator resolves it —
  [Activation manual recovery](activation-manual-recovery.md). Neither
  matters to a shadow that never activates, but both matter to the
  production-shaped cutover the pilot is evidence for.
- **A promise of compatibility beyond the v1 contract**, an SLA, or a
  release cadence — the honest-boundaries list at the end.

## Which evidence exists, and which does not

What stands behind this pilot today:

- **M83** — RFC 7947 route-server profile against BIRD 2 + GoBGP + FRR +
  StayRTR: byte-level transparency on the wire, RFC 9234 OTC, per-member
  views, ROV reject-at-import, both path-hiding mitigations live
  ([route-server recipe](route-server.md)).
- **M90** — the arouteserver differential: one site input drives
  arouteserver/BIRD and `rs-config-render`/rustbgpd, **11/11**
  accept/reject verdicts and explain terms agree, with a rust-only policy
  mutation proving the differential can go red
  ([`INTEROP.md`](../interop.md)). This is the receipt behind "render
  the shadow's filters from your `clients.yml`".
- **M96 / M97** — the IXP Manager render → atomic activation → lifecycle
  stack, against real pinned v7.4 and MD5-authenticated FRR, including
  pre-effect restoration and two handles on one host
  ([`INTEROP.md`](../interop.md#ixp-manager-v74-manual-configuration-oracle)).
  Local gates, not hosted CI.
- **The IXP receipt matrix** and the **24 h route-server flagship soak**
  — the shapes and numbers in the resource envelope above, wins and
  losses together ([matrix](../perf/ixp-matrix-2026-07.md),
  [soak](../soaks/soak-rs-flagship-24h.md)).

What does not exist yet — and a pilot is exactly what would produce it:

- Long-running history for the IXP Manager lifecycle stack: it has days
  of use behind it, not months, and no soak receipt of its own.
- Any published shadow-pilot result from a real exchange. Every
  comparison artifact to date is from the project's own labs and fixtures.
- Production operating history at an IXP, of any length, for the daemon
  as a route server. The incumbents have well over a decade each.

Let the site weigh those two lists; this document's job is to make sure
both are on the table.

## The data-return contract

Stated up front so nobody discovers an expectation mid-pilot.

**The operator keeps everything.** The daemon runs on operator
hardware; the dashboards, metrics, rejection ledgers, render receipts,
and diff reports are the operator's. The comparison tooling (`rbgp diff`,
the snapshot adapters, `rbgp doctor`) is open source and remains useful
after the pilot regardless of its outcome — including for auditing the
incumbent against itself.

**What comes back to the project** — only ever by the operator's own
action, nothing phones home:

- Doctor support bundles attached to bug reports (redaction contract
  above; operator reviews before sending).
- Comparison results in anonymized form: verdicts, divergence classes,
  counts, and reason-token distributions — with peer addresses, member
  ASNs, and descriptions stripped or mapped to opaque labels by the
  operator before sharing. Raw snapshots and member-identifying route
  data stay on site unless the operator decides otherwise.
- Findings: any divergence not explainable by the pre-explained
  classes, any daemon misbehavior, any render refusal that should not
  have been one, any place the tooling refused or confused. Negative
  results are as wanted as positive ones.

**"Publishable feedback" means exactly this:**

- Quote-level approval: nothing an operator said is published, even
  paraphrased, without that operator approving the specific wording.
- No identifiers without written consent: the exchange's name, member
  names/ASNs, host details, and anything that fingerprints them stay
  out of any publication unless consented to in writing.
- Operator pre-review: the operator sees and can veto any publication
  draft that draws on the pilot, before it appears anywhere.
- Declining publication ends nothing: a pilot whose results never
  become public is still a successful pilot.

**Honest boundaries** (the register that governs every claim made
around this pilot, consistent with [`SUPPORT.md`](../../SUPPORT.md)):

- rustbgpd is public alpha. The only narrow compatibility promise is
  the machine-inventoried
  [v1 route-server/route-reflector contract](../reference/v1-stable-contract.md);
  everything else may change between minor releases.
- No SLA: no promised response time, resolution time, maintenance
  window, or release cadence. "Direct support during the pilot" means
  best-effort attention from the maintainer, not a contract.
- Performance receipts establish only their named fixtures, versions,
  and environments. The losses are part of the record: OpenBGPD holds
  a smaller reload stall, and BIRD holds the flapstorm-leg settled
  memory, in the [same matrix](../perf/ixp-matrix-2026-07.md) that
  reports rustbgpd's wins.
- BIRD and OpenBGPD have well over a decade of documented IXP
  production behind them; rustbgpd does not. That gap is the reason
  this pilot is shaped to be zero-risk rather than an argument to
  ignore.
