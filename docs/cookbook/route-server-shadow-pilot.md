# Route-server shadow pilot — a standing non-authoritative deployment

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

## Zero blast radius, precisely

"Non-authoritative" is a config property here, not a promise:

- **No member relies on it.** Every member's production session to the
  incumbent is untouched. The shadow's sessions are additional, on a
  non-production listener (`listen_port = 1179` below), so there is no
  TCP/179 collision with anything.
- **Receive-only from the operator's view.** The export chain is a
  single explicit deny-all policy (`shadow-receive-only` below: no
  statements, `default_action = "deny"`). Zero UPDATE messages leave
  the daemon toward any member — sessions carry OPEN and KEEPALIVE
  only. This is stronger than "members should filter it": there is
  nothing to filter.
- **The failure mode of a misedit is still silence.** With
  `ebgp_requires_policy = true` (RFC 8212,
  [ADR-0112](../adr/0112-rfc-8212-ebgp-requires-policy.md)), deleting
  or misnaming the export chain does not fall back to permit-all — the
  reserved deny is installed and `rustbgpd --check` names the gap.
- **Verified, not asserted.** Every config revision must pass
  `rustbgpd --check --strict <config>` (exit 0 — warnings fail). At
  runtime, `rbgp rib sent <member>` must be empty for every member,
  `rbgp rib --prefix <p> advertised <member> --explain` shows the gate
  ladder stopping with `[STOP] export_policy` at the
  `shadow-receive-only` term, and the member's own session shows zero
  received prefixes.

The worst the shadow can do, by construction: hold a TCP session and
send keepalives. It never originates, propagates, or withdraws a route
anywhere.

## Two tap topologies

### A — member-fed: volunteers peer with the shadow

Volunteer members add a second BGP session to the shadow listener. The
shadow receives their real announcements first-hand and runs the exact
import hygiene the operator intends (or already runs on the incumbent —
IXPs on arouteserver can render the same member filters with
[`rs-config-render`](../../tools/rs-config-render/README.md), see the
[filter-pipeline tutorial](ixp-filter-pipeline.md)).

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
directly actionable artifact for the operator.

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
([`docs/ribdiff.md`](../ribdiff.md)) compares the shadow's live
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
definition alongside the others.) The blast-radius argument is intact:
the only session that receives anything is operator-owned. Then:

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
the same receipt; the README's
[performance section](../../README.md#performance-vs-the-incumbents)
states the wins and the losses together. Do not size from any single
headline number — read the receipt for the shape closest to your
member count.

## Monitoring during the pilot

The [route-server cookbook's watch table](route-server.md#watch)
applies unchanged; the Grafana overview dashboard and alert rules are
in [`GRAFANA.md`](../GRAFANA.md). Pilot-specific notes:

- `bgp_session_state_transitions_total` flat outside member churn is
  the primary health signal — a shadow that flaps its taps is
  disturbing volunteers' routers even while sending no routes.
- `bgp_rejected_routes_retained{peer}` trending is the second-opinion
  signal, not an error: alert on sudden *changes*, not on nonzero.
- Route pilot alerts to whoever runs the pilot, not the production
  on-call — nothing here can page-worthily affect members.
- Bracket the pilot with support bundles: `rbgp doctor --output ...`
  ([OPERATIONS.md](../OPERATIONS.md#support-bundles-and-triage-checks-rbgp-doctor))
  at start, on a weekly cadence, and at every incident. The bundle is
  redacted at collection (no raw config file, no secrets; metrics,
  events, and descriptions scrubbed client-side) — review it anyway
  before it leaves your site.

## Teardown

Nothing depends on the shadow, so teardown is unceremonious and total:

1. Produce a final doctor bundle and a final dated diff report — the
   pilot's close-out artifacts.
2. Stop the daemon. No member session moves; no member routing changes.
3. Volunteers delete their shadow-tap session; the incumbent operator
   deletes the feed/observer session. Both are ordinary neighbor
   removals on their side.
4. Delete the shadow's `runtime_state_dir` (journal, event history,
   MRT dumps, crash reports) once the close-out artifacts are archived.
5. Confirm the exchange's state is prior state: incumbent session
   counts and member `PfxRcd` are what they were before step 1 of the
   pilot.

## The data-return contract

Stated up front so nobody discovers an expectation mid-pilot.

**The operator keeps everything.** The daemon runs on operator
hardware; the dashboards, metrics, rejection ledgers, and diff reports
are the operator's. The comparison tooling (`rbgp diff`, the snapshot
adapters, `rbgp doctor`) is open source and remains useful after the
pilot regardless of its outcome — including for auditing the incumbent
against itself.

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
  classes, any daemon misbehavior, any place the tooling refused or
  confused. Negative results are as wanted as positive ones.

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
  [v1 route-server/route-reflector contract](../v1-stable-contract.md);
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
