# IXP route server

**When this is you:** you run (or are about to run) an Internet-exchange
route server — one BGP speaker that redistributes routes among member
networks so they don't need a full mesh of bilateral sessions. You want
transparent redistribution (the members' own NEXT_HOP and AS_PATH, not
yours), RPKI origin validation and import hygiene at the door, RFC 9234
roles so a member can't leak transit back through the fabric, and a path
that doesn't hide a prefix from a member just because that member's own
policy rejected the single best path.

**Proven by:**
[M83](../RECEIPTS.md#interop-labs--pr-gated-interopyml) (RFC 7947
route-server profile against BIRD 2.0.12 + GoBGP 3.37.0 + FRR 10.3.1 +
StayRTR, [ADR-0101](../adr/0101-route-server-profile.md)): byte-level
transparency on the wire (tshark on the RS↔BIRD link — no route-server
ASN in any AS_PATH segment, NEXT_HOP = originator, MED and communities
verbatim), RFC 9234 OTC toward members, per-member export views, ROV
reject-at-import with `rbgp policy explain`, and the §2.3 path-hiding
contrast live (single-best hides / per-client-best advertises the
runner-up / Add-Path carries both). Also
[M19](../RECEIPTS.md#interop-labs--manual--local-gates) (transparent
route server vs FRR: no ASN prepend, NEXT_HOP preservation). The config
shape is derived from
[`examples/route-server/`](../../examples/route-server/). M83 uses the same
route-server architecture but a pinned, reduced IPv4 lab policy: its
deterministic probes intentionally occupy RFC 6598 Shared Address Space and
TEST-NET-3, so it does not load the public example's dual-stack
special-purpose snapshot.

## Quickstart

Start from the checked-in route-server example:

```bash
cp examples/route-server/config.toml ./rs.toml
cp examples/route-server/hygiene.rpol ./hygiene.rpol
rustbgpd --check --strict rs.toml
rbgp policy check hygiene.rpol
```

Edit `rs.toml` for your ASN, router ID, RTR cache, and member addresses. Then
run the daemon and point the CLI at its UDS:

```bash
rustbgpd rs.toml
export RUSTBGPD_ADDR=unix:///var/lib/rustbgpd/grpc.sock
rbgp health
rbgp summary
```

For a live exchange, run the shadow trial below before carrying production
traffic.

## Config

Two members, dual-stack, RPKI, and a hygiene chain. `member-alpha` can do
Add-Path; `member-beta` can't, so it opts into per-client best-path. Add
more `[[neighbors]]` for additional members, or manage them dynamically
over gRPC as they join and leave the fabric.

```toml
[global]
asn = 65500
router_id = "198.51.100.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

# Owner-only local socket (default mode 0600): clients are authorized as the
# implicit "local-operator" principal — no [security.grpc] block needed.
[global.telemetry.grpc_uds]
path = "/var/lib/rustbgpd/grpc.sock"

# --- RPKI origin validation ---
[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"       # Routinator, rpki-client, StayRTR, etc.

# --- Import hygiene, applied to every member ---
# reject-rpki-invalid, reject-long-prefixes, and prefer-rpki-valid are TOML
# policies. ixp-hygiene plus the dated dual-stack reject-special-purpose
# starter live in hygiene.rpol. rpol and TOML policies share one namespace
# and compose in one chain — see examples/route-server/ for the prefix sets.
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

[policy]
rpol_files = ["hygiene.rpol"]
import_chain = [
    "reject-rpki-invalid",
    "ixp-hygiene",
    "reject-special-purpose",
    "reject-long-prefixes",
    "prefer-rpki-valid",
]

# --- Members ---

# Add-Path-capable member: receives up to the eight best export-permitted
# candidates, subject to configured and negotiated Paths-Limit, and runs
# its own best-path selection (the preferred path-hiding mitigation).
# Like per_client_best, Add-Path send places the member on the per-peer
# distribution path (the add_path_send fallback reason); update-group
# sharing applies to members using neither mitigation.
[[neighbors]]
address = "198.51.100.2"
remote_asn = 64501
description = "member-alpha"
hold_time = 90
families = ["ipv4_unicast"]
route_server_client = true     # transparent: no AS prepend, NEXT_HOP preserved
role = "route_server"          # RFC 9234: attach OTC on egress
# RFC 7948 §4.8 / ADR-0107: reject announcements whose NEXT_HOP is not the
# member's own session address (pre-policy, fail-closed). Leave unset for
# members that legitimately announce another connection's next hop in the
# same AS. Use a separate IPv6 session to apply strict_peer to IPv6 unicast.
next_hop_ownership = "strict_peer"
max_prefixes = 50000

[neighbors.add_path]
send = true
send_max = 8

# Member without Add-Path: per_client_best advertises the best
# export-policy-permitted candidate when the overall best is denied (RFC
# 7947 §2.3.2 per-client best-path, the BIRD-`secondary` equivalent).
# Requires route_server_client; excludes the peer from update-group sharing.
[[neighbors]]
address = "198.51.100.3"
remote_asn = 64502
description = "member-beta"
hold_time = 90
families = ["ipv4_unicast", "ipv6_unicast"]
route_server_client = true
per_client_best = true
role = "route_server"
max_prefixes = 50000
```

## Member-set control communities (RFC 7947 §2.3.2 / RFC 8195)

A member with a selective peering policy steers what the route server
redistributes on its behalf by tagging its announcements with control
communities keyed on the *target* member's ASN — the same convention
the major IXPs document. `RS` below is the route server's ASN, `PEER`
the target member's ASN. The standard (16-bit) forms exist only when
both ASNs fit 16 bits; the large-community forms (RFC 8195) work for
4-byte ASNs. Extended-community control forms are deliberately not
implemented (draft-ietf-grow-ixp-ext-comms).

| Member intent | Standard | Large |
|---|---|---|
| Do not announce to `PEER` | `0:PEER` | `RS:0:PEER` |
| Announce to no one | `0:RS` | `RS:0:0` |
| …except announce to `PEER` | `RS:PEER` | `RS:1:PEER` |
| Prepend my ASN 1× / 2× / 3× toward `PEER` | — | `RS:101:PEER` / `RS:102:PEER` / `RS:103:PEER` |
| Prepend toward every member | — | `RS:101:0` / `RS:102:0` / `RS:103:0` |

Evaluation follows the deny-specific ladder: a target-specific "do not
announce" always suppresses; otherwise "announce to no one" suppresses
unless a target-specific "announce to" overrides it; otherwise the
route is announced. Prepending inserts the *announcing member's* own
leftmost ASN (the RS stays transparent and never inserts its own), and
the largest matching count wins. Acted-on control communities are
scrubbed from the outbound announcement: standard communities
administered by `0` or `RS` (the `0xFFFF____` well-known space is
never touched) and large communities `RS:{0,1,101,102,103}:*`.
Informational large communities under the RS ASN with other function
values pass through.

Enforcement is per-neighbor via `rs_control_communities` — **default
on for `route_server_client` sessions** (the standard IXP posture),
off otherwise, inheritable from a peer group. On sessions explicitly
set off, control communities reach that member verbatim (full
pass-through). Suppression shows up in
`rbgp rib --prefix <prefix> advertised <addr> --explain` as the
`rs_control` gate rung.

Cost note: the filter is route-granular at emit (ADR-0101 Decision 3).
Enabled sessions stay in shared update-groups; a distribution pass
with no control-tagged route — the overwhelming majority — is
byte-identical to the feature being off, sharing staging and encoding
fleet-wide. Only routes actually carrying a control-form community
diverge per target (suppression/prepend/scrub evaluated against each
target's ASN), paying a per-target clone for those routes alone. This
replaced the earlier session-level exclusion, whose per-peer
Adj-RIB-Out + per-peer encode took a 700-client full-table route
server from ~1.3 GiB to over 100 GiB of RSS when enabled fleet-wide.

## Verify

```console
$ rustbgpd --check --strict config.toml # config + rpol validate offline
$ rbgp policy check hygiene.rpol         # rpol in-language tests
$ export RUSTBGPD_ADDR=unix:///var/lib/rustbgpd/grpc.sock
$ rbgp summary                           # both members Established
```

Distribution mode per member — the mitigation each one uses is visible in
the detail view (`single-best` / `add-path` / `per-client-best`):

```console
$ rbgp neighbor 198.51.100.2             # Distribution Mode: add-path
$ rbgp neighbor 198.51.100.3             # Distribution Mode: per-client-best
```

Transparency and per-member views:

<!-- rbgp-cli-conformance -->
```console
$ rbgp rib recv 198.51.100.2             # what a member sent us
$ rbgp rib sent 198.51.100.3             # what that member sees back
$ rbgp rib --prefix 203.0.113.0/24 advertised 198.51.100.3 --explain
```

For a `per-client-best` member the explain output is a ranked candidate
ladder: each denied candidate names the export-policy term that dropped
it, followed by the runner-up actually advertised — instead of the false
"denied" a single-best dry run would report.

Members can be added and removed at runtime:

```console
$ rbgp neighbor 198.51.100.4 add --remote-asn 64503 \
    --route-server-client --per-client-best --role rs \
    --families ipv4_unicast,ipv6_unicast \
    --max-prefixes 50000 --max-prefix-restart-seconds 30
```

## Shadow trial

Use the shadow trial before production cutover. The goal is to prove import
hygiene and per-member export views without carrying member traffic yet.

1. Run rustbgpd beside the incumbent route server with a non-production listener
   or `listen_port = 0`, and peer it to safe member-session copies where
   possible.
2. Keep `route_server_client = true`, `role = "route_server"`, and the same
   import/export chains you intend to use after cutover.
3. Compare the incumbent and rustbgpd views per member:

   ```console
   $ rbgp rib recv 198.51.100.2
   $ rbgp rib sent 198.51.100.3
   $ rbgp rib --prefix 203.0.113.0/24 advertised 198.51.100.3 --explain
   ```

   For the systematic version — every member, every prefix, every
   attribute — export the incumbent's advertised view to an NDJSON
   snapshot and diff it against the live Adj-RIB-Out
   ([`docs/ribdiff.md`](../ribdiff.md) has the snapshot format and
   producer snippets):

   ```console
   $ rbgp diff advertised --against incumbent.ndjson
   $ echo $?   # 0 in sync, 1 divergent, 2 comparison refused
   ```

4. For Add-Path members, verify multiple candidate paths are present. For
   non-Add-Path members, verify `Distribution Mode: per-client-best` and inspect
   the candidate ladder with `--explain`.
5. Keep the session counters flat after convergence:

   ```console
   $ rbgp policy counters
   $ rbgp metrics | grep -E 'bgp_session_state_transitions_total|route_refresh'
   ```

6. Generate a support bundle before and after the trial:

   ```console
   $ rbgp doctor --output ./support-rs-shadow.tar.gz
   ```

Migration mapping for FRR, BIRD, and ARouteServer lives in
[`route-server-migration.md`](route-server-migration.md).

## IRR-driven member filters (arouteserver data)

Per-member IRR prefix/origin filters, PeeringDB max-prefix ceilings,
and the shared hygiene chain do not need hand-authoring: keep your
arouteserver `general.yml`/`clients.yml` and render rustbgpd
configuration from its resolved data model with
[`tools/rs-config-render/`](../../tools/rs-config-render/README.md)
(`arouteserver template-context` → `rs-config-render` →
`rustbgpd --check --strict` → swap → SIGHUP, fail-stale at every step). The
end-to-end walkthrough — including the Alice-LG looking glass — is
[ixp-filter-pipeline.md](ixp-filter-pipeline.md). Design and failure
policy:
[ADR-0110](../adr/0110-irr-peeringdb-filtering-pipeline.md).

## Watch

Prometheus (`prometheus_addr`, `/metrics`; dashboards in
[`GRAFANA.md`](../GRAFANA.md)):

| Metric | Healthy shape |
|--------|---------------|
| `bgp_session_state_transitions_total` | flat outside member churn |
| `sum without (af) (bgp_rpki_vrp_count)` | per-target IPv4 + IPv6 total; non-zero once the RTR cache syncs (`rbgp doctor` warns when configured caches have no visible VRPs) |
| `bgp_update_group_fallback_peers` | ≥ your `per_client_best` + Add-Path send member count (both path-hiding mitigations distribute per-peer) |
| `bgp_rib_outbound_registered_peers` | = established member count |
| `bgp_policy_generation_loaded_timestamp_seconds` | recent — ages past your render/SIGHUP cadence when the filter pipeline is stuck; see "Policy artifact freshness" in [`OPERATIONS.md`](../OPERATIONS.md) for the alert expressions |

Groups of one are the silent degradation shape: distinct per-member
export-chain *content* — most commonly per-member literal chains from
arouteserver-style expansion — puts every member in its own group, at
full per-peer cost, while `bgp_update_group_fallback_peers` stays 0 and
`bgp_update_groups` climbs toward the session count. On a fleet whose
members should share chains, treat `bgp_update_groups` approaching the
session count as a misconfiguration signal. The fix is one shared
export chain plus the member-set control communities above for
per-member steering — they are evaluated at emit time and work inside
a shared group.

## Member support: the filtered-route view

The de-facto IXP member-support flow (what Alice-LG renders from
arouteserver's `reject_reason` tagging on BIRD) is "show the member
their *filtered* routes, tagged with why". rustbgpd retains rejected
inbound routes per member session with a canonical reason token —
`policy_reject`, `otc_route_leak`, `next_hop_ownership`,
`as_path_loop`, `rr_loop`, `treat_as_withdraw` — queryable without
knowing the prefix in advance:

```console
$ rbgp rib received 198.51.100.2 --rejected
Prefix                 PathId   Reason             Detail                       Next Hop           RPKI       AS Path
------------------------------------------------------------------------------------------------------------------------
203.0.113.0/24         0        policy_reject      member-import                198.51.100.2       invalid    64500 64501
```

`--json` emits the same rows for a looking-glass or portal backend
(`PolicyService.ListRejectedRoutes` is the underlying RPC — the
structured reject-reason source an Alice-LG-style adapter needs for its
filtered view). Retention is bounded per member
(`[policy.reject_retention] capacity`, default 1024, LRU on recency),
self-cleans when a rejected identity is later accepted or withdrawn,
and `bgp_rejected_routes_retained{peer}` gauges it for proactive "your
filters are eating this member's routes" alerting. For the
statement-level *why* on a specific prefix, follow up with
`rbgp policy explain`. See the runbook in
[`OPERATIONS.md`](../OPERATIONS.md).

## Failure modes

**A member's routes never appear (`rbgp rib received <addr>` is empty
but the session is Established).** Import hygiene dropped them. List
the retained rejections, then drill into the deciding term:

```console
$ rbgp rib received 198.51.100.2 --rejected
$ rbgp policy explain --neighbor 198.51.100.2 --prefix 203.0.113.0/24
```

The first command works on a stock route server. The second needs
`[policy.explain] enabled = true` — import explain is opt-in and the
route-server starter turns it off explicitly, because the decision cache
is per session and its cost multiplies by member count
([CONFIGURATION.md](../CONFIGURATION.md#import-decision-explain-policyexplain)).
Enable it and reload so future sessions adopt the setting; the target
member must then re-establish before you query the statement-level trace.
The rejected-route view above needs no such switch.

The explain names the deciding term — typically `reject-rpki-invalid`
(fix the member's ROA or your RTR feed) or an `ixp-hygiene` rule
(AS_SET or ASPA-invalid in the announcement).

**A prefix is hidden from one member but present in the Loc-RIB.** That
member's own export policy denies the single best path. In `single-best`
mode this is correct RFC 7947 behavior — the prefix is legitimately
withheld. If the member can't do Add-Path and you want it to see the
next-best permitted candidate instead, set `per_client_best = true` on
it (it drops out of update-group sharing, shown as the `per_client_best`
fallback reason).

**A member's AS or your route-server ASN shows up in an AS_PATH.**
Transparency broke. Confirm `route_server_client = true` on the member —
without it, the route server prepends its own ASN and rewrites NEXT_HOP
like an ordinary eBGP speaker. Some stacks also reject the transparent
first-AS (the neighbor AS isn't first in the path); disable first-AS
enforcement on the *member* side. On FRR this must be **per-neighbor**,
once per route-server neighbor in the member's own config —
`no neighbor 198.51.100.1 enforce-first-as`. The global
`no bgp enforce-first-as` alone is **insufficient** in FRR 10.3.1. BIRD
uses `enforce first as off`.

**A member is Established but receives nothing, and the route server
says it sent the routes.** This is the silent form of the first-AS
rejection above: FRR treats each offending update as withdrawn
(RFC 7606) rather than resetting the session, so the session stays up,
the member's `PfxRcd` stays 0, and neither side logs an error. `rbgp rib
advertised` and the `already_advertised` explain gate report local
send-side state — BGP carries no acceptance signal, so neither can see
the member discarding them. Confirm the per-neighbor
`no neighbor <route-server> enforce-first-as` is present on the member
and re-check its received count.

**A member leaks transit routes back into the fabric.** The RFC 9234
role guards this: with `role = "route_server"` the route server attaches
OTC on egress and a conforming member drops OTC-marked routes it would
otherwise re-advertise. A member that ignores roles still needs its own
outbound filter — roles are defense in depth, not a substitute for it.

**A member's routes vanish after enabling `next_hop_ownership`.** The
strict-peer gate (ADR-0107) rejected them pre-policy: the announced
NEXT_HOP is not that member's session address. Each rejection logs at
`warn` with the peer, prefixes, offending next-hop tuple, and a `reason`
token (`foreign_next_hop`, `unverified_link_local_companion`,
`unscoped_link_local`). If the member legitimately points at another of
its own connections (same AS, different port), unset the knob for that
member — the strict pilot only authorizes the session's own address.
