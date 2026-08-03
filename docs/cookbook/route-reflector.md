# iBGP route reflector at scale

**When this is you:** you run (or are about to run) an iBGP full mesh
that no longer scales, and you want a dedicated route reflector —
tens to a thousand clients, fast convergence without per-peer tuning,
stale-route protection across client restarts, and per-client optimal
paths if your clients sit in different corners of the IGP. rustbgpd's
RR path needs no fanout configuration: peers whose staged output is
provably identical share one update group automatically.

**Proven by:** [M14](../RECEIPTS.md#interop-labs--pr-gated-interopyml)
(RFC 4456 reflection vs FRR), M76 (RFC 9107 Optimal Route Reflection),
M77 (GR/LLGR stale preservation), and the
[1000-peer scale receipt](../perf/scale-receipt-2026-07.md): 100k
routes to 1,000 real transport sessions converge on the wire in 1.8 s
at 419 MiB RSS, driven by the ADR-0098 update-group fanout (~28×
faster than per-peer staging at 256 uniform clients). Config shape
derived from
[`tests/interop/configs/rustbgpd-m76-orr-rr.toml`](../../tests/interop/configs/rustbgpd-m76-orr-rr.toml)
and [`rustbgpd-m77-gr-rr.toml`](../../tests/interop/configs/rustbgpd-m77-gr-rr.toml).

## Config

```toml
[global]
asn = 65000
router_id = "10.0.0.1"
listen_port = 179
cluster_id = "10.0.0.1"        # RFC 4456 cluster identifier
dynamic_neighbor_limit = 1024  # cap for the auto-accept range below

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

# Owner-only local socket (default mode 0600): clients are authorized as the
# implicit "local-operator" principal — no [security.grpc] block needed.
[global.telemetry.grpc_uds]
path = "/var/lib/rustbgpd/grpc.sock"

# One template for the whole client fleet. Uniform clients group
# automatically (ADR-0098) — there is no update-group knob.
#
# GR/LLGR: the RR is a receiving-speaker helper. On client restart it
# keeps the client's routes for the peer-advertised restart window
# (RFC 4724), then — because llgr_stale_time > 0 — demotes them to
# LLGR_STALE (RFC 9494) instead of purging, up to
# min(local llgr_stale_time, peer's per-family time).
#
# send_hold_time (RFC 9687) is on by default at max(480, 2 × hold_time):
# a client that stops draining its TCP socket is torn down instead of
# silently wedging the shared writer.
[peer_groups.rr-clients]
hold_time = 90
families = ["ipv4_unicast", "ipv6_unicast"]
route_reflector_client = true
graceful_restart = true
gr_stale_routes_time = 120
llgr_stale_time = 300

[[neighbors]]
address = "10.0.0.11"
remote_asn = 65000
description = "client-1"
peer_group = "rr-clients"

[[neighbors]]
address = "10.0.0.12"
remote_asn = 65000
description = "client-2"
peer_group = "rr-clients"

# The rest of the fleet auto-accepts from the loopback range — no
# per-client stanza needed. Dynamic peers inherit rr-clients.
[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "rr-clients"
remote_asn = 65000
description = "rr client fleet"
```

### Optional: per-client optimal paths (ORR, RFC 9107)

If clients in different IGP regions should each get *their* closest
exit (not the RR's), add a BGP-LS topology source and pin clients to
vantages. Per-vantage best paths are computed via SPF over the
BGP-LS-sourced topology ([ADR-0095](../adr/0095-optimal-route-reflection.md))
— a capability no other open-source BGP daemon ships. M76 proves
divergent per-vantage bests and a topology-driven flip against GoBGP.

```toml
# An IGP node exporting the topology over BGP-LS (e.g. a router or a
# controller speaking AFI 16388 / SAFI 71).
[[neighbors]]
address = "10.0.0.250"
remote_asn = 65000
description = "igp-topology-source"
hold_time = 90
route_reflector_client = true
families = ["linkstate"]

# A client whose best paths should be computed from node 10.0.8.1's
# position in the IGP. An unresolved vantage falls back silently to
# the standard best — check `rbgp orr` after enabling.
[[neighbors]]
address = "10.0.0.13"
remote_asn = 65000
description = "client-region-b"
peer_group = "rr-clients"
orr_vantage = "10.0.8.1"
```

## Verify

```console
$ export RUSTBGPD_ADDR=unix:///var/lib/rustbgpd/grpc.sock
$ rbgp neighbor
```

Expect one row per client in `Established`. The per-peer detail view
carries the update-group membership: uniform clients share a
`group:N` id; a peer on the per-peer fallback shows its reason
instead:

```console
$ rbgp neighbor 10.0.0.11
...
Send Hold Time:        480
...
Update Group:          group:0
```

Routes and reflection:

```console
$ rbgp rib                                 # Loc-RIB best routes
$ rbgp rib received 10.0.0.11              # what a client sent us
$ rbgp rib advertised 10.0.0.12            # what we reflect to a client
$ rbgp rib --prefix 203.0.113.0/24 --explain   # why this best won
```

ORR (if configured):

```console
$ rbgp topology nodes        # BGP-LS-sourced graph is populated
$ rbgp orr                   # each vantage: resolved, SPF reach, bound peers
```

An unresolved vantage row means that client is silently getting the
standard best — fix the BGP-LS feed, not the client.

## Watch

Prometheus (`prometheus_addr`, `/metrics`; dashboard import in
[`GRAFANA.md`](../GRAFANA.md) — the churn/distribution row carries the
update-group gauges):

| Metric | Healthy shape |
|--------|---------------|
| `bgp_update_groups` | small and stable (1 for a uniform fleet) |
| `bgp_update_group_members{group}` | ≈ fleet size in one group |
| `bgp_update_group_fallback_peers` | 0 unless you expect fallbacks (table below) |
| `bgp_update_group_regroups_total` | flat outside config/policy changes |
| `bgp_rib_outbound_registered_peers` | = established client count |
| `bgp_session_state_transitions_total` | flat outside maintenance |

## Failure modes

**A client is not grouped (`rbgp neighbor <address>` prints a reason, not
`group:N`).** Grouping is purely an optimization — semantics are
identical on the per-peer path — but at fleet scale you want to know
why. The reasons ([full table](../CONFIGURATION.md#update-groups-automatic)):
`policy_peer_context` (its export chain matches on peer
address/ASN/group), `add_path_send`, `orr_vantage`, `orf_installed`.
The first is the one you can usually fix: rewrite the chain so the
peer-dependent match lives in a per-neighbor chain instead of a shared
one.

**A route isn't reaching a client.** Run the export gate ladder — a
read-only dry run of the same staging body live distribution executes,
update groups included:

```console
$ rbgp rib --prefix 203.0.113.0/24 advertised 10.0.0.12 --explain
```

Each rung reports pass / STOP / n/a in live evaluation order
(`best_route → split_horizon → rr_reflection → family → llgr → orf →
export_policy → adj_rib_out`); a STOP names the gate holding the route
back. `rr_reflection` STOPs are the classic RR misconfigurations:
non-client → non-client reflection, or the client's own cluster id in
CLUSTER_LIST.

**Stale routes after a client restart.** Expected, and bounded: routes
stay for the peer's advertised GR restart time, then carry
`LLGR_STALE` until `llgr_stale_time` expires (during LLGR they are
export-restricted per RFC 9494). If routes vanish immediately instead,
the client didn't advertise GR — check `rbgp neighbor <address>` capability
output. Legacy-family edge cases are documented in
[`KNOWN_ISSUES.md`](../../KNOWN_ISSUES.md).

**A client session drops with a send-hold NOTIFICATION.** The client
stopped reading its socket for `send_hold_time` seconds (RFC 9687) —
that is the protection working; investigate the client. Tune per peer
group if your clients legitimately stall longer.
