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
rustbgpd --check rs.toml
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

[global.telemetry.grpc_uds]
path = "/var/lib/rustbgpd/grpc.sock"
principal = "operator"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
operator = "operator"

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

# Add-Path-capable member: receives every candidate path and runs its own
# best-path selection (the preferred path-hiding mitigation). These peers
# stay update-group-shareable.
[[neighbors]]
address = "198.51.100.2"
remote_asn = 64501
description = "member-alpha"
hold_time = 90
families = ["ipv4_unicast", "ipv6_unicast"]
route_server_client = true     # transparent: no AS prepend, NEXT_HOP preserved
role = "route_server"          # RFC 9234: attach OTC on egress
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

## Verify

```console
$ rustbgpd --check config.toml          # config + rpol validate offline
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
    --route-server-client --per-client-best --role rs
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

## Watch

Prometheus (`prometheus_addr`, `/metrics`; dashboards in
[`GRAFANA.md`](../GRAFANA.md)):

| Metric | Healthy shape |
|--------|---------------|
| `bgp_session_state_transitions_total` | flat outside member churn |
| `bgp_rpki_vrp_total` | non-zero once the RTR cache syncs |
| `bgp_update_group_fallback_peers` | ≥ your `per_client_best` member count (they never group) |
| `bgp_rib_outbound_registered_peers` | = established member count |

## Failure modes

**A member's routes never appear (`rbgp rib received <addr>` is empty
but the session is Established).** Import hygiene dropped them. Run the
import decision cache explain:

```console
$ rbgp policy explain --neighbor 198.51.100.2 --prefix 203.0.113.0/24
```

It names the deciding term — typically `reject-rpki-invalid` (fix the
member's ROA or your RTR feed) or an `ixp-hygiene` rule (AS_SET or
ASPA-invalid in the announcement).

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
enforcement on the *member* side (FRR `no enforce-first-as`, BIRD
`enforce first as off`).

**A member leaks transit routes back into the fabric.** The RFC 9234
role guards this: with `role = "route_server"` the route server attaches
OTC on egress and a conforming member drops OTC-marked routes it would
otherwise re-advertise. A member that ignores roles still needs its own
outbound filter — roles are defense in depth, not a substitute for it.
