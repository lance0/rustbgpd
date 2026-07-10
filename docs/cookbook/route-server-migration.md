# Route-server migration notes

This page maps common FRR, BIRD, and ARouteServer route-server concepts to
rustbgpd's config and verification surfaces. It is not a mechanical converter;
use it to build a side-by-side candidate, then run the shadow trial from the
route-server cookbook before carrying production traffic.

## Baseline rustbgpd shape

Start from:

- [`examples/route-server/config.toml`](../../examples/route-server/config.toml)
- [`examples/route-server/hygiene.rpol`](../../examples/route-server/hygiene.rpol)
- [`docs/cookbook/route-server.md`](route-server.md)

Core member shape:

```toml
[[neighbors]]
address = "198.51.100.2"
remote_asn = 64501
description = "member-alpha"
families = ["ipv4_unicast", "ipv6_unicast"]
route_server_client = true
role = "route_server"
max_prefixes = 50000
import_policy_chain = ["reject-rpki-invalid", "ixp-hygiene", "prefer-rpki-valid"]
```

For path hiding, prefer Add-Path receive on the member:

```toml
[neighbors.add_path]
send = true
send_max = 8
```

For members that cannot receive Add-Path, use the RFC 7947 §2.3 per-client-best
fallback:

```toml
per_client_best = true
```

## FRR

Common FRR route-server member shape:

```frr
router bgp 65500
 neighbor 198.51.100.2 remote-as 64501
 neighbor 198.51.100.2 route-server-client
 neighbor 198.51.100.2 local-role rs
 neighbor 198.51.100.2 strict-role
 neighbor 198.51.100.2 maximum-prefix 50000
 no bgp ebgp-requires-policy
```

rustbgpd equivalent:

```toml
[[neighbors]]
address = "198.51.100.2"
remote_asn = 64501
route_server_client = true
role = "route_server"
strict_role = true
max_prefixes = 50000
```

Notes:

- FRR peers receiving transparent route-server paths usually need
  `no enforce-first-as` on the member side because the member AS is not first in
  reflected AS_PATHs.
- FRR route-maps map naturally to TOML policy definitions for simple match/set
  chains, or to `.rpol` for reusable hygiene logic. The M80 receipt proves
  route-for-route parity between `.rpol` and FRR route-maps for the core
  import/export pattern.
- `neighbor ... addpath-tx-all-paths` maps to `[neighbors.add_path] send = true`
  with an explicit `send_max`.

## BIRD

Common BIRD route-server ideas:

```bird
protocol bgp member_alpha {
  local as 65500;
  neighbor 198.51.100.2 as 64501;
  rs client;
  enforce first as off;
  ipv4 {
    import filter ixp_import;
    export filter ixp_export;
    add paths tx;
  };
}
```

rustbgpd equivalent:

```toml
[[neighbors]]
address = "198.51.100.2"
remote_asn = 64501
route_server_client = true
role = "route_server"
families = ["ipv4_unicast", "ipv6_unicast"]
import_policy_chain = ["ixp-hygiene"]

[neighbors.add_path]
send = true
send_max = 8
```

Notes:

- BIRD's `rs client` maps to `route_server_client = true`.
- BIRD's `secondary` path-hiding mitigation maps to `per_client_best = true`
  for non-Add-Path members.
- BIRD filter functions map best to `.rpol` named policies and parameterized
  policies. Keep prefix/community data in named sets so `rbgp policy check` and
  `rbgp policy test` can validate changes before reload.

## ARouteServer

ARouteServer-generated configs usually encode member inventory, max-prefix
limits, bogon / hygiene / RPKI policy, route-server transparency, and
path-hiding settings. There is no direct ARouteServer target in-tree yet.

Practical migration path:

1. Export member inventory to `[[neighbors]]` rows.
2. Convert shared prefix/community lists to `.rpol` `prefix-set` /
   `community-set` declarations.
3. Convert import hygiene to a named `.rpol` policy and keep per-member
   exceptions as parameters or per-neighbor chain overrides.
4. Choose one path-hiding mode per member:
   - Add-Path-capable members: `[neighbors.add_path] send = true`
   - legacy members: `per_client_best = true`
5. Run a shadow trial and compare `rbgp rib advertised` output against the
   incumbent route server's BMP/MRT/looking-glass view.

Minimal generated-neighbor target shape:

```toml
[[neighbors]]
address = "198.51.100.2"
remote_asn = 64501
description = "member-alpha"
route_server_client = true
role = "route_server"
max_prefixes = 50000
import_policy_chain = ["ixp-hygiene", "member-alpha-in"]
export_policy_chain = ["member-alpha-out"]
per_client_best = true
```

## Capturing the incumbent's advertised view

One snapshot per member, produced on (or from) the incumbent route
server with the bundled adapters (`scripts/ribsnap/`, stdlib-only
Python 3; adapter contract in [`docs/ribdiff.md`](../ribdiff.md)). All
converters exit 0 with the snapshot on stdout, or 2 (nothing emitted)
when the input is malformed or not the expected form — a truncated or
wrong-form capture can never read as "in sync".

### BIRD 2 (verified: 2.0.12)

```bash
birdc show route export <member-protocol> all > bird-<member>.txt
scripts/ribsnap/bird2-export-to-ribsnap.py \
    --peer <member-ip> --peer-asn <member-asn> bird-<member>.txt \
    > bird-<member>.ndjson
```

Prerequisites and limitations:

- `show route export P` computes P's export filters on the fly — no
  config change needed, but it reflects the table *now*, not what was
  actually sent. If the incumbent has `export table on` (an Adj-RIB-Out
  kept per protocol, at ~one table's memory cost per member), capture
  that instead (`show route export table <member-protocol> all`) for a
  true sent-view; the converter accepts both (same text format).
- The view is pre-encoding: locally-originated routes carry no
  `BGP.as_path` / `BGP.next_hop` / `BGP.origin` — those fields are
  omitted, never fabricated. A transparent route server neither prepends
  nor rewrites toward `rs client` members, so member-learned routes
  compare fully; if your capture includes RS-originated routes, add
  `--ignore-attribute` for the missing fields.
- `BGP.ext_community` is printed symbolically and is skipped (stderr
  note); compare with `--ignore-attribute extended_communities`.

### FRR (verified: 10.3.1)

```bash
vtysh -c "show ip bgp neighbor <member-ip> advertised-routes detail json" \
    > frr-<member>.json
scripts/ribsnap/frr-advertised-to-ribsnap.py \
    --peer <member-ip> --peer-asn <member-asn> frr-<member>.json \
    > frr-<member>.ndjson
```

Prerequisites and limitations:

- The `detail` form is required — the summary form
  (`advertised-routes json`) has no community information at all, and
  the converter refuses it (exit 2) rather than emit a snapshot that can
  never show a communities difference. Both forms are post-policy
  (outbound route-map rewrites are reflected; verified on 10.3.1).
- The detail form lists every RIB path per advertised prefix, including
  paths not advertised to this member; only the
  `bestpath.overall == true` path is converted. Members with
  `addpath-tx-all-paths` are not supported by this converter.
- The view is pre-prepend / pre-nexthop-rewrite: `aspath` excludes FRR's
  own ASN and self-originated routes show next hop `0.0.0.0` (omitted,
  never fabricated). Toward `route-server-client` members there is no
  prepend or rewrite, so member-learned routes compare fully.
- FRR emits `metric: 0` whether MED was absent or zero; both convert to
  an omitted `med` (matching the diff's documented MED conflation).
- `extendedCommunity` is rendered symbolically and skipped (stderr
  note).

### GoBGP (verified: 3.37.0)

```bash
gobgp neighbor <member-ip> adj-out -j > gobgp-<member>.json
scripts/ribsnap/gobgp-adjout-to-ribsnap.py \
    --peer <member-ip> --peer-asn <member-asn> gobgp-<member>.json \
    > gobgp-<member>.ndjson
```

Prerequisites and limitations:

- `adj-out` is a true post-policy Adj-RIB-Out (own-ASN prepend and
  next-hop rewrite included), so no attribute needs to be ignored.
- With Add-Path send negotiated, `adj-out -j` emits one entry per path
  but no path identifier (verified on 3.37.0): duplicates become
  repeated route records. The diff compares multiplicity and never
  compares path IDs, so this is lossless for the verdict.
- Extended communities are rendered structurally and skipped (stderr
  note).

### MRT dumps

If the incumbent's advertised view exists as an MRT `TABLE_DUMP_V2`
file, convert it in-binary:

```bash
rbgp diff snapshot from-mrt capture.mrt --view adj-rib-out-capture \
    --peer <member-ip> --peer-asn <member-asn> > mrt-<member>.ndjson
```

`--view` is the honesty gate: `TABLE_DUMP_V2` is by default a collector
RIB view, and only a dump you can attest is a per-client post-policy
capture (`adj-rib-out-capture`) is comparable. `--view loc-rib` and
`--view adj-rib-in` are refused with exit 2 — a Loc-RIB compared against
an Adj-RIB-Out reports every export-policy effect as divergence.

### BMP (RFC 8671 post-policy Adj-RIB-Out)

If the incumbent supports BMP with the RFC 8671 post-policy Adj-RIB-Out
view, its BMP feed is a wire-true multi-member capture — no per-member
CLI exports, and it carries attributes no CLI view renders (preserved
as `unknown_attrs`). Point the incumbent's BMP export at a listener,
capture the raw bytes from the **start** of the BMP session, and stop
only after every member's initial dump has completed:

```bash
nc -l 11019 > incumbent.bmp
rbgp diff snapshot from-bmp incumbent.bmp > incumbent.ndjson
```

Prerequisites and limitations:

- The incumbent must be configured to export the **post-policy
  Adj-RIB-Out** monitoring view (O=1/L=1). The default Adj-RIB-In feed
  is skipped with a note; a pre-policy Adj-RIB-Out feed (L=0) is
  refused as non-comparable.
- The capture must include the session start (Initiation and Peer Ups
  carry the negotiated OPENs that drive Add-Path decoding) and each
  member's End-of-RIB. **A peer/family without End-of-RIB is an
  incomplete dump and the conversion is refused (exit 2)** — a
  truncated capture must never read as "in sync". Exclude peers you
  don't care about with `--peer` if they never completed.
- Live churn during the capture is fine: updates that interleave with
  the initial dump supersede it, and post-End-of-RIB stats (RFC 8671
  types 15/17) are cross-checked against the folded state.
- Offline only: capture to a file first; the adapter does not read from
  a socket. Full contract in [`docs/ribdiff.md`](../ribdiff.md).

### Example reports

From the M83 multi-stack lab (FRR member AS 65003 advertising three
prefixes with MED 55 and community 65003:99 toward the route server at
10.83.3.1). The equal outcome, exit 0:

```text
diff advertised: incumbent "frr-advertised/1 view=adj-rib-out-capture m83-frr-member" (generation 7) vs rustbgpd-grpc (adj-rib-out, advertised)
schema rbgp-ribdiff/1; normalization v1; ignored attributes: as_path, next_hop
live-source notes:
  - med: the daemon proto carries MED as a bare integer, so MED-absent and MED 0 are indistinguishable over gRPC; live med=0 is compared as absent (snapshot producers should omit `med` when it is zero or absent)
  - as_path: the daemon proto exposes a flattened ASN list, so AS_PATH is compared as a single AS_SEQUENCE on both sides; AS_SET structure is not compared
  - unknown attributes: path attributes outside the typed set (origin, as_path, next_hop, med, local_pref, communities, extended/large communities) are not visible over gRPC and are not compared
  - generation: the route-listing API exposes no RIB generation token; mid-walk listing drift is detected via per-page total_count instead, and the snapshot header's generation is adopted for the live side
verdict: in_sync
per-peer summary:
  10.83.3.1 AS65500 ipv4_unicast: matched 3, incumbent-only 0, rustbgpd-only 0, attribute-changed 0, multiplicity-changed 0
```

The explained-difference outcome, exit 1: rustbgpd rejected
100.68.0.0/24 at import (RPKI-invalid under the lab's VRP set), so the
incumbent advertises one route the shadow does not — an expected,
explainable divergence during a migration that tightens ROV:

```text
verdict: divergent
per-peer summary:
  10.83.3.1 AS65500 ipv4_unicast: matched 2, incumbent-only 1, rustbgpd-only 0, attribute-changed 0, multiplicity-changed 0
differences (1 total, showing 1):
  - 10.83.3.1 ipv4_unicast 100.68.0.0/24 [incumbent-only]
```

(Header and live-source notes identical to the equal report and elided
here.) Divergences you cannot explain from a deliberate policy delta are
cutover blockers.

## Cutover checklist

1. Build the candidate config and run `rustbgpd --check`.
2. Run `rbgp policy check` for every `.rpol` file.
3. Shadow-peer the same members with a non-production listener so no accidental
   TCP/179 collision occurs.
4. Compare received and advertised views:

   ```bash
   rbgp rib recv <member>
   rbgp rib sent <member>
   rbgp rib --prefix <prefix> advertised <member> --explain
   ```

   Then run the systematic per-member advertised-view diff: export the
   incumbent's advertised routes to an `rbgp-ribsnap/1` NDJSON snapshot
   with the bundled adapters (below; format details in
   [`docs/ribdiff.md`](../ribdiff.md)) and compare it against the live
   Adj-RIB-Out:

   ```bash
   rbgp diff advertised --against incumbent.ndjson          # all snapshot members
   rbgp diff advertised --neighbor <member> --against incumbent.ndjson
   ```

   Exit code 0 means complete inputs with no semantic differences, 1
   means differences (listed in the report), and 2 means the comparison
   was refused (incomplete, stale, or over-limit input is never treated
   as equal). Gate each cutover batch on exit code 0 for its members.

5. Confirm counters stay quiet after convergence:

   ```bash
   rbgp metrics | grep -E 'route_refresh|session_state|update_group'
   ```

6. Cut member sessions in small batches. Keep the incumbent read-only during the
   first batch so advertised-view diffs remain available.
