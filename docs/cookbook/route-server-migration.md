# Route-server migration notes

This page maps common FRR, BIRD, OpenBGPD, and ARouteServer route-server
concepts to rustbgpd's config and verification surfaces. Structure is
mechanical for BIRD 2/3, FRR, and GoBGP: `rbgp config import` translates their
supported structural subset and refuses to guess at anything else. There is
**no OpenBGPD importer**; use the manual mapping below. In every case, hand-map
untranslated policy and run the shadow trial before carrying production
traffic.

## The mechanical first step (BIRD, FRR, and GoBGP)

```bash
# 1. Translate the structure; the report lists every warning and stanza that
#    needs review, with source line numbers where available (exit 0 only
#    when neither exists; 2 = translated but needs review; 3 = nothing).
rbgp config import bird.conf --out config.toml

# 2. Hand-translate the reported policy stanzas to .rpol
#    (docs/rpol-language.md), wire them into import/export chains, then
#    validate — --check also compiles every referenced .rpol file, and
#    warns (exit stays 0) for every eBGP neighbor still resolving no
#    explicit policy, by name and direction.
rustbgpd --check config.toml

# 3. Shadow trial (docs/cookbook/route-server.md), then compare the
#    advertised view against the incumbent per member:
rbgp diff advertised --neighbor 198.51.100.2 --against bird-member.ndjson
```

The importer covers local AS, router-id, neighbors (address, remote AS,
description), peer groups, address families, hold timers, and max-prefix
limits. MD5/auth presence is flagged but secrets are never imported. BIRD
filters, FRR route-maps/prefix-lists, and GoBGP policy-definitions are
deliberately not translated — a wrong mechanical policy translation would
be worse than the honest list; the sections below are the hand-translation
map for exactly those stanzas.

Because no policy is translated, the emitted `[global]` sets
`ebgp_requires_policy = true` (ADR-0112) — a knob the source config did not
ask for, so the import report says so and why. Every eBGP direction that
resolves no explicit policy runs the RFC 8212 reserved deny until you
configure one: the session establishes and carries nothing in that direction,
rather than silently passing everything. Each direction starts carrying
traffic as its chain lands. Delete the line from the emitted config to run
permit-all instead; it is startup-only, so changing it later needs a restart
rather than a reload.

Either way, `rustbgpd --check` names every eBGP neighbor that still resolves
no explicit policy and the directions it is missing, and summarizes as
`config VALID, <n> WARNINGS — NOT a clean check` rather than `config OK`. It
does not fail: a permit-all route server is a legitimate configuration, and
so is a deliberately empty one mid-migration.

The importer deliberately reads one BIRD source file and does not resolve files
named by standalone `include` statements. Flatten every referenced file into
one source before importing. Standalone `include` statements that remain are
reported with their source line and make the translated skeleton exit 2 for
operator review.

Do not pass an OpenBGPD `bgpd.conf` under another `--format`: its grammar and
semantics are not supported. Start with the baseline below and migrate each
peer and policy explicitly.

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

- FRR peers receiving transparent route-server paths need first-AS
  enforcement relaxed on the member side, because the route server's AS is not
  first in the AS_PATHs it forwards. The working form is **per-neighbor**:

  ```frr
  ! in the member's own FRR config, once per route-server neighbor
  no neighbor 198.51.100.1 enforce-first-as
  ```

  The global `no bgp enforce-first-as` alone is **insufficient** in FRR 10.3.1.
  Getting this wrong fails silently: FRR treats the offending updates as
  withdrawn (RFC 7606) instead of resetting, so the session stays Established,
  the member holds zero routes, and neither side logs an error. `rbgp rib
  advertised` on the route server still shows the routes sent — it reports
  local send-side state, not what the member accepted. Check `PfxRcd` on the
  member.
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

## OpenBGPD

OpenBGPD route-server deployments commonly combine global
[`transparent-as yes`][openbgpd-transparent-as] with per-neighbor policy and,
where path hiding must be mitigated,
[`rde evaluate all`][openbgpd-rde-evaluate]. Map those concepts as follows:

- The closest mapping for transparent route-server export is
  `route_server_client = true` on each member; also set
  `role = "route_server"` so RFC 9234 role negotiation is explicit.
  The flags are not a complete policy conversion. One important
  non-equivalence is `NO_ADVERTISE`: OpenBGPD's `transparent-as` disables its
  automatic well-known-community filtering, while rustbgpd always enforces
  RFC 1997 `NO_ADVERTISE`. Audit any site policy that expected that community
  to pass through the incumbent.
- Map inbound and outbound rules to `import_policy_chain` and
  `export_policy_chain`; translate the policy itself by hand to `.rpol`.
- `rde evaluate all` maps to `per_client_best = true` for a member that cannot
  receive Add-Path. Prefer negotiated Add-Path where the member supports it.
- Translate authentication, timers, max-prefix limits, and address-family
  enablement peer by peer. The importer cannot inventory or warn about omitted
  OpenBGPD-only settings for you.

Validate the completed config with `rustbgpd --check --strict`, then compare
each member's post-filter view manually as described below.

## ARouteServer

ARouteServer-generated configs usually encode member inventory, max-prefix
limits, bogon / hygiene / RPKI policy, route-server transparency, and
path-hiding settings. Most of this does not need hand-migration:
[`tools/rs-config-render/`](../../tools/rs-config-render/README.md) renders
rustbgpd config and `.rpol` filters directly from `arouteserver
template-context` output, keeping the existing `general.yml`/`clients.yml`
workflow — the end-to-end walkthrough is
[ixp-filter-pipeline.md](ixp-filter-pipeline.md). The renderer refuses knobs
it cannot map faithfully (see its README); a site relying on those, or
hand-tuned ARouteServer output, follows the manual path:

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

### BIRD 2/3 (verified: 2.0.12 and 3.3.1)

```bash
birdc show route export <member-protocol> all > bird-<member>.txt
scripts/ribsnap/bird2-export-to-ribsnap.py \
    --peer <member-ip> --peer-asn <member-asn> bird-<member>.txt \
    > bird-<member>.ndjson
```

On BIRD 3, enable `export table on` on the member channel and capture the
retained post-policy view with `birdc show route export table
<member-channel> all`. The adapter accepts BIRD 3's lowercase `bgp_*`
attributes while retaining the historical `bird2-export/1` source ID.
Preconfigure the option before shadowing or use a maintenance window: changing
it restarts the channel. If a restart is unacceptable, use the on-the-fly
`show route export <member-protocol> all` view instead; it is less exact.

Prerequisites and limitations:

- `show route export P` computes P's export filters on the fly — no
  config change needed, but it reflects the table *now*, not what was
  actually sent. If the incumbent has `export table on` (an Adj-RIB-Out
  kept per protocol, at ~one table's memory cost per member), capture
  that instead (`show route export table <member-channel> all`) for a
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

### OpenBGPD (manual post-filter view)

OpenBGPD's documented [`show rib out`][openbgpd-bgpctl-out] view of the
filtered routes sent to one neighbor is:

```sh
bgpctl show rib out neighbor <member-ip> detail
```

Inspect this per member during the shadow trial. rustbgpd does not ship a
`bgpctl` output adapter, so this text cannot be passed directly to `rbgp diff
advertised` and must not be relabeled as an `rbgp-ribsnap/1` snapshot.

OpenBGPD's generic [`dump table-v2`][openbgpd-dump] is a dump of a named RIB,
not proof of a per-member post-policy Adj-RIB-Out. Likewise, neighbor-scoped
[`dump updates out`][openbgpd-neighbor-dump] records ongoing BGP activity after
capture starts; it is not a complete point-in-time advertised snapshot.
Neither source satisfies
`--view adj-rib-out-capture` on its own. Use the manual `bgpctl` view, or an
independently captured source that can genuinely attest to the MRT/BMP
post-policy boundaries below.

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
  - generation: route-page tokens are process-local, bound to the exact RPC scope and canonical filters, and fenced by a conservative Received/Best/Advertised scope-class generation; the adapter keeps scope and filters stable, while any same-class mid-walk mutation (including an unrelated peer) aborts the listing and requires a restart; the API still exposes no numeric RIB generation, so the snapshot header's generation is adopted for the live side
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

1. Build the candidate config and run `rustbgpd --check --strict`.
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
   with a bundled BIRD/FRR/GoBGP adapter (below; OpenBGPD is manual unless an
   independently captured MRT/BMP source satisfies the stated boundary;
   format details in
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

[openbgpd-bgpctl-out]: https://man.openbsd.org/OpenBSD-7.7/bgpctl.8#out
[openbgpd-dump]: https://man.openbsd.org/OpenBSD-7.7/bgpd.conf.5#dump
[openbgpd-neighbor-dump]: https://man.openbsd.org/OpenBSD-7.7/bgpd.conf.5#dump~3
[openbgpd-rde-evaluate]: https://man.openbsd.org/OpenBSD-7.7/bgpd.conf.5#rde
[openbgpd-transparent-as]: https://man.openbsd.org/OpenBSD-7.7/bgpd.conf.5#transparent-as
