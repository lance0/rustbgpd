# Propose a scoped EVPN route-reflector inventory

> **Proposal, not a compatibility contract.** EVPN, including RR-only use, is
> [currently alpha](../reference/v1-stable-contract.md#role-matrix). The
> [stable-surface inventory](../reference/v1-stable-surface.json) and its
> classifications are unchanged. The prepared changes below need evidence,
> review, and explicit approval before they can be applied.

This proposal defines the smallest candidate v1 boundary for **receiving,
reflecting, and querying EVPN Types 1–5** on an iBGP route reflector. It does
not claim local EVPN origination, PE behavior, remote receipt, or Linux
forwarding. Relaying Type 1 and Type 4 routes does not stabilize local Ethernet
segment or multi-homing behavior.

## Candidate boundary

| Surface | Candidate Type 1–5 RR boundary | Current status and exclusions |
|---|---|---|
| Configuration | `l2vpn_evpn` (AFI 25/SAFI 70) in `Neighbor.families` or `PeerGroupConfig.families`; optionally require it through `required_families`. Use the already inventoried common `Global.asn`, `Global.router_id`, `Global.cluster_id`, `Neighbor.remote_asn`, and neighbor/peer-group `route_reflector_client`. Existing common restart keys are neighbor/peer-group `graceful_restart`, `gr_restart_time`, `gr_peer_restart_time_max`, `gr_stale_routes_time`, and `llgr_stale_time`. A client must be iBGP; absent an explicit cluster ID, the router ID supplies it. | The config **keys** are already stable, but the `l2vpn_evpn` **family value is alpha today**. The proposed role would scope that value to Types 1–5 RR operation, including the named restart settings; it would add no EVPN-specific knob. RR-only operation has no local EVI: leave `Config.evpn_instances`, `Config.evpn_ip_vrfs`, Ethernet segments, managed netdevs, and all dataplane configuration alpha. See [family and mode](../reference/configuration.md#address-families) and [RR configuration](../reference/configuration.md#route-reflector-rfc-4456). |
| `RibService.ListReceivedEvpnRoutes` and `ListAdvertisedEvpnRoutes` | Accepted post-policy Adj-RIB-In from a source peer, or committed Adj-RIB-Out for a destination peer. `ListPeerEvpnRoutesRequest`: `neighbor_address=1`, `route_type_filter=2`, `rd_filter=3`, `page_size=4`, `page_token=5`. `ListPeerEvpnRoutesResponse`: `routes=1`, `next_page_token=2`, `total_count=3`, `page_version=4`; `RoutePageVersion.epoch=1`, `generation=2`. Require a type filter in `1..=5`. An advertised row's `peer_address` remains its source peer. | Both methods currently accept `0` and `6` and are outside v1. A committed row proves outbound admission, not remote receipt. Default page size is 100, maximum 1000; continuation is process-local and invalidated by table mutation. |
| Route projection | For Type 1–5 peer-view results, pin `EvpnRouteEntry` fields 1–16: `route_type`, `rd`, `esi`, `ethernet_tag`, `mac`, `ip`, `prefix`, `gateway`, `label`, `label2`, `next_hop`, `peer_address`, `as_path`, `communities`, `extended_communities`, `tunnel_type`. | Field 17 `prefix_sid` is an optional decoded SRv6-related view; field 18 `smet` is Type 6. Neither belongs to this proposal. Labels/VNIs, gateway, and tunnel type are route data for query and reflection, not promises to program them. |
| CLI | Candidate paths are `rbgp evpn received PEER` and `rbgp evpn advertised PEER`, **only with `--route-type TYPE`, where `TYPE` is one of `1`, `2`, `3`, `4`, or `5`**. Peer views accept `--rd`, `--limit` (1–1000), and `--page-token`; `--json` is a page object with `view`, `neighbor`, `routes`, `next_page_token`, `total_count`, and `page_version` (`epoch`, `generation`). | The CLI spells this `evpn`, not `rib evpn`. Base `rbgp evpn`, unfiltered output, Type 6, `evpn explain`, injection/deletion, runtime, instance, ES, and dataplane commands stay alpha. The existing CLI inventory pins command paths only; a JSON type floor would need separate design and tests. |
| CLI route row | JSON row: `route_type`, `route_type_name`, `rd`, `esi`, `ethernet_tag`, `mac`, `ip`, `prefix`, `gateway`, `label`, `label2`, `tunnel_type`, `next_hop`, `peer`, `as_path`, `communities`, `extended_communities`. Human rows show the route-type label, RD and present identity fields, next hop, and source peer; present labels and encapsulation are displayed. | `peer` is the JSON projection of RPC `peer_address`. Conditional JSON `prefix_sid` and `smet` are alpha. No per-route `stale` or `llgr_stale` field exists in the EVPN RPC/CLI today; this proposal does not invent one. |

The RPC names and field numbers above come from the current
[protobuf](../../proto/rustbgpd.proto); the CLI projection comes from the
[EVPN command](../../crates/cli/src/commands/evpn.rs). A type-filtered query is
one route type at a time; callers can query each of Types 1–5. The methods
also serve alpha cases, so merely naming a method does not widen the role.

The selected Loc-RIB view is **deferred**, not part of this initial candidate.
Its existing `RibService.ListEvpnRoutes` takes `ListEvpnRequest` fields
`route_type_filter=1`, `peer_filter=2`, and `rd_filter=3`, and returns
`ListEvpnResponse.routes=1`. Base `rbgp evpn` accepts `--route-type`,
`--neighbor`/`--peer`, and `--rd`; its `--json` output is a bare route-row
array. The method is unpaginated: it scans the EVPN table and clones every
matching row. A Type 1–5 filter does not bound the scan or number of matching
rows returned. Its existing behavior is accepted as alpha; this proposal adds
no latency claim or measurement gate. Including it later needs an explicit
cost/inclusion decision or a bounded replacement. The existing Scoped RR
families' query precedent does not decide that EVPN profile automatically.
No RPC or CLI runtime behavior changes are proposed here.

### Metrics to inventory

| Existing series | Meaning in an RR-only deployment | Scope limit |
|---|---|---|
| `bgp_rib_prefixes{peer,afi_safi="evpn"}` | Retained EVPN Adj-RIB-In paths for a peer. | Counts the EVPN table, including Type 6 if received; it is not a Type 1–5 counter. |
| `bgp_rib_loc_prefixes{afi_safi="evpn"}` | Selected EVPN Loc-RIB entries. | Same table-wide limit. |
| `bgp_rib_adj_out_prefixes{peer,afi_safi="evpn"}` | Committed EVPN Adj-RIB-Out entries. | Same table-wide limit; not remote receipt. |
| `bgp_rr_loop_detected_total{peer}`; `bgp_as_path_loop_detected_total{peer}` | Shared RR and AS-path loop rejection counters. | Neither counter is EVPN-specific. |
| `bgp_evpn_nlri_discarded_total{peer}`; `bgp_evpn_nlri_discarded_by_type_total{peer,route_type}` | Unsupported or unrecognized typed EVPN NLRI discards while the session survives. | Includes types outside 1–5; malformed supported types have separate handling. |
| `bgp_gr_stale_routes{peer}` | Stale routes retained during GR/LLGR, including EVPN. | Aggregates families; no per-route stale query exists. Restart evidence must also use retained identities and wire witnesses. |
| `bgp_route_refresh_stale_entries{peer,afi_safi="l2vpn_evpn"}` | EVPN routes awaiting refresh replacement. | Enhanced Route Refresh state, not a GR stale flag. |

These are existing names and label meanings in the
[metric definitions](../../crates/telemetry/src/metrics.rs). The present
inventory states a general metric compatibility rule but does not enumerate
metric series. A reviewed inventory addition must say whether these names and
labels become an executable floor; writing their names in prose alone would
not create one.

## Prepared patch — not applied

The following is a **review sketch**, not a final approvable inventory diff, a
valid digest update, or a change to the protected files. It identifies the
exact decision points before an executable inventory/classification diff is
prepared. The checker and filtered-call profile still need a design decision;
hashes must be computed only after that design and the final scope are approved.

```diff
# docs/reference/v1-stable-surface.json — NOT APPLIED
 roles += {
   "id": "route-reflector-evpn",
   "classification": "scoped_rr_only",
   "families": ["l2vpn_evpn"],
   "constraints": ["receive-reflect-query", "types-1-through-5-only",
                   "type-filter-1-through-5-required", "no-local-evi-or-dataplane"]
 }
 # Retain a separate alpha EVPN role for Type 6 and PE/dataplane behavior.
 grpc.scoped_rr_only_method_sets += {
   "service": "RibService",
   "methods": ["ListReceivedEvpnRoutes", "ListAdvertisedEvpnRoutes"],
   "excluded_message_fields": ["EvpnRouteEntry.prefix_sid",
                               "EvpnRouteEntry.smet"],
   "signature_sha256": "<compute after approval>",
   "message_graph_sha256": "<compute after checker carve-out>"
 }
 grpc.explicitly_unstable_message_fields += ["EvpnRouteEntry.prefix_sid",
                                               "EvpnRouteEntry.smet"]
 grpc.explicitly_outside_v1 -= ["RibService.ListReceivedEvpnRoutes",
                                "RibService.ListAdvertisedEvpnRoutes"]
 # Keep RibService.ListEvpnRoutes and ExplainEvpnRoute outside v1.
 cli.scoped_rr_only_command_paths += ["evpn received", "evpn advertised"]
 # Add an explicit, type-filtered CLI JSON/human output floor and a checked
 # metric name/type/label floor only if their checker/test representation is
 # designed and reviewed. Do not copy the unicast rbgp-rib/1.1 schema.
```

```text
scripts/check-v1-stable-surface.py — NOT APPLIED
For each new EVPN method-set entry, validate excluded_message_fields as exact
message.field paths. Remove those field declarations from that entry's
normalized protobuf definitions *before* following references and calculating
its message-graph digest. Keep the ordinary full graph for every other method
set. Assert that the exclusions still exist and that no method path is both
inventoried and outside v1. Add a broken-field regression so a change to a
Type 1–5 field fails while a change confined to excluded fields does not.
The checker must also enforce the approved type-filtered call/output profile;
a method name and a hash cannot verify a value restriction by themselves.
```

The current [checker](../../scripts/check-v1-stable-surface.py) hashes the
**whole transitive request/response message graph** for each Scoped RR method
set. Its `explicitly_unstable_message_fields` list checks field existence but
does not remove fields from that graph. Therefore the sketch above does **not**
pass the current checker: without a per-entry carve-out, adding these methods
would hash Type 6 `smet` and optional `prefix_sid`. The other Scoped RR families
currently use one full-graph `RibService` method set; that is no precedent for
a partial EVPN graph. `ExplainEvpnRoute` also references a Type 6 selector and
optional SRv6 Argument companion, so it is deliberately absent here.

Only after the independent real-peer restart evidence, RR soak verdict, RR-path
defect disposition, and a reviewed, exact inventory diff should the
[contract row](../reference/v1-stable-contract.md#role-matrix),
[stability guide](../reference/stability.md), roadmap, and upgrade notes change.
Until then, the current alpha classification remains authoritative.
