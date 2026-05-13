# EVPN VTEP alpha-soak checklist

Post-merge confidence list for the bidirectional EVPN VTEP loop
(Gates 7a + 7b + 7b+1 in v0.15.0; Gates 7b+2 / 7c / 8 / 8b prep /
8b enforcement intent + kernel primitive layered in across v0.16.0
and v0.17.0; Gate 9 symmetric Interface-less IRB end-to-end in
v0.18.0 — PRs #77 / #78 / #79; ADR-0059 aliasing dataplane ECMP
via FDB nexthop groups fully landed in v0.19.0 — PRs
#84 / #86 / #87 / #88 / #89). The branch landed the control-plane,
kernel, L3, and aliasing-ECMP paths; this file tracks what we
still need to retire residual alpha-VTEP risk before claiming
v1.0-grade production readiness.

Items are checkboxed so individual slices can move independently;
none of them block v0.18.0 release on their own.

## CI / observability

- [ ] **M37 on a privileged CI runner.** Today M37 is local-only
  (`docker build` + `containerlab deploy` + the driver script). The
  M36 row is in the same boat. Wire a privileged-runner job —
  ideally the same one that hosts `EVPN_LINUX_NETNS=1` for the
  in-tree netns test — so a regression in `notify::classify_neigh`,
  `LinkCache::bridge_port_to_vni`, or the originator's path-
  attribute construction surfaces on PR-CI rather than in the field.
  Tracked in `docs/INTEROP.md` "Not in CI" footnote on the M37 row.
- [x] **EVPN local-origination Prometheus counters.** The originator
  now records successful RIB-accepted Type 2 actions in
  `evpn_local_originations_total{action="inject"}` and
  `evpn_local_originations_total{action="withdraw"}`, and failed RIB
  handoff / rejection / reply-drop paths in
  `evpn_local_origination_errors_total{action="inject"}` and
  `evpn_local_origination_errors_total{action="withdraw"}`. During
  M37 or churn soak, inject and withdraw should track the synthetic
  `bridge fdb add` / `bridge fdb del` cadence, while the error
  counter should stay flat.
- [x] **`evpn_local_observations_dropped_total` Prometheus counter.**
  The `RTNLGRP_NEIGH` notify loop now records
  `evpn_local_observations_dropped_total{reason="channel_full"}` and
  `evpn_local_observations_dropped_total{reason="channel_closed"}`
  when a classified kernel local-MAC observation cannot be forwarded
  to the originator. This distinguishes kernel-event loss before the
  originator sees an observation from RIB-side origination failures.
- [x] **`ListEvpnInstances` exposes `originated_local_macs_count`
  per instance.** Gives operators a fast "is the loop alive?" view
  via `rustbgpctl evpn instances` without scraping logs. Human output
  renders `originated-local-macs=N`; JSON and gRPC expose
  `originated_local_macs_count`.
- [ ] **24 h MAC-churn soak** of M37 with a synthetic MAC churn
  driver (`bridge fdb add` + `bridge fdb del` at ~10 Hz on a few
  thousand MACs). The local-only driver now lives at
  `tests/interop/scripts/test-m37-evpn-local-origination-churn.sh`.
  Use `--smoke` for a one-round, five-MAC pre-release check; the
  remaining work is to run the full driver long enough to confirm RSS
  slope stays flat under the originator's
  `BTreeMap<MacAddress, LocalMacOriginationState>` retention model
  (entries are kept after Aged so the seq ratchet survives — we want
  to verify that doesn't compound badly under heavy churn). Separate
  from the Gate 8b BUM-state 24 h soak under "remaining multi-homing
  enforcement work" below, which exercises DF flips rather than
  origination churn.

## Convergence + correctness slices

- [x] **5 s RIB-poll floor for remote-best-path mobility.** Closed
  by Gate 7c — `crates/rib/src/event.rs` exposes an
  EVPN-keyed `EvpnRouteEvent` broadcast and the originator
  consumes it synchronously. The 5 s `QueryEvpnRoutes` poll stays
  as a backstop for `Lagged` subscribers and cold-start cache
  population.
- [x] **MAC-with-IP (Type 2 with host IP) origination.** Closed by
  Gate 7b+2 — three slices on top of v0.16.0. Slice 1 extended the
  existing `RTNLGRP_NEIGH` classifier to recognize `AF_INET` /
  `AF_INET6` neighbours on bridge ifindexes. Slice 2 added
  `LocalMacIpOriginator`, a parallel state machine to
  `LocalMacOriginator` keyed on `(MAC, IP)` with independent
  RFC 7432 §15.1 mobility sequencing. Slice 3 wired the daemon
  correlation under the FRR-style **replace model**: at any time
  at most one of `{MAC-only, MAC+IP}` is advertising for a given
  MAC. Operator prerequisite: the bridge must have
  `neigh_suppress on` per-VXLAN-port so the kernel routes ARP/ND
  bindings into the bridge's neighbour table. M37+IP
  containerlab smoke (operator-run, privileged) covers the
  end-to-end FRR replace flow.
- [x] **`advertise_svi_mac` consumption.** Closed — the Linux
  dataplane captures the bridge link-layer address during link
  inventory, surfaces it on `InstanceDataplaneStatus.bridge_mac`,
  and the daemon's `src/evpn_svi.rs` task subscribes to the
  `DataplaneReport` broadcast to originate / withdraw the Type 2
  on `Ready` ↔ `NotReady` transitions and bridge MAC drift. Pairs
  with `sticky_macs` (ADR-0056) — listing the bridge MAC there
  marks the originated SVI Type 2 sticky.
- [ ] **RFC 7432 §15.1 duplicate-MAC quarantine** (M=180 s, N=5
  moves). ADR-0055 §9 defers the action; the detection-only
  `evpn_duplicate_mac_moves_total{vni,mac}` counter and
  `evpn_duplicate_mac_first_move_timestamp_seconds{vni,mac}` gauge
  have landed so operators can see repeated contention for a key and
  when its current observation window began. Still ahead: quarantine
  action and the operator-facing escalation channel.
- [x] **Sticky MAC anti-spoof config schema.** Closed by ADR-0056
  — `[[evpn_instances]].sticky_macs` lists MACs to mark with the
  RFC 7432 §15.4 sticky bit on origination. **Not** a static FDB:
  the daemon does not synthesize routes for these MACs, only marks
  Type 2s emitted as a result of normal kernel learning (or
  SVI-MAC origination when `advertise_svi_mac = true`). Quarantine
  action remains deferred — sticky-bit origination ships without
  any automatic detect-and-defend behavior on top of it.

## Larger follow-on gates (beyond the v0.15.0 bidirectional-loop
landing, tracked here for visibility)

- [x] **Gate 8 — multi-homing foundation + observable DF election.**
  Type 4 ES + Type 1 EAD-per-ES + Type 1 EAD-per-EVI origination,
  RFC 7432 §8.5 service carving, RFC 8584 §3 algorithm negotiation,
  Prometheus `evpn_df_role` surface + `evpn_df_role_changes_total`
  counter, M38 smoke topology. **Forwarding enforcement was deferred
  from Gate 8 and is now covered by the Gate 8b alpha items below.**
- [x] **Gate 8b prep — ES-Import RT + ESI Label origination.**
  Auto-derived ES-Import RT extcomm (RFC 7432 §7.6) on Type 4 ES
  routes, ESI Label extcomm (RFC 7432 §7.5) on Type 1 EAD-per-ES
  with `single_active = false` (Gate 8 default). M38 driver asserts
  both extcomms appear on the wire. No wire codec change.
- [x] **Gate 8b enforcement intent foundation.** DF-election role
  state now feeds the EVPN Linux dataplane supervisor as a portable
  `(ESI, VNI)` BUM-enforcement table. The reconciler resolves bridge,
  VXLAN ifindex, and CE-facing port identity and reports the desired
  `allow` / `suppress` action in `DataplaneReport`, but still does
  not mutate kernel filters.
- [x] **Gate 8b multi-homing enforcement — end-to-end wired,
  opt-in by config, validated on a real kernel.** Closes the loop
  from DF election to kernel split-horizon. The per-port
  `bridge link set ... flood off mcast_flood off bcast_flood off`
  triplet on the CE-facing bridge port is the chosen primitive
  (proven by the privileged netns spike at
  `crates/evpn-linux/tests/scripts/netns-bum-filter-spike.sh`,
  gated on `EVPN_LINUX_NETNS=1`); five load-bearing invariants
  hold: DF allows, Non-DF blocks broadcast / multicast /
  unknown-unicast, known-unicast forwarding survives Non-DF,
  toggle is symmetric, `extern_learn` FDB add/del succeeds
  regardless of mode. The pure-logic plan
  (`crates/evpn-linux/src/bum_filter.rs`) maps
  `BumEnforcementStatus` → `Vec<BumPortFlagPlan>` with
  most-restrictive-wins on collisions and auto-restore for
  disappeared ports; `LinuxDataplane::apply` consumes
  `DataplaneOp::SetBumPortFlags` and issues `RTM_NEWLINK` with
  the `IFLA_BRPORT_*_FLOOD` triplet; the reconcile actor emits
  the diff each pass, with per-port `last_bum_plan` updates
  gated on apply success so failed ports keep retrying. Top-level
  `apply_bum_enforcement: bool` TOML field on `Config` (default
  `false`) is the operator-facing opt-in; with the flag off, the
  resolved plan still flows through `DataplaneReport.bum_enforcement`
  for visibility. Hot reload still requires a daemon restart for
  this field — promoting it to SIGHUP-reloadable rides with the
  next config-shape pass. **Validated against a real kernel via
  the Docker harness at `crates/evpn-linux/tests/docker/`** —
  spike + Rust netlink round-trip both green, confirming the
  `RTM_NEWLINK + IFLA_LINKINFO + IFLA_INFO_PORT_DATA +
  IFLA_BRPORT_*_FLOOD` encoding actually lands the desired flag
  triplet on the kernel-side bridge port. **The harness is wired
  into PR-CI** (`evpn_bum_filter_kernel` job in
  `.github/workflows/ci.yml`), so a netlink-attribute encoding
  regression can't slip past review. The remaining soak question
  (slice 1 below) is "does it stay correct under sustained
  churn?", not "does it work?".
- [x] **Per-ESI label allocator landed** (`crates/evpn/src/label_allocator.rs`).
  `EsiLabelAllocator` with stable `(ESI -> label)` assignments,
  free-list reuse, and synth-first strategy so operators on the
  Gate 8b prep upgrade path see no label change unless they hit a
  real collision. Replaces the deterministic
  `synthesize_esi_label` previously vulnerable to bytes-[4..7]
  collisions across operator-chosen ESIs.
- [x] **DF-role-aware (ESI-aware) MAC origination landed**
  (`src/evpn_originator.rs`). Type 2 NLRIs for MACs learned on a
  VNI in a configured `[[ethernet_segments]]` block now carry the
  segment's ESI; peers can resolve aliasing alternatives via
  RFC 7432 §14. SVI MACs stay ESI=0 (L3 next-hop, not CE-side).
- [x] **Aliasing resolver landed** (`crates/evpn/src/aliasing.rs`).
  Pure-logic `AliasIndex` over EAD-per-EVI advertisements; lookup
  by `(ESI, EthernetTag)` returns deduped `Vec<IpAddr>` of VTEPs
  that can reach the segment. Shovel-ready for the projection
  layer's `RemoteMacEntry::alias_vtep_ips` wiring slice and the
  dataplane's ECMP-to-multiple-VTEPs forwarding slice.
- [x] **Mass-withdraw `AS_PATH`-change detector landed**
  (`crates/evpn/src/mass_withdraw.rs`). Pure-logic
  `AsPathTracker` with `record_advertisement` / `record_withdrawal`
  / `drop_origin_vtep`. Returns
  `MassWithdrawTrigger { origin_vtep, esi }` for fingerprint
  changes. The RIB-side sweep that consumes triggers remains a
  follow-up integration slice.
- [x] **Aliasing receive-side projection + dataplane wiring
  landed.** The daemon's projection layer resolves
  `RemoteMacEntry::alias_vtep_ips` for non-zero-ESI Type 2 routes
  by combining them with EAD-per-EVI advertisements via the
  `AliasIndex`. The supervisor at `src/evpn_dataplane.rs` plumbs
  both Type 2 and EAD-per-EVI through from the RIB.
  [ADR-0059](adr/0059-evpn-aliasing-fdb-nexthop-groups.md) is
  fully shipped in v0.19.0 across four implementation slices
  (PRs #84 / #86 / #87 / #88) plus the M40 manual containerlab
  smoke (PR #89): slice 1 added `RemoteMacEntry::alias_group_key`
  + same-AF projection invariant; slice 2 added the
  `nexthop_raw` raw-netlink primitive (rtnetlink 0.21 has no
  nexthop API); slice 3a added the state types, apply primitive,
  and CVE-2025-39851 inline guard; slice 3b is the
  operational-behavior-change slice that wires the FDB nexthop
  group programming into the reconcile actor's apply path
  (Pass 1b diff, `NexthopOps` impls on LinuxDataplane +
  InMemoryDataplane, startup NHID adoption with snapshot-aware
  retention, partial-install rollback, three-key-space retry
  schedule). Multi-homed Type 2 routes now program an FDB
  nexthop group via `NDA_NH_ID` on the receive path. M40 in
  PR #89 validated end-to-end against FRR EVPN-MH 10.3.1 —
  16/16 PASS first-shot with the expected `NHG_TAG | n` /
  `VTEP_NH_TAG | n` tag scheme and a clean drain-to-single-dst
  transition. Slice 3.5 deferred follow-ups: periodic
  `RTM_GETNEXTHOP` drift recovery, `apply_aliasing_ecmp`
  operator off-switch, IPv6 alias members.
- [x] **Mass-withdraw receive-side filter landed (RFC 7432 §8.4).**
  The supervisor's `build_remote_mac_table` snapshots EAD-per-ES
  routes from the RIB on every pass and drops any Type 2 with
  non-zero ESI whose `(origin VTEP next-hop, ESI)` isn't in that
  snapshot. When a PE withdraws its EAD-per-ES, all that PE's MACs
  for the segment disappear from the next supervisor pass (≤5s).
  Stateless, no event-tracking state machine in the supervisor — the
  `mass_withdraw::AsPathTracker` shipped earlier remains for
  future event-driven RIB-side work where sub-poll latency
  matters.
- [ ] **Gate 8b — remaining multi-homing enforcement work.** Two
  concrete slices left (the aliasing-dataplane slice landed via
  ADR-0059, see above):
  1. **MAC-churn variant of the 24 h BUM-state soak.** Single-pass
     primitive validation already landed via the Docker harness; the
     baseline 24 h BUM-state soak completed 2026-05-11
     (full postmortem: [`docs/soak-gate8b-24h-bum-state.md`](soak-gate8b-24h-bum-state.md)).
     PE1 RSS plateaued at 13.9453 MB after a one-time 3h 32m settle
     and stayed there for the remaining 20.5h (steady-state slope
     0.000 MB/h); all 142 flip events kept the BUM-port flag
     triplet on the expected side of every DF transition. What's
     still ahead is the **MAC-churn variant** (FDB programming
     concurrent with flag flips) so the combined enforcement +
     origination paths get the same sustained-churn confidence
     under realistic timing. The MAC-churn variant reuses
     `tests/soak/run-gate8b-soak.sh` with an additional ~10 Hz
     `bridge fdb add / del` loop on the per-cycle hook. This is
     the gate to flip the `apply_bum_enforcement` default to
     `true`.
  2. Optional import-side ES-Import RT filtering on the daemon's
     own RIB import path (we already *originate* the RT in Gate 8b
     prep; this would also *import* by it).
  Estimated ~1-2 weeks once started.
- [x] **Gate 9 — symmetric Interface-less IRB end-to-end (v0.18.0).**
  Per-VRF IP routes via Type 5, MAC-VRF + IP-VRF separation,
  Router MAC extended community lifecycle, the symmetric IRB
  packet path through the kernel. Full readiness + origination +
  import + L3 FIB programming chain shipped in v0.18.0:
  - `[[evpn_ip_vrfs]]` TOML schema + validation, optional
    `ip_vrf` field on `[[evpn_instances]]` (config foundation).
  - Pure-logic `ip_vrf::readiness` probe against ADR-0058 §3's
    seven predicates, with per-failure `NotReady { reasons }`
    surface.
  - Pure-logic `ip_vrf::origination` + `ip_vrf::projection`
    helpers for Type 5 NLRI + RT-keyed import / Router MAC
    enforcement / self-origination filtering.
  - Linux `ip_vrf::dump_ip_vrf_observations` (VRF + L3 VXLAN
    netlink dumps) and `Dataplane::probe_ip_vrfs` trait + Linux
    implementation.
  - `IpVrfTable` plumbed through `DataplaneIntent`; the reconcile
    actor calls `probe_ip_vrfs` each pass and logs `Ready` ↔
    `NotReady` transitions via tracing.
  - `DataplaneReport.ip_vrf_status` rows + `rustbgpctl evpn vrfs
    [NAME]` CLI + `EvpnService.ListIpVrfs` / `EvpnService.GetIpVrf`
    gRPC RPCs so operators read the verdict without scraping logs.
  - **Slice 6 PR A (#77)**: per-IP-VRF kernel-route observation +
    local Type 5 origination. The reconcile actor's per-pass
    `Dataplane::dump_ip_vrf_routes` walks each IP-VRF's `table_id`
    via `RTM_GETROUTE`, runs a conservative classifier
    (connected/static/manual kept; other routing daemons' routes,
    non-forwardable types, link-local / multicast prefixes, and
    routes whose output device is the IP-VRF's own L3 VXLAN are
    filtered), and emits observations on
    `DataplaneReport.ip_vrf_routes`. The daemon mirrors observations
    onto a `tokio::sync::watch` channel that the new L3 originator
    task subscribes to alongside the slice-5 readiness watch.
    The originator's level-triggered diff loop injects Type 5
    routes when the IP-VRF is `Ready` and withdraws them on
    readiness loss; transient kernel-dump failure preserves the
    last-good observation snapshot so a netlink hiccup doesn't
    cascade into a mass withdraw. `IpVrfState.originated_routes_count`
    + three new Prometheus series (observed gauge, filtered
    counter, suppressed counter) expose the surface to operators.

  - **Slice 6 PR B (#78)**: remote Type 5 import + L3 FIB
    programming. The daemon subscribes to the EVPN best-path
    broadcast, runs `project_ip_prefix_routes()` on each
    refreshed RIB view to derive per-IP-VRF target state, and
    drives the kernel through a transactional L3 ownership model
    (`L3OwnedState` in `crates/evpn-linux/src/l3_diff.rs`): per
    `(IpVrfId, prefix)` route install state plus shared
    `kernel_neighbors: BTreeMap<(idx, ip), MacAddress>` and
    `kernel_fdb: BTreeMap<(idx, MacAddress), IpAddr>` so the diff
    catches both refcount changes and value drift (next-hop or
    Router MAC changing under the same prefix triggers
    `.replace()` ops on the kernel-side rows). Four-phase apply
    ordering — route removes → resolution adds (neighbor → FDB)
    → route adds → resolution removes — keeps the kernel in a
    forwarding-safe state across transitions. Router MAC
    conflicts (two prefixes mapping `(L3VXLAN idx, router_mac)`
    to different next-hops) drop all conflicting prefixes with
    `L3Drop::RouterMacConflict` rather than silently
    misforwarding. Foreign state preservation is enforced by
    diffing only against `L3OwnedState`, never the kernel dump.
    Shutdown drain (`reconcile::drain`) computes
    `compute_l3_diff` against empty intent so the L3 ownership
    state unwinds before exit. 11 unit tests in `l3_diff.rs`
    cover cold start, refcount, shape change, value drift,
    Router MAC conflict, partial-success cleanup, failed-remove
    retry, NotReady drain, idempotent record. Two privileged
    netns integration tests at
    `crates/evpn-linux/tests/netns_l3_install.rs` (gated on
    `EVPN_LINUX_NETNS=1`) re-exec the process inside an `ip
    netns` and assert kernel `ip route show table`, `ip neigh
    show dev`, and `bridge fdb show dev` produce the expected
    rows, with one test pre-loading a `proto static` foreign
    route and verifying it survives our install/withdraw cycle.
    `IpVrfState.installed_routes_count` + install-error counters
    expose the surface to operators.
  - **M39 manual containerlab smoke** at
    `tests/interop/m39-evpn-type5-symmetric-irb.clab.yml`
    validates the bidirectional Type 5 path against FRR 10.3.1:
    BGP Established, Type 5 origination both directions, PE1
    kernel route + L3 neighbor + L3VXLAN FDB rows landed,
    `installed_routes_count == 1`, bidirectional `ip vrf exec
    vrf1 ping`, and withdraw on `ip addr del`. Same hosted-runner
    constraint as M30b (Azure kernel lacks `vrf` module); manual
    invocation per the row in `docs/INTEROP.md`.

  Follow-on optimization once the reconcile-loop integration is
  in place: share one rtnetlink link dump across
  `links::dump_links` (L2) and `ip_vrf::dump_ip_vrf_observations`
  (L3). Today each reconcile pass issues two `RTM_GETLINK`
  round-trips that traverse the same kernel link list. Saves
  one syscall + one allocation per pass; matters under churn.
  Not a correctness blocker.
- [ ] **`[[evpn_instances]]` mutation surface.** Today the table is
  pinned at startup. `AddEvpnInstance` / `DeleteEvpnInstance` gRPC
  + SIGHUP reload semantics need a swap surface (`ArcSwap` or
  `RwLock`) and careful interaction with the originator's per-VNI
  `LocalMacOriginator` state (delete must drain its Withdraws first).

## Field-readiness gates

- [ ] **bgperf2-style scale**: 100 k local MACs originated by a
  single rustbgpd VTEP, RIB / AdjRibOut / wire encode hot path
  profiled. Reuses the Gate 7b 50 k EVPN scale infrastructure.
- [ ] **Cross-vendor interop sweep**: M37 against Junos and Arista
  in addition to FRR. Junos vMX + cEOS are listed as "stretch"
  targets in `docs/INTEROP.md`; landing one of them would close the
  "RFC 7432 §15 mobility actually interoperates" question
  empirically.
- [x] **Operational runbook** for the bidirectional VTEP path:
  diagnostic flowchart for "MAC learned in kernel but Type 2 not on
  wire" / "remote Type 2 received but FDB not programmed" / "IMET
  drained early on shutdown". The MR debug logs are in place
  (cache-miss in the classifier, originator emit, IMET inject); the
  runbook at `docs/evpn-vtep-troubleshooting.md` ties them to
  operator-actionable triage steps.

## Reference

- ADR-0054 — Linux dataplane boundary (Gate 7b)
- ADR-0055 — Local-MAC origination boundary (Gate 7b+1)
- ADR-0058 — Gate 9 symmetric Interface-less IRB design
- ADR-0059 — EVPN aliasing dataplane via FDB nexthop groups
- `docs/evpn-enablement.md` — gate ladder + still-ahead lists
- `docs/soak-gate8b-24h-bum-state.md` — Gate 8b BUM-state 24h soak
- `docs/soak-gate9-slice6-24h-symmetric-irb.md` — Gate 9 slice 6 24h soak
- `docs/evpn-vtep-troubleshooting.md` — bidirectional VTEP runbook
- `docs/INTEROP.md` — M36, M37 test coverage
- `KNOWN_ISSUES.md` — by-design alpha limitations
