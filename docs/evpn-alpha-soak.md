# EVPN VTEP alpha-soak checklist

Post-merge confidence list for the bidirectional EVPN VTEP loop
(Gates 7a + 7b + 7b+1, v0.15.0). The branch landed the
control-plane and kernel paths; this file tracks what we still need
to retire residual alpha-VTEP risk before claiming v1.0-grade
production readiness.

Items are checkboxed so individual slices can move independently;
none of them block v0.15.0 release on their own.

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
- [ ] **24 h soak** of M37 with a synthetic MAC churn driver
  (`bridge fdb add` + `bridge fdb del` at ~10 Hz on a few thousand
  MACs). The local-only driver now lives at
  `tests/interop/scripts/test-m37-evpn-local-origination-churn.sh`.
  Use `--smoke` for a one-round, five-MAC pre-release check; the
  remaining work is to run the full driver long enough to confirm RSS
  slope stays flat under the originator's
  `BTreeMap<MacAddress, LocalMacOriginationState>` retention model
  (entries are kept after Aged so the seq ratchet survives — we want
  to verify that doesn't compound badly under heavy churn).

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

## Larger follow-on gates (out of v0.15.0 scope, tracked here for
visibility)

- [x] **Gate 8 — multi-homing foundation + observable DF election.**
  Type 4 ES + Type 1 EAD-per-ES + Type 1 EAD-per-EVI origination,
  RFC 7432 §8.5 service carving, RFC 8584 §3 algorithm negotiation,
  Prometheus `evpn_df_role` surface + `evpn_df_role_changes_total`
  counter, M38 smoke topology. **Forwarding enforcement deferred to
  Gate 8b** — see ADR-0057 for the carve-out.
- [x] **Gate 8b prep — ES-Import RT + ESI Label origination.**
  Auto-derived ES-Import RT extcomm (RFC 7432 §7.6) on Type 4 ES
  routes, ESI Label extcomm (RFC 7432 §7.5) on Type 1 EAD-per-ES
  with `single_active = false` (Gate 8 default). M38 driver asserts
  both extcomms appear on the wire. No wire codec change.
- [ ] **Gate 8b — multi-homing enforcement.** Six concrete
  remaining slices:
  1. Dataplane split-horizon enforcement (feed `evpn_df_role` into
     the Linux dataplane supervisor; suppress CE-facing BUM on
     Non-DF for `(ESI, VNI)`, preserve remote FDB programming and
     local learning).
  2. Proper per-ESI label allocator (replaces the deterministic
     ESI-byte-derived synthesizer used by Gate 8b prep).
  3. Aliasing / backup paths via Type 1 EAD-per-EVI (RFC 7432 §14).
  4. Mass-withdraw on `AS_PATH` change (RFC 7432 §8.6).
  5. DF-role-aware MAC origination (couples to slice 1).
  6. Optional import-side ES-Import RT filtering on the daemon's
     own RIB import path (we already *originate* the RT in Gate 8b
     prep; this would also *import* by it).
  Estimated ~3-4 weeks once started.
- [ ] **Gate 9 — symmetric IRB (RFC 9135) + L3VNI / Type 5
  dataplane.** Per-VRF IP routes via Type 5, MAC-VRF + IP-VRF
  separation, Router MAC extended community lifecycle, the
  symmetric IRB packet path through the kernel. ~2-3 weeks. The
  `crates/rib` Type 5 codec already round-trips; the daemon-side
  origination + kernel programming is what's missing.
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
- `docs/evpn-enablement.md` — gate ladder + still-ahead lists
- `docs/evpn-vtep-troubleshooting.md` — bidirectional VTEP runbook
- `docs/INTEROP.md` — M36, M37 test coverage
- `KNOWN_ISSUES.md` — by-design alpha limitations
