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
  `tests/interop/scripts/test-m37-evpn-local-origination-churn.sh`;
  the remaining work is to run it long enough to confirm RSS slope
  stays flat under the originator's
  `BTreeMap<MacAddress, LocalMacOriginationState>` retention model
  (entries are kept after Aged so the seq ratchet survives — we want
  to verify that doesn't compound badly under heavy churn).

## Convergence + correctness slices

- [ ] **5 s RIB-poll floor for remote-best-path mobility.** The
  originator polls `RibUpdate::QueryEvpnRoutes` every 5 s to detect
  remote contention; the existing `RouteEvent` broadcast is keyed
  by `Prefix` and is unicast-only. ADR-0055 §5 defers sub-second
  convergence to Gate 7c. Path forward: either add an EVPN-keyed
  broadcast in `crates/rib/src/event.rs` or a `tokio::sync::Notify`
  the EVPN best-path apply pings. Both are ~150-250 LOC.
- [ ] **MAC-with-IP (Type 2 with host IP) origination.** Gate 7b+2.
  Requires a separate `AF_INET` / `AF_INET6` `RTNLGRP_NEIGH`
  subscription correlated by MAC against the bridge's ARP/ND-
  suppression table. ADR-0055 §7. The wire codec already supports
  `EvpnRouteKey::MacIp.ip = Some(...)`; only the consumer is
  deferred.
- [ ] **`advertise_svi_mac` consumption.** The flag is parsed and
  ignored today. Plug `RTM_GETLINK` on the bridge at instance-Ready
  to read the SVI MAC, then originate a Type 2 for it. Intersects
  IRB / L3VNI design (Gate 9) but the SVI-MAC slice can ship
  independently.
- [ ] **RFC 7432 §15.1 duplicate-MAC quarantine** (M=180 s, N=5
  moves). ADR-0055 §9 defers the action; the detection-only
  `evpn_duplicate_mac_moves_total{vni,mac}` counter has landed so
  operators can see repeated contention for a key. Still ahead:
  first-move timestamp / window state, quarantine action, and the
  operator-facing escalation channel.
- [ ] **Static / sticky MAC anti-spoof config schema.** Wire codec
  for the sticky bit is plumbed; the operator-facing knob isn't.
  ADR-0055 §8. Schema question: per-MAC list on `EvpnInstance`,
  per-port, or imported from sysctl? Needs its own ADR.

## Larger follow-on gates (out of v0.15.0 scope, tracked here for
visibility)

- [ ] **Gate 8 — multi-homing execution + DF election.** Type 1
  EAD-per-EVI origination from a shared ESI, RFC 7432 §8 / RFC 8584
  DF election, ESI Label extended community for split-horizon,
  backup-path selection. ~3-4 weeks.
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
