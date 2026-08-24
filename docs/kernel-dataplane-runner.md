# Kernel Dataplane Runner

The `Kernel Dataplane` workflow (`.github/workflows/kernel-dataplane.yml`) runs
the privileged Linux dataplane interop suite on **GitHub-hosted `ubuntu-latest`**
runners. A spike on 2026-05-25 confirmed the hosted Azure-kernel VM provides
everything these tests need; the suite previously targeted a self-hosted runner,
which has been **retired**.

## Why hosted works

The hosted `ubuntu-latest` runner is a full VM with **passwordless `sudo`**, so
job steps run privileged kernel operations directly (`ip netns`, `modprobe`,
`docker run --cap-add=…`, `containerlab deploy`). The one gap is that the slim
Azure kernel ships without the `vrf` module — it is supplied on demand by
`linux-modules-extra-$(uname -r)` (see `setup-dataplane-host` below). Everything
else the suite needs is present: bridge + VXLAN, FDB nexthop groups
(`NDA_NH_ID`, kernel ≥ 5.8), real netns route tables, `CONFIG_TCP_AO`, and
UDP/3784 for BFD.

> The privileged-in-*container* restriction (the single-CPU "ubuntu-slim" /
> `container:`-job runners) does **not** apply here: these jobs run their steps
> directly on the VM, and the netns harness adds caps to its *own* child
> container via `docker run --cap-add=NET_ADMIN --cap-add=SYS_ADMIN`.

## Per-job setup (no shared state)

Each hosted job is an isolated VM, so it provisions itself rather than reusing a
shared persistent Docker daemon. Two composite actions carry the repetition:

- **`.github/actions/install-containerlab`** — downloads the pinned containerlab
  release with retry + `dpkg-deb --info` validation before `dpkg -i` (issue
  #208), so a truncated/HTML download fails clearly instead of with
  `dpkg-deb: … is not a Debian format archive`. Shared with `interop.yml`.
- **`.github/actions/setup-dataplane-host`** — installs containerlab (via the
  above), `grpcurl` + `jq`, loads kernel modules (`vrf` via
  `linux-modules-extra` when absent, plus `vxlan` / `bridge` / `bonding`), and
  builds `rustbgpd:dev` with a GitHub Actions layer cache (`type=gha`). The
  `vrf` load is best-effort and exposes a `vrf-available` output: the hosted
  kernel can roll ahead of the matching `linux-modules-extra-$(uname -r)` in the
  apt mirror (`actions/runner-images` #7570 / #7587), and on that transient skew
  the module cannot install. The vrf-dependent receipts are CI-gated on that
  output — they run when the runner exposes or can install `vrf`, and otherwise
  **skip with a notice** rather than fail (the netns job applies the same gate
  to its L3 selectors).

Because every job rebuilds from a clean VM, stale `clab-*` topology
accumulation cannot happen across jobs (this obsoletes issue #188 — there is no
persistent host to sweep).

## Retry + telemetry

`.github/actions/run-interop-test` deploys → runs → destroys each topology with
bounded retry, and records per-job **retry telemetry** to the job summary
(topology, attempts used, result, whether a retry absorbed a transient failure —
issue #187) so reviewers can distinguish real stability from flake masking.

## What runs

- M36: EVPN VTEP receive-side FDB programming against FRR.
- M37 / M37+IP: EVPN local MAC / MAC+IP origination against FRR.
- M38: EVPN DF election + Type 1/4 origination (rustbgpd ×2).
- M39: EVPN Type 5 symmetric Interface-less IRB against FRR (uses `vrf`).
- M39b: EVPN auto-derived Route Targets, cross-vendor against FRR (uses `vrf`).
- M68: EVPN GW-IP overlay-index Type 5 consumed by FRR
  `enable-resolve-overlay-index` (uses `vrf`).
- M47: EVPN runtime tenant teardown against FRR.
- M48: EVPN runtime tenant teardown over the kernel L3 datapath (uses `vrf`).
- M40: EVPN aliasing dataplane ECMP via FDB nexthop groups against FRR EVPN-MH.
- M42: ADR-0061 configured-table unicast FIB runtime against FRR.
- M58: ADR-0061 runtime `[[fib_tables]]` CRUD against FRR and the real kernel
  (`SetFibTable` / `DeleteFibTable` / `ListFibTables`, persistence, and
  key-move withdraw/install).
- M50: ADR-0066 unicast multipath/ECMP FIB install against two FRR peers.
- M52: ADR-0066 multipath-relax against two FRR peers in different ASes.
- M53: ADR-0069 BGP unnumbered / IPv6 link-local peering with scoped FIB ECMP
  against two FRR peers over unnumbered links.
- M51: ADR-0067 single-hop BFD + RFC 5882 coupling against FRR `bfdd`.
- M43: TCP-AO dynamic `/24` queued-child reconciliation plus full live
  add/select/deprecate/delete rotation against BIRD 3.3.1 (conditional on the
  runner advertising `CONFIG_TCP_AO=y`). The deletion phase proves the exact
  sole-survivor inventory, unchanged session, the route present at every sample
  from a 100 ms polling oracle, and authenticated post-delete traffic. A
  separate clean-topology mode SIGKILLs rustbgpd after add-only, while
  selection/deprecation is `awaiting_peer`, and after delete. Every restart
  must use the copied process-durable config, get a new PID, recover fresh
  generation `1/1` / `idle`, re-establish only with TCP-AO, restore the exact
  phase inventory and Current/RNext, and receive the BIRD route again. The
  selection restart first requires authenticated `degraded` Current `2` /
  RNext `13` while BIRD still sends the deprecated key, then `healthy` `3/13`
  only after BIRD switches.
- M60: ADR-0079 EVPN adoption sweep kill-and-restart against FRR.
- M61: ADR-0079 EVPN L3 adoption sweep kill-and-restart against FRR.
- M62: ADR-0079 blackhole adoption sweep kill-and-restart against FRR.
- M65: ADR-0083 single-active failover blackout measurement against GoBGP.
- M66: ADR-0084 ES drain service handover (rustbgpd ×3).
- M67: ADR-0085 link-driven ES drain failover (rustbgpd ×3).
- M69: EVPN preference-DF election against FRR.
- M70: ADR-0089 VLAN-aware bridge FDB attribution against FRR.
- M71: RFC 9136 §4.3 ESI overlay-index Type 5 single-active receive against GoBGP.
- M72: RFC 9136 §4.3 ESI overlay-index Type 5 all-active receive against GoBGP.
- Docker netns selectors, in job order — `fdb_nhg`, `fib_runtime`,
  `bfd_runtime`, `dataplane_vlan_fdb`, `dataplane_remote_mac`,
  `vlan_local_mac_attribution`, `macip_vlan_attribution`, `svd_fdb_vni`,
  `managed_bridge`, `managed_vxlan`, `managed_svd_vxlan`,
  `managed_vlan_upper`, `managed_ready`, `link_carrier`, `ac_gate`,
  `nexthop_raw`, `foreign_state_l2`, and `foreign_state_nhid`. Seven further
  L3 selectors run only when the job's `vrf-available` probe loads the `vrf`
  kernel module, and skip otherwise: `l3_multipath`,
  `managed_ip_vrf_ready`, `l3_all_active_writer`, `foreign_state_l3`, and
  `l3_route_event`, `l3_single_path_cycle`, and `l3_foreign_route_cycle`.

The job always publishes a stable `netns-selector-receipt` JSON artifact and a
concise job summary. A selector is recorded only after its harness invocation
succeeds. The finalizer requires all 25 selectors when VRF is available; when
VRF is unavailable it requires the 18 unconditional selectors and records the
seven L3 omissions with reason `vrf_unavailable`. Missing, duplicate, or
unexpected required selectors fail the job.

The automatic selector inventory now includes the four exact direct-netns
proofs that were unique to the retired dispatch-only workflow: remote-MAC
programming, VLAN-scoped local-MAC attribution, the single-path L3 lifecycle,
and foreign-route preservation. They reuse the same Docker capability envelope,
VRF omission policy, receipt artifact, and required aggregate as the rest of
the kernel lane.

## Security model

Jobs run on GitHub's ephemeral hosted VMs, so untrusted PR code never touches a
persistent machine of ours — the custom `kernel-dataplane` Environment approval
gate and `self-hosted` runner group are no longer needed. Fork / first-time
contributor PRs are gated by GitHub's default workflow-approval policy. The
workflow uses `pull_request` (not `pull_request_target`), so PR code runs with
normal pull-request token permissions; no repository secrets are required.
