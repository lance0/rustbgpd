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
  builds `rustbgpd:dev` with a GitHub Actions layer cache (`type=gha`).

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
- M46: EVPN HRW DF election (rustbgpd ×2).
- M47: EVPN runtime tenant teardown against FRR.
- M48: EVPN runtime tenant teardown over the kernel L3 datapath (uses `vrf`).
- M49: EVPN preference-DF election (rustbgpd ×2).
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
- M43: ADR-0062 static-neighbor TCP-AO protected session against BIRD 3.2.1
  (conditional on the runner advertising `CONFIG_TCP_AO=y`).
- Docker netns selectors: `fdb_nhg`, `fib_runtime`, `bfd_runtime`,
  `dataplane_vlan_fdb`, `svd_fdb_vni`, and `l3_multipath`.

The `Privileged Interop (netns)` workflow (`privileged-interop.yml`) is a
manual (`workflow_dispatch`) on-demand harness for the non-docker direct-`cargo
test` netns binaries (`netns_dataplane` / `netns_fdb_nhg` / `netns_l3_install` /
`netns_nexthop_raw`); its former containerlab EVPN smokes (M36–M49) now run
automatically here.

## Security model

Jobs run on GitHub's ephemeral hosted VMs, so untrusted PR code never touches a
persistent machine of ours — the custom `kernel-dataplane` Environment approval
gate and `self-hosted` runner group are no longer needed. Fork / first-time
contributor PRs are gated by GitHub's default workflow-approval policy. The
workflow uses `pull_request` (not `pull_request_target`), so PR code runs with
normal pull-request token permissions; no repository secrets are required.
