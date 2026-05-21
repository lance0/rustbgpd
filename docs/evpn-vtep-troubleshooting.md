# EVPN VTEP troubleshooting runbook

This runbook is for the bidirectional EVPN VTEP alpha path:

- Gate 7b: received Type 2 routes program Linux bridge/VXLAN FDB
  entries.
- Gate 7b+1: kernel-learned local MACs originate EVPN Type 2 routes,
  and one Type 3 IMET is originated per configured L2VNI.
- Gate 7b+2: MAC-with-IP origination — `AF_INET` / `AF_INET6`
  neighbour observations on the bridge correlate with their MAC and
  are advertised under FRR-style replace semantics (one of MAC-only
  / MAC+IP advertising at any time).
- Gate 7c: sub-second remote-best-path mobility via the EVPN-keyed
  `EvpnRouteEvent` broadcast; the 5 s `QueryEvpnRoutes` poll stays
  as a backstop for `Lagged` subscribers and cold start.

RR-only deployments with empty `[[evpn_instances]]` do not spawn the
dataplane reconciler or local-MAC originator.

## Fast state snapshot

Run these first:

```bash
rustbgpctl evpn instances
rustbgpctl evpn --route-type 2
rustbgpctl evpn --route-type 3
bridge fdb show
```

Expected signals:

- `rustbgpctl evpn instances` lists each configured VNI and
  `originated-local-macs=N`.
- `rustbgpctl evpn --route-type 3` lists one IMET for each configured
  L2VNI after the daemon starts.
- `bridge fdb show` contains remote MACs as `extern_learn` rows with a
  `dst` pointing at the remote VTEP IP.
- Prometheus shows flat `evpn_local_origination_errors_total` and
  `evpn_local_observations_dropped_total` counters during steady state.
- `rustbgpctl evpn diagnose` summarizes instance count, Type 2/3 route
  presence, and the key EVPN metrics from one command.

## Local MAC learned, but no Type 2 appears

1. Confirm the MAC is on a non-VXLAN bridge port:

   ```bash
   bridge fdb show br br100 | grep -i 02:aa:bb:cc:dd:01
   bridge link show
   ```

   The originator ignores VXLAN-port observations because those are
   remote-MAC echoes, not locally attached hosts.

2. Confirm the EVI is active:

   ```bash
   rustbgpctl evpn instances
   ```

   The bridge must match the configured instance. `originated-local-macs`
   should increment after the RIB accepts the Type 2.

3. Check event loss before the originator:

   ```bash
   curl -s http://127.0.0.1:9179/metrics \
     | grep evpn_local_observations_dropped_total
   ```

   Non-zero `reason="channel_full"` means local MAC events are arriving
   faster than the originator channel can drain. Non-zero
   `reason="channel_closed"` means the dataplane notify loop is still
   classifying events after the originator receiver is gone.

4. Check RIB handoff failures:

   ```bash
   curl -s http://127.0.0.1:9179/metrics \
     | grep evpn_local_origination_errors_total
   ```

   Any increment means the kernel observation reached the originator but
   the `RibUpdate::InjectEvpn` or reply path failed.

5. Enable targeted debug logging for the Linux classifier:

   ```bash
   RUST_LOG=rustbgpd_evpn_linux=debug,rustbgpd=info rustbgpd --config config.toml
   ```

   Look for local-MAC classifier messages and cache misses. A miss means
   the bridge-port ifindex was not yet mapped to a VNI; the startup dump
   and periodic supervisor pass should populate it.

## Remote Type 2 visible, but FDB is not programmed

1. Confirm the Type 2 is in the EVPN RIB:

   ```bash
   rustbgpctl evpn --route-type 2 --rd 65000:100
   ```

2. Confirm the Linux readiness shape:

   ```bash
   ip -d link show br100
   ip -d link show vxlan100
   bridge link show
   ```

   Gate 7b requires an existing bridge, exactly one VXLAN port under the
   bridge, matching VNI, matching local VTEP IP, VXLAN learning disabled,
   and no VLAN-aware bridge mode. rustbgpd does not create bridge/VXLAN
   netdevs in this gate. See
   [`examples/evpn-vtep-leaf/README.md`](../examples/evpn-vtep-leaf/README.md)
   for exact `ip link` pre-create commands.

3. Confirm permissions:

   ```bash
   getcap "$(command -v rustbgpd)"
   ```

   `CAP_NET_ADMIN` is required for rtnetlink FDB programming and
   multicast netlink subscription.

4. Inspect the two-row kernel shape:

   ```bash
   bridge fdb show dev vxlan100 | grep -i 02:aa:bb:cc:dd:01
   bridge fdb show br br100 | grep -i 02:aa:bb:cc:dd:01
   ```

   A working programmed remote MAC has a VXLAN self row with `dst
   <remote-vtep>` and a bridge-master row with `extern_learn`.

## IMET missing or not withdrawn

Type 3 IMET is originated at startup for every configured L2VNI and
withdrawn during coordinated shutdown before BGP peer sessions are
stopped.

Check:

```bash
rustbgpctl evpn --route-type 3
```

On an FRR peer:

```bash
vtysh -c 'show bgp l2vpn evpn route type multicast'
```

If IMET is absent, verify the session reached Established with
`l2vpn_evpn` negotiated. If IMET persists after a clean daemon exit,
check structured logs for the EVPN originator and IMET drain messages
before peer shutdown.

## Duplicate-MAC / mobility noise

Duplicate-MAC detection runs per `(VNI, MAC)` using the RFC 7432 §15.1
M/N window configured on the owning `[[evpn_instances]]` entry. Default
behavior is detect-only; `duplicate_mac_detection.action =
"suppress_local"` withdraws/suppresses local Type 2 originations for the
key until `recovery_seconds` elapses.

```bash
curl -s http://127.0.0.1:9179/metrics \
  | grep -E 'evpn_duplicate_mac_(moves_total|first_move_timestamp_seconds|threshold_exceeded_total|quarantine_active)'
```

Repeated increments for the same `(vni, mac)` indicate cross-VTEP
contention and should be investigated as a loop, spoof, or host mobility
event. One-off increments can be normal during planned host moves. While
`evpn_duplicate_mac_quarantine_active{vni,mac}` is `1`, this daemon does
not originate local Type 2 routes for that key, and it filters the
quarantined `(VNI, MAC)` out of the remote-FDB dataplane intent (so Linux
FDB / NHG state stops programming forwarding for it); Loc-RIB, RR
reflection, and `ListEvpnRoutes` visibility are preserved. Quarantine
clears automatically after `recovery_seconds`, or immediately via
`rustbgpctl evpn clear-duplicate-mac --vni <VNI> --mac <MAC>`.

## MAC+IP routes not appearing

Gate 7b+2 origination requires the operator to enable per-VXLAN-port
neighbour suppression on the bridge so the kernel routes ARP/ND
bindings into the bridge's neighbour table. Without it, no
`IpAdded` events reach the daemon and only MAC-only Type 2 routes
get advertised. Verify in this order:

```bash
# 1. neigh_suppress on the VXLAN port?
bridge -d link show dev vxlan100 | grep neigh_suppress
#    Expect: neigh_suppress on

# 2. Does the kernel have an (IP, MAC) binding on the *bridge*?
ip neigh show dev br100
#    Expect: <ip> dev br100 lladdr <mac> ... REACHABLE/STALE/PERMANENT

# 3. Is the daemon receiving the IpAdded event?
RUST_LOG=rustbgpd::evpn_originator=debug rustbgpd ...
#    Expect: the FRR-style replace-flow Inject/Withdraw pair in the
#    originator log when the binding lands.
```

Common gotchas:

- **`neigh_suppress` set on the bridge instead of the VXLAN port.**
  The flag is per-port and only meaningful on the VXLAN port —
  setting it on the bridge itself is silently ignored. Use
  `bridge link set dev vxlan<vni> neigh_suppress on`, not
  `bridge link set dev br<vni>`.
- **Entry in `INCOMPLETE` / `FAILED` / `DELAY` / `PROBE` state.**
  The daemon's classifier deliberately drops these per RFC §15
  spirit — acting on them mid-revalidation produces origination
  thrash. Wait for the kernel to confirm the binding (`REACHABLE`)
  or use `ip neigh replace ... nud reachable` to force it.
- **Address-shape filter dropped the IP.** Multicast, link-local,
  loopback, broadcast, and unspecified addresses are filtered at
  the classifier per ADR-0054 §1. A `192.0.2.10` works; a
  `fe80::1` is dropped. See `crates/evpn-linux/src/linux/notify.rs`
  for the full filter.

## Local smoke

The current real-VTEP smokes are M37 (MAC-only origination) and
M37+IP (MAC+IP origination via ARP/ND suppression):

```bash
docker build -t rustbgpd:dev .

# MAC-only path (Gate 7b+1)
sudo containerlab deploy -t tests/interop/m37-evpn-local-origination.clab.yml
bash tests/interop/scripts/test-m37-evpn-local-origination.sh
sudo containerlab destroy -t tests/interop/m37-evpn-local-origination.clab.yml

# MAC+IP path (Gate 7b+2 — requires bridge neigh_suppress on)
sudo containerlab deploy -t tests/interop/m37-evpn-mac-ip-origination.clab.yml
bash tests/interop/scripts/test-m37-evpn-mac-ip-origination.sh
sudo containerlab destroy -t tests/interop/m37-evpn-mac-ip-origination.clab.yml
```

For churn, run the M37 topology and then use the local-only churn driver:

```bash
bash tests/interop/scripts/test-m37-evpn-local-origination-churn.sh --smoke

M37_CHURN_MACS=1000 M37_CHURN_ROUNDS=60 \
  bash tests/interop/scripts/test-m37-evpn-local-origination-churn.sh
```

Watch RSS, `originated-local-macs`, and the EVPN metrics while it runs.

## Multi-homed MAC not load-sharing across alias VTEPs

ADR-0059 ships aliasing dataplane ECMP via FDB nexthop groups
(`NDA_NH_ID` + `NHA_FDB`). A multi-homed Type 2 with ESI on a
shared Ethernet Segment should land as an FDB row referencing a
nexthop **group**, not a single-dst `dst <ip>` row.

**Symptom**: traffic to a multi-homed MAC only hits one alias VTEP.

**Triage**:

1. `bridge fdb show dev vxlanNNN | grep -i <mac>` — a correctly
   programmed multi-homed row shows `nhid <id>` (decimal) instead
   of `dst <ip>`.
2. `ip nexthop show` — expect one group line `id <gid> group
   <mid>/<mid> ... fdb` and the corresponding member lines `id
   <mid> via <ip> fdb`. NHIDs are tagged: groups at
   `0x4000_xxxx`, members at `0x3000_xxxx`.
3. Confirm rustbgpd actually observed both alias VTEPs' Type 1
   EAD-per-EVI routes for the shared ESI — check
   `rustbgpctl evpn instances` or the gRPC `ListEvpnInstances`,
   and verify peer sessions are Established.
4. If the FDB row has `dst <ip>` (not `nhid`), the entry is in
   the single-dst fallback path. Common causes:
   - Mixed address-family alias members: one FDB nexthop group
     cannot mix IPv4 and IPv6 VTEPs, so rustbgpd warns once per
     `(VNI, MAC)` and falls back to the primary VTEP. Homogeneous
     IPv4 aliases and homogeneous IPv6 aliases both use the FDB-NHG
     path.
   - All but one alias VTEP withdrew their EAD-per-EVI (the
     projection invariant `empty alias_vtep_ips ⇔
     alias_group_key.is_none()` collapses N→1 alias to
     single-dst).
   - CVE-2025-39851 guard: rustbgpd refuses to install FDB-NHG
     rows on a VXLAN device with `learning on`. `ip -d link
     show vxlanNNN | grep learning` — must say `nolearning`.
   - `apply_aliasing_ecmp = false` on the `[[evpn_instances]]`
     entry for the VNI. Slice 3.5 added a per-L2VNI off-switch
     that routes multi-homed entries through the single-dst path.
     Check the config + restart-required flip semantics in
     `docs/CONFIGURATION.md`.

The slice 4 / M40 smoke
(`tests/interop/scripts/test-m40-evpn-aliasing-ecmp-frr.sh`)
runs end-to-end against FRR EVPN-MH and is the canonical
correctness reference if you suspect the daemon path itself.

For live systems, `rustbgpctl evpn nexthops` shows the reconciler's
owned FDB-NHG view: per-VNI groups, member nexthop IDs, MAC refs,
orphan tagged nexthop count, pending-delete count, and drift-recovery
state. Use it before falling back to raw `ip nexthop show` / `bridge
fdb show` output.

### Stale tagged FDB rows after `apply_aliasing_ecmp` restart-flip

**Symptom**: after flipping `apply_aliasing_ecmp = true → false` in
`[[evpn_instances]]` and restarting the daemon, `bridge fdb show`
still has `nhid <id>` rows that the daemon now refuses to install.

**Cause**: the slice 3b adoption pass reserves the tagged kernel
NHIDs from the prior run into the allocator, but with the gate
flipped off the diff layer emits no `RemoveFdbNhg` (the FDB
nexthop group path is gated off). The orphaned FDB row stays
bound to the stale `nh_id` until something overwrites it.

**Resolution**: slice 3.5 PR 2 (periodic `RTM_GETNEXTHOP` drift
recovery) closes this gap as part of the 60 s reconcile cadence —
the orphaned tagged rows are cleaned up within ≤ 60 s of daemon
start. If you are on a build that predates PR 2 and need an
immediate cleanup, `bridge fdb del <mac> dev vxlanNNN nhid <id>`
the stale rows by hand, or flip the knob back to `true`, restart
once to re-adopt cleanly, then flip back to `false`.

## IP-VRF stuck in `NotReady`

Gate 9 slice 6 surfaces per-VRF readiness via gRPC
(`EvpnService.GetIpVrf` / `ListIpVrfs`) and the CLI
(`rustbgpctl evpn vrfs [NAME]`). The probe checks the seven
ADR-0058 §3 predicates; `NotReady { reasons }` reports every
failing predicate at once.

**Symptom**: an `[[evpn_ip_vrfs]]` entry never originates Type 5
or installs remote prefixes.

**Triage**:

1. `rustbgpctl evpn vrfs <name>` and read the `not_ready_reasons`
   list. Common entries:
   - `vrf_device_missing` / `not_up` — the VRF master device must
     exist and be UP before the probe runs.
   - `vrf_table_id_mismatch` — the kernel's VRF `table` must
     match the configured `table_id`.
   - `l3vxlan_device_missing` / `not_up` / `vni_mismatch` /
     `local_ip_mismatch` / `not_enslaved_to_vrf` /
     `router_mac_mismatch` — covers the L3VXLAN device side.
2. `ip link show type vrf` + `ip -d link show type vxlan` to
   confirm the kernel side matches the rustbgpd config.
3. If the probe is `Ready` but `originated_routes_count == 0`,
   inspect the per-IP-VRF kernel route table: `ip route show
   table <table_id>`. The slice 6a classifier filters out
   routes installed by other routing daemons (any `proto` other
   than `kernel`/`static`/`boot`/`zebra`-with-EVPN-marker),
   non-forwardable types, and routes whose output device is the
   IP-VRF's own L3 VXLAN.
4. If `installed_routes_count == 0` despite a remote PE
   advertising Type 5: check the Router MAC extcomm conflict
   path. Two prefixes mapping `(L3VXLAN ifindex, router_mac)` to
   different next-hops trip
   `L3Drop::RouterMacConflict` and drop both. Look for
   `evpn_l3_dropped_router_mac_conflict_total` in Prometheus.
