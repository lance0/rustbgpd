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
rbgp evpn instances
rbgp evpn --route-type 2
rbgp evpn --route-type 3
bridge fdb show
```

Expected signals:

- `rbgp evpn instances` lists each configured VNI, its L2 dataplane
  `readiness=ready|not-ready|unbound|unknown`, and
  `originated-local-macs=N`. A `not-ready` row includes the readiness
  probe reason.
- `rbgp evpn --route-type 3` lists one IMET for each configured
  L2VNI after the daemon starts.
- `bridge fdb show` contains remote MACs as `extern_learn` rows with a
  `dst` pointing at the remote VTEP IP.
- Prometheus shows flat `evpn_local_origination_errors_total` and
  `evpn_local_observations_dropped_total` counters during steady state.
- `rbgp evpn diagnose` summarizes instance count, Type 2/3 route
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
   rbgp evpn instances
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

   Look for local-MAC classifier messages and cache misses. On legacy
   non-VLAN-aware bridges, a miss means the bridge-port ifindex was not yet
   mapped to a VNI; the startup dump and periodic supervisor pass should
   populate it. On ADR-0089 VLAN-aware bridges, a miss can also mean the
   kernel event lacked `NDA_VLAN`, carried a VLAN not configured as an
   `[[evpn_instances]].bridge_vlan`, or matched a duplicate bridge/VLAN
   binding; those cases fail closed rather than guessing.

## Remote Type 2 visible, but FDB is not programmed

1. Confirm the Type 2 is in the EVPN RIB:

   ```bash
   rbgp evpn --route-type 2 --rd 65000:100
   ```

2. Confirm the Linux readiness shape:

   ```bash
   ip -d link show br100
   ip -d link show vxlan100
   bridge link show
   ```

   Gate 7b requires an existing bridge, matching VNI, matching local VTEP
   IP, and VXLAN learning disabled. Without `bridge_vlan`, the bridge must
   be non-VLAN-aware and have exactly one VXLAN port. With `bridge_vlan`,
   ADR-0089 requires a `vlan_filtering=1` bridge, exactly one VXLAN member
   for the instance VNI, and the configured VLAN on both the bridge and that
   VXLAN member; remote-MAC FDB rows are then scoped with `NDA_VLAN`.
   Unmanaged deployments still provision bridge/VXLAN netdevs out of
   band. ADR-0091 is the explicit opt-in exception for bridge, fixed-VNI
   VXLAN, VLAN upper, VRF, and L3VXLAN create/adopt/reap through
   `[managed_netdevs]`.
   `rbgp evpn instances` reports the same probe result as `readiness`
   and, for `not-ready`, the concrete failed predicate. See
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
rbgp evpn --route-type 3
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
`rbgp evpn clear-duplicate-mac --vni <VNI> --mac <MAC>`.

## Draining an Ethernet Segment for maintenance (ADR-0084)

Before taking a multi-homed CE's access circuit down, drain its
Ethernet Segment so remote PEs repair around this VTEP first
(single-active segments swap to the backup PE per ADR-0083):

```bash
rbgp evpn es drain 00:11:22:33:44:55:66:77:88:99
# ... do the access-circuit maintenance ...
rbgp evpn es undrain 00:11:22:33:44:55:66:77:88:99
```

Use `rbgp evpn es list [ESI]` to inspect the composed runtime state:
operator/link drain reasons, per-member DF/BUM role, same-ESI local
bias, whole-port AC-gate intent, and owned FDB-NHG refs. The matching
gRPC surface is `EvpnService.ListEthernetSegments`.

Draining withdraws the ES's Type 4 (exiting DF election), EAD-per-ES,
and EAD-per-EVI routes plus the member VNIs' locally-originated Type 2
MAC/MAC+IP routes, and suppresses new local-MAC origination while
drained. The local observation caches keep tracking kernel FDB/neigh
events, so undraining replays the *latest* local state (and re-runs DF
election). Repeating the current state is an idempotent no-op; an ESI
that is not in `[[ethernet_segments]]` returns `NOT_FOUND`.

### Link-driven drain and composable reasons (ADR-0085)

Bind the ES to its attachment-circuit link and the drain follows
carrier automatically:

```toml
[[ethernet_segments]]
esi = "00:11:22:33:44:55:66:77:88:99"
member_vnis = [100]
originator_ip = "10.0.0.1"
interface = "bond0"          # AC link; carrier = IFF_LOWER_UP
recovery_delay_secs = 30     # hold-off after carrier returns (0-3600)
```

- **Carrier loss drains immediately** (cable pull and `ip link set
  ... down` both clear `IFF_LOWER_UP`). A bound link that does not
  exist in the kernel counts as down — fail-closed toward drain.
- **Recovery is held off** for `recovery_delay_secs` after carrier
  returns, and the hold re-arms on every up edge, so a flapping
  circuit stays drained until it holds carrier for the full window.
  Down is always immediate; only recovery waits.
- **Reasons compose.** The RPC/CLI owns the `operator` reason; the
  binding owns `link`; the ES is drained while either is held. The
  maintenance flow above still works with a binding: drain manually,
  do the cable work (the link flapping changes nothing), undrain
  manually — origination returns only once the link is also healthy
  past its hold-off.
- **"Why is this ES drained?"** — the drain/undrain response and
  `--json` output list the reason set, and the
  `evpn_es_drained{esi, reason}` gauge exposes each reason in
  Prometheus.
- Bindings hot-apply: SIGHUP / `ApplyEvpnRuntime` may add, change, or
  remove `interface`/`recovery_delay_secs`; a changed binding
  re-evaluates against the new link immediately, and removing the
  binding clears any `link` drain.

Caveats:

- **Operator drain state is in-memory.** A daemon restart clears the
  `operator` reason and replays configured state — re-apply the drain
  after any restart inside the maintenance window. For **bound**
  segments this caveat softens: link state is re-read at startup, so
  an ES whose AC is down when the daemon boots starts drained(`link`)
  with no operator action and no hold-off.
- Drain state survives SIGHUP / runtime applies that keep the ES
  configured; removing the ES from config drops its drain entry (all
  reasons).
- The RPC is `operator_only` (it redirects live traffic); observer and
  automation principals are denied.
- Duplicate-MAC quarantines still apply: undrain does not replay a
  quarantined MAC until its quarantine clears.

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
docker build --target dev -t rustbgpd:dev .

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
   `0x4000_xxxx`, members at `0x3000_xxxx` (L3VXLAN: `0x6000_xxxx` /
   `0x5000_xxxx`). These ranges are reserved for rustbgpd — see the
   single-writer contract in `docs/deployment.md`. A foreign object
   parked in a range is quarantined (left untouched, never adopted or
   deleted) and surfaces on `evpn_foreign_nhid_range_conflicts_total`.
3. Confirm rustbgpd actually observed both alias VTEPs' Type 1
   EAD-per-EVI routes for the shared ESI — check
   `rbgp evpn instances` or the gRPC `ListEvpnInstances`,
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

For live systems, `rbgp evpn nexthops` shows the reconciler's
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

## Single-active AC gate: port disabled (or not) unexpectedly

For a single-active Ethernet Segment **with an `interface` binding**,
the dataplane enforces the RFC 7432 non-DF rule at the whole-port
level: the bound AC bridge port is held in STP state `disabled`
(every frame blocked, known unicast included) while this PE is
non-DF for **every** member VNI of the ES or the ES is drained, and
`forwarding` when it is the DF. This rides the same
`apply_bum_enforcement` knob as the BUM flood flags.

**Fast check**: `rbgp evpn es list <esi>` for the daemon's joined
view, `bridge -d link show dev <ac-port>` for the kernel `state`
field, and the `evpn_es_ac_gate{esi, state}` gauge on the Prometheus
endpoint (`blocked` / `forwarding` / `mixed-roles`; the state with
value 1 is current).

**The AC is not blocked but the PE is non-DF**:

1. **No binding** — only segments with
   `[[ethernet_segments]].interface` can be gated (the binding is
   the port handle). Unbound single-active segments fall back to
   BUM-flood-only enforcement; bind the AC to get full enforcement.
2. **Mixed roles** — `evpn_es_ac_gate{state="mixed-roles"} == 1`
   means RFC 8584 service carving elected this PE DF for some member
   VNIs and non-DF for others. The gate is per *port*, not per VLAN,
   so blocking would break the DF VNIs; the port stays forwarding
   and only the per-VNI BUM flood flags enforce. The daemon logs a
   structured warning when entering this state. Single-VNI ESes
   never hit it.
3. **`apply_bum_enforcement = false`** — observe-only posture; no
   port mutation at all.
4. **Binding doesn't resolve** — the bound name must currently be a
   bridge port (enslaved to a bridge). The daemon warns
   `bound interface is not a bridge port` when it cannot resolve the
   handle.
5. **Kernel STP owns the port state** — `listening`, `learning`, and
   `blocking` are STP-owned bridge-port states. rustbgpd will warn and
   leave the port untouched rather than force it to `disabled` or
   `forwarding`; disable STP on the bound AC before relying on the
   single-active gate.
6. **Kernel carrier reset window** — the kernel itself re-enables a
   disabled port when carrier returns (`br_port_carrier_check`), so
   immediately after a carrier flap the port can briefly read
   `forwarding` until the next reconcile pass re-blocks it (kernel
   event wake or the periodic dump, ≤ 60 s).

**The AC is blocked and you didn't expect it**:

1. **Drained ES** — any drain reason (operator or link, including
   the post-carrier-return recovery hold-off) blocks the AC; that is
   the maintenance semantic. Check
   `evpn_es_drained{esi, reason}` / `rbgp evpn es list <esi>`.
2. **This PE lost DF election** for every member VNI — check
   `evpn_df_role{esi, vni, role}`.
3. A crash-stopped daemon can leave the port disabled (clean
   shutdown restores forwarding; a kill cannot). The next daemon
   start re-evaluates and re-opens it if this PE is DF, and a
   carrier flap re-enables it kernel-side regardless.

**Do not run kernel STP on a bound AC** — STP and the gate write the
same per-port state. rustbgpd now guards this by warning and skipping
the gate while the kernel reports an STP-owned state, which prevents
the daemon from fighting STP but also means whole-port single-active
blocking is not enforced until STP is disabled or releases the port.

## IP-VRF stuck in `NotReady`

Gate 9 slice 6 surfaces per-VRF readiness via gRPC
(`EvpnService.GetIpVrf` / `ListIpVrfs`) and the CLI
(`rbgp evpn vrfs [NAME]`). The probe checks the seven
ADR-0058 §3 predicates; `NotReady { reasons }` reports every
failing predicate at once.

**Symptom**: an `[[evpn_ip_vrfs]]` entry never originates Type 5
or installs remote prefixes.

**Triage**:

1. `rbgp evpn vrfs <name>` and read the `not_ready_reasons`
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
   advertising Type 5: first check the **projection layer** via
   `evpn_ip_vrf_remote_prefix_drops{vrf="<name>",reason=...}` in
   Prometheus. `overlay_index_no_linked_l2vni` means the non-zero
   Gateway Address route matched the IP-VRF but no L2VNI is linked
   through `[[evpn_instances]].ip_vrf`; `unresolved_overlay_index_gateway`
   means no eligible Type 2 MAC/IP route resolved the Gateway Address;
   `ambiguous_overlay_index_gateway` means the Gateway Address resolved
   to multiple distinct MACs at the winning mobility sequence.
   `l3vni_mismatch`, `missing_router_mac`, `no_matching_ip_vrf`, and
   `self_originated` cover the other fail-closed projection gates.
5. If `evpn_ip_vrf_remote_prefix_drops` is empty/zero but
   `installed_routes_count == 0`, the route cleared projection and was
   dropped at **L3 install time** instead — that path has no Prometheus
   counter today. Confirm the IP-VRF is `Ready` (step 1; an unready VRF
   yields `L3Drop::NotReady`), then read the daemon's `L3 install drop`
   debug logs for `RouterMacConflict` (two prefixes mapping
   `(L3VXLAN ifindex, router_mac)` to different next-hops drop *both*) or
   `FamilyMismatch` (`L3Drop` in `crates/evpn-linux/src/l3_diff.rs`).

## Crash-restart adoption across upgrades (ADR-0082)

rustbgpd stamps every EVPN FDB/neighbor install with
`NDA_PROTOCOL = RTPROT_BGP` (since v0.38.0), so managed L3 neighbor
rows show `proto bgp` in `ip neigh show` alongside `extern_learn`,
and the crash-restart adoption sweep (ADR-0079) refuses rows stamped
by another controller (e.g. zebra's `proto zebra`).

L3 neighbor adoption *requires* the stamp: the stamp-or-legacy
migration window (v0.38.0) is closed, and a stamp-less
`extern_learn` + permanent row — the shape a pre-stamp rustbgpd left
behind — is not adopted (it is preserved untouched, like any other
foreign row, but it will not be reaped when its route is withdrawn).
The upgrade gate that follows: upgrading from v0.37.0 or earlier,
run a version in the v0.38.0–v0.45.0 range at least once first — its
converge re-writes every owned row with the stamp — before moving
on. Foreign stamps are always refused.

The `RUSTBGPD_EVPN_ADOPTION_ACCEPT_LEGACY=1` escape hatch that
restored stamp-or-legacy acceptance for a skip-version upgrade's
first boot was **removed in v0.50.0**: the daemon now refuses
to start if the variable is set (to any value), so stale automation
fails loudly instead of silently changing adoption behavior. If you
still have pre-stamp kernel rows, step through a v0.38.0–v0.45.0
release once (or clear the stale rows by hand) before upgrading.

FDB rows are unaffected either way: mainline kernels don't store the
attribute for AF_BRIDGE entries, so FDB adoption stays flag-based
(with the stamp honored in prefer mode) until kernel support lands.
