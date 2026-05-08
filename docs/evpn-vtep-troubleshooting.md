# EVPN VTEP troubleshooting runbook

This runbook is for the bidirectional EVPN VTEP alpha path:

- Gate 7b: received Type 2 routes program Linux bridge/VXLAN FDB
  entries.
- Gate 7b+1: kernel-learned local MACs originate EVPN Type 2 routes,
  and one Type 3 IMET is originated per configured L2VNI.

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

The alpha path does not quarantine duplicate MACs yet. It does expose
detection:

```bash
curl -s http://127.0.0.1:9179/metrics \
  | grep -E 'evpn_duplicate_mac_(moves_total|first_move_timestamp_seconds)'
```

Repeated increments for the same `(vni, mac)` indicate cross-VTEP
contention and should be investigated as a loop, spoof, or host mobility
event. The timestamp metric records the first observed contention for
that key so a later RFC 7432 M/N quarantine window can be implemented
without changing metric shape. One-off increments can be normal during
planned host moves.

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
