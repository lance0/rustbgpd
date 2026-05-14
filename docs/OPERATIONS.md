# Operations Guide

Practical reference for running rustbgpd in production. For config syntax,
see [CONFIGURATION.md](CONFIGURATION.md). For security posture, see
[SECURITY.md](SECURITY.md).

---

## Starting the daemon

```bash
rustbgpd /etc/rustbgpd/config.toml
```

Or via systemd (see `examples/systemd/rustbgpd.service`):

```bash
sudo systemctl start rustbgpd
```

The daemon validates the config file at startup. Validation errors display
rustc-style diagnostics showing the offending TOML line with column markers:

```
error: invalid hold_time 2: must be 0 or >= 3
  --> /etc/rustbgpd/config.toml:12:13
   |
12 | hold_time = 2
   |             ^ must be 0 or >= 3
```

The daemon exits with code 1 — it never starts with an invalid config.

On success, structured JSON logs go to stdout. The daemon is ready when you
see the `starting rustbgpd` log line with version, ASN, and router ID.

### Per-peer log filtering

Set `log_level` on any neighbor or peer group to override the global log level:

```toml
[[neighbors]]
address = "10.0.0.1"
remote_asn = 65001
log_level = "debug"
```

Or filter via `RUST_LOG` using the per-peer tracing span:

```bash
RUST_LOG=info,peer{peer_addr=10.0.0.1}=debug rustbgpd /etc/rustbgpd/config.toml
```

---

## Config validation

Validate a config file without starting the daemon:

```bash
rustbgpd --check /etc/rustbgpd/config.toml
```

Prints rustc-style diagnostics on error, or `config OK` on success.

## Config diff (dry-run reload)

Preview what a SIGHUP reload would change before sending it:

```bash
# Compare proposed config against current config
rustbgpd --diff /tmp/new-config.toml /etc/rustbgpd/config.toml

# JSON output for scripting
rustbgpd --diff /tmp/new-config.toml /etc/rustbgpd/config.toml --json
```

Output is grouped into two actionable sections plus a per-neighbor
effective-impact view:

- **Reload-applied changes** — `[[neighbors]]` deltas, neighbor sets,
  named policies, peer groups, and global / per-neighbor policy
  chains. SIGHUP reconciles all of these.
- **Restart-required changes** — `[global]` ASN/router-id/families,
  `[global.telemetry.grpc_*]` listener config (including TLS / mTLS),
  `[rpki]`, `[bmp]`, `[mrt]`, `[[evpn_instances]]`,
  `[[ethernet_segments]]`, `[[evpn_ip_vrfs]]`,
  `apply_bum_enforcement`, and inline `policy.import` /
  `policy.export` legacy statements. Surfaced with a one-line
  migration hint where applicable.
- **Effectively impacted neighbors (via inheritance)** — every
  neighbor whose resolved import / export chain would move at reload,
  with the upstream change(s) responsible (peer-group / policy /
  neighbor-set / global chain). Catches transitive references: a
  policy definition edit picked up via the global `import_chain`
  (chain list itself unchanged) or via a peer-group's chain
  (peer-group record unchanged) still flags every affected member.

Exit codes: 0 = no actionable changes, 1 = actionable changes found,
2 = error (bad config, missing file).

## Configuration reload (SIGHUP)

```bash
sudo systemctl reload rustbgpd
# or: kill -HUP $(pidof rustbgpd)
```

What happens (in dependency order):

1. The daemon re-reads the TOML config file from disk and diffs it
   against the running snapshot, bucket by bucket.
2. **Definitions land first** — neighbor sets, named policies, peer
   groups, and global import / export chains. Each bucket fires a
   single-shot command at the peer manager that goes through the same
   `apply_policy_change` / `apply_peer_group_change` paths the gRPC API
   uses; effect matches a sequence of `SetPolicy` / `SetPeerGroup` /
   `SetGlobalImportChain` mutations. Hot-applied policy chains land at
   every affected peer's session task without tearing the BGP session.
3. **`[[neighbors]]` reconcile** — `diff_neighbors()` computes per-peer
   add/remove/change deltas; `ReconcilePeers` applies them.
4. **Deletes of obsolete definitions** in reverse-dependency order so
   transient `still referenced` rejections don't fire.
5. **Automatic Route Refresh on import-policy hot-apply** — when a
   peer's effective import chain changes (whether triggered by a
   SIGHUP reload or a gRPC mutation), the peer manager issues
   `soft_reset_in` (gated on Established) so routes already in
   `AdjRibIn` get re-evaluated against the new policy. Operators no
   longer need to run `softreset` manually after a chain swap.

Reload halts at the first step failure and returns a partial-state
snapshot, so the daemon's in-memory config tracks what actually
landed at the peer manager. Operator fixes the failing TOML and
reloads again to converge against the half-applied state. Per-step
errors are logged with structured `bucket` / `target` / `error`
fields.

**Restart-required surfaces** (logged at reload, surfaced under
"Restart-required" in `--diff`): `[global]` ASN/router-id/families,
`[global.telemetry.grpc_tcp]` and `[global.telemetry.grpc_uds]`
listener config (including any TLS / mTLS field), `[rpki]`, `[bmp]`,
`[mrt]`, `[[evpn_instances]]` (Phase-2 VTEP foundation — gRPC
`EvpnService` shares an `Arc<EvpnInstanceTable>` built once at
startup; reload-time mutation lands with kernel reconciliation),
`[[ethernet_segments]]` (Gate 8 segment orchestrator snapshot),
`[[evpn_ip_vrfs]]` (Gate 9 IP-VRF foundation — pinned
`Arc<IpVrfTable>` consumed by the readiness probe),
`apply_bum_enforcement` (Gate 8b dataplane actor startup flag), and
inline `policy.import` / `policy.export` legacy global-fallback
statements.

Use `rustbgpd --diff` to preview changes before reloading; the diff
buckets the changes by Reload-applied / Restart-required and surfaces
a per-neighbor "effective impact" view for transitive references
(policy edit picked up via global `import_chain`, peer-group's
chain, etc.).

---

## What state persists

| State | Where | When |
|-------|-------|------|
| Neighbor add/delete via gRPC | Config file (atomic write) | Immediately on mutation |
| GR restart marker | `<runtime_state_dir>/gr-restart.toml` | On coordinated shutdown |
| MRT dump files | `[mrt] output_dir` | On periodic timer or `TriggerMrtDump` |
| gRPC UDS socket | `<runtime_state_dir>/grpc.sock` | Daemon lifetime |

**Not persisted:** routing state (Adj-RIB-In, Loc-RIB, Adj-RIB-Out), policy
evaluation state, RPKI VRP tables, BMP client state. All routing state is
rebuilt from peers after restart.

---

## Upgrading

1. Build the new version: `cargo build --release`
2. Stop the daemon: `systemctl stop rustbgpd` (or `rustbgpctl shutdown`)
3. Replace the binary at `/usr/local/bin/rustbgpd`
4. Start: `systemctl start rustbgpd`

When Graceful Restart is enabled (the default), the coordinated shutdown in
step 2 writes a GR restart marker. On step 4, the daemon advertises `R=1` to
static peers, asking them to retain our routes while we reconnect. The restart
window is the largest `gr_restart_time` among all GR-enabled peers.
rustbgpd still advertises `forwarding_preserved = false`; use a drained
route-server pair or another traffic-shift procedure when forwarding
continuity matters.

For zero-downtime upgrades in a route-server pair, drain traffic to the
standby, upgrade, then swap.

---

## Failure modes

### gRPC server dies unexpectedly

The daemon treats an unexpected gRPC server exit as fatal and initiates a
coordinated shutdown (NOTIFICATION to all peers, GR marker write). This is
deliberate: losing the control plane means losing the ability to shut down
cleanly later. See [ADR-0022](adr/0022-grpc-server-supervision.md).

### RPKI cache unreachable

Each RTR client reconnects independently after a fixed `retry_interval`
(default 600s). If no fresh `EndOfData` arrives before
`expire_interval` (default 7200s), cached VRPs for that server are discarded.
Routes are re-validated against the remaining VRP table.

When all caches are down, the VRP table is empty and all routes have
validation state `NotFound`. If your policy denies `NotFound` routes, this
will cause route drops. The recommended policy is to deny `Invalid` and
prefer `Valid`, leaving `NotFound` as a neutral fallback.

### BMP collector unreachable

Each BMP client reconnects independently with backoff (default
`reconnect_interval` = 30s). During disconnection, BMP events for that
collector are dropped. No routing state is affected — BMP is purely
observational. On reconnect, the client sends a fresh Initiation message;
the collector rebuilds state from subsequent Peer Up and Route Monitoring
messages.

### MRT dump failure

If the output directory is not writable, the MRT manager logs an error and
skips that dump cycle. Periodic dumps continue on the next interval. The
daemon does not crash on MRT failures.

### Peer max-prefix exceeded

When a peer sends more prefixes than `max_prefixes`, the daemon sends a
NOTIFICATION (Cease / Maximum Number of Prefixes Reached) and tears down the
session. The peer is not automatically re-enabled — use
`rustbgpctl neighbor <addr> enable` or the gRPC `EnableNeighbor` RPC to
restart it.

---

## Key metrics to watch

Metrics are exposed on the Prometheus endpoint if `prometheus_addr` is
configured. If omitted, metrics are still collected internally and available
via gRPC `GetMetrics` and `GetHealth` RPCs.

### Health

| Metric | What it tells you |
|--------|-------------------|
| `bgp_peers_established` | Number of peers in Established state |
| `bgp_peers_configured` | Total configured peers |
| `bgp_uptime_seconds` | Daemon uptime |

### Routing

| Metric | What it tells you |
|--------|-------------------|
| `bgp_rib_prefixes{table="loc_rib"}` | Loc-RIB size (best paths) |
| `bgp_rib_prefixes{table="adj_rib_in"}` | Total received prefixes |
| `bgp_rib_prefixes{table="adj_rib_out"}` | Total advertised prefixes |
| `bgp_updates_received_total` | Inbound UPDATE count |
| `bgp_updates_sent_total` | Outbound UPDATE count |

### General Unicast FIB

These metrics are present when the daemon is built with the ADR-0061 general
FIB runtime. The actor is still default-off; configure at least one
`[[fib_tables]]` block to start it.

| Metric | What it tells you |
|--------|-------------------|
| `bgp_fib_routes_installed_total` | Configured-table routes successfully installed or replaced in the Linux kernel |
| `bgp_fib_routes_withdrawn_total` | Daemon-owned configured-table routes successfully removed from the kernel |
| `bgp_fib_routes_rejected_total{reason="foreign_route_exists"}` | Desired route suppressed because a kernel row already exists at the same table / metric / prefix and is not daemon-owned |
| `bgp_fib_routes_rejected_total{reason="next_hop_family_unsupported"}` | Desired route suppressed because the table family and BGP next-hop family do not match |
| `bgp_fib_routes_rejected_total{reason="peer_not_allowed"}` | Desired route suppressed by a `[[fib_tables]]` peer / peer-group allow-list |
| `bgp_fib_routes_rejected_total{reason="route_limit_exceeded"}` | Desired route suppressed because the table exceeded its `max_routes` hard cap; existing owned rows are frozen in place |
| `bgp_fib_kernel_failures_total{action="setup"}` | Runtime could not open the Linux FIB programming surface at startup |
| `bgp_fib_kernel_failures_total{action="dump"}` | Runtime could not dump configured route tables during a reconcile pass |
| `bgp_fib_kernel_failures_total{action="install"}` | Kernel rejected an add operation |
| `bgp_fib_kernel_failures_total{action="replace"}` | Kernel rejected a replace operation |
| `bgp_fib_kernel_failures_total{action="remove"}` | Kernel rejected a remove operation |
| `bgp_fib_kernel_failures_total{action="unsupported_platform"}` | Config requested FIB programming on a non-Linux build |

Use `rustbgpctl rib fib --json` as the per-route companion to these counters.
The most important state to investigate is `foreign_route_exists`: rustbgpd
will not overwrite or delete pre-existing `RTPROT_BGP` rows because protocol
alone is not ownership proof.

### Graceful Restart

| Metric | What it tells you |
|--------|-------------------|
| `bgp_gr_active_peers` | Peers currently in GR stale-route state |
| `bgp_gr_stale_routes` | Routes currently marked stale |
| `bgp_gr_timer_expired_total` | GR timers that expired (routes swept) |

### RPKI

| Metric | What it tells you |
|--------|-------------------|
| `bgp_rpki_vrp_count{af="ipv4"}` | IPv4 VRP entries loaded |
| `bgp_rpki_vrp_count{af="ipv6"}` | IPv6 VRP entries loaded |

A sudden drop in VRP count likely means a cache connection was lost or the
cache itself has stale data.

### EVPN VTEP alpha

| Metric | What it tells you |
|--------|-------------------|
| `evpn_local_originations_total{action="inject"}` | Locally learned MACs that the originator successfully handed to the RIB as Type 2 advertisements |
| `evpn_local_originations_total{action="withdraw"}` | Locally aged / deleted MACs that the originator successfully handed to the RIB as Type 2 withdraws |
| `evpn_local_origination_errors_total{action="inject"}` | Failed local Type 2 inject attempts: RIB channel closed, RIB rejected the inject, or the reply was dropped |
| `evpn_local_origination_errors_total{action="withdraw"}` | Failed local Type 2 withdraw attempts: RIB channel closed, RIB rejected the withdraw, or the reply was dropped |
| `evpn_local_observations_dropped_total{reason="channel_full"}` | Kernel local-MAC observations classified by the netlink notify loop but dropped because the originator channel was full |
| `evpn_local_observations_dropped_total{reason="channel_closed"}` | Kernel local-MAC observations classified by the netlink notify loop after the originator receiver was gone |
| `evpn_duplicate_mac_moves_total{vni,mac}` | Cross-VTEP MAC mobility contention events detected by the local originator; detection only, no quarantine action yet |
| `evpn_duplicate_mac_first_move_timestamp_seconds{vni,mac}` | Unix timestamp of the first observed duplicate-MAC / mobility contention event for that key |

During M37 or a synthetic MAC-churn soak, the inject and withdraw counters
should follow the `bridge fdb add` / `bridge fdb del` cadence. Any non-zero
observation-drop counter means the kernel event reached the notify loop but
not the originator; any non-zero origination-error counter means the
observation reached the originator but did not complete at the RIB boundary.
`evpn_duplicate_mac_moves_total` and
`evpn_duplicate_mac_first_move_timestamp_seconds` are intentionally per
`(VNI, MAC)`; alert on repeated increments within a short window rather
than on one-off mobility during planned host moves.
`rustbgpctl evpn instances` also reports `originated-local-macs=N` per
instance, and `rustbgpctl evpn instances --json` exposes the same value as
`originated_local_macs_count`.

---

## Key log messages

rustbgpd uses structured JSON logging. Key messages to watch for:

| Message | Level | Meaning |
|---------|-------|---------|
| `starting rustbgpd` | INFO | Daemon started successfully |
| `peer session established` | INFO | BGP session reached Established |
| `peer session down` | INFO | BGP session left Established |
| `received shutdown signal` | INFO | SIGTERM/SIGINT received |
| `shutdown initiated via gRPC` | INFO | `Shutdown` RPC called |
| `gRPC server exited unexpectedly` | ERROR | Fatal — coordinated shutdown follows |
| `config reloaded` | INFO | SIGHUP reload succeeded |
| `config reload failed` | ERROR | SIGHUP reload failed — previous config kept |
| `GR restart marker` | INFO | Restart marker written or read |
| `max-prefix limit exceeded` | WARN | Peer exceeded prefix limit |
| `gRPC TCP listener bound to a non-loopback address` | WARN | Security posture warning |

---

## Debugging a session that won't establish

1. **Check peer state:**
   ```bash
   rustbgpctl neighbor
   ```
   Look at the FSM state. `Active` means we're trying to connect but TCP
   isn't establishing. `OpenSent`/`OpenConfirm` means OPEN exchange is
   failing.

2. **Check logs for the peer:**
   ```bash
   journalctl -u rustbgpd | grep "10.0.0.2"
   ```
   Look for NOTIFICATION codes, capability mismatches, or hold timer expiry.

3. **Common causes:**
   - **TCP not reaching:** Firewall, wrong address, peer not listening on 179
   - **ASN mismatch:** Remote peer has a different `remote-as` configured for us
   - **Router ID collision:** Two speakers with the same router ID
   - **Hold timer zero vs non-zero:** One side sends hold_time=0, the other expects keepalives
   - **Capability mismatch:** Check address family negotiation in OPEN logs
   - **MD5 mismatch:** TCP RST with no BGP-level error; check both sides' passwords
   - **TTL security:** GTSM requires TTL=255; multi-hop peers will fail

4. **Verify from the remote side:**
   Check FRR/BIRD/peer logs for their view of the session attempt.

---

## Common operational tasks

### Add a peer at runtime

```bash
rustbgpctl neighbor 10.0.0.5 add --asn 65005 --description "new-peer"
```

The peer is persisted to the config file automatically.

### Remove a peer

```bash
rustbgpctl neighbor 10.0.0.5 delete
```

Sends NOTIFICATION, tears down the session, removes from config.

### Soft reset (re-evaluate import policy)

```bash
rustbgpctl neighbor 10.0.0.2 softreset
```

Re-applies import policy to all routes from this peer without tearing down
the session.

> Note: as of v0.12.0, `update_runtime_policies` automatically issues a
> Route Refresh whenever a peer's effective import chain materially
> changes (via SIGHUP reload, gRPC `SetPolicy`, `SetPeerGroup`, or
> chain mutations). Operators only need this command after manual
> ad-hoc edits or to recover from a session-mid-restart at the time
> of the original reload. The `pending_refresh` retry semantics on
> `ManagedPeer` cover most of those edge cases automatically.

### Enable / disable a peer

```bash
rustbgpctl neighbor 10.0.0.2 enable
rustbgpctl neighbor 10.0.0.2 disable --reason "maintenance"
```

### Trigger an MRT dump

```bash
rustbgpctl mrt-dump
```

### Live dashboard

```bash
rustbgpctl top          # default 2s poll
rustbgpctl top -i 5     # 5s poll interval
```

Shows sessions, prefix counts, message rates, RPKI VRP counts, and
streaming route events in a terminal UI. Press `h` for keybindings.

### Check health

```bash
rustbgpctl health
```

### View received routes from a peer

```bash
rustbgpctl rib received 10.0.0.2
```

### View best routes (Loc-RIB)

```bash
rustbgpctl rib
```

### View general FIB route status

```bash
rustbgpctl rib fib
rustbgpctl -j rib fib
```

This reports only the ADR-0061 configured-table runtime, not the ordinary
Loc-RIB. Rows are `installed`, `rejected`, or `failed`.

- `installed` / `owned`: rustbgpd owns the row and the kernel table matches
  the current best route.
- `rejected` / `foreign_route_exists`: a kernel row already exists at the
  same table / metric / prefix but is not owned by this daemon instance.
  This includes pre-existing `RTPROT_BGP` rows after crash restart; rustbgpd
  preserves them rather than taking ownership by protocol alone.
- `rejected` / `next_hop_family_unsupported`: the configured table family and
  BGP next-hop family do not match.
- `rejected` / `peer_not_allowed`: the route's source peer did not match the
  table's `allowed_neighbors` or `allowed_peer_groups` guardrail.
- `rejected` / `route_limit_exceeded`: the table's eligible route count
  exceeded `max_routes`. The table freezes for that pass: existing owned
  rows stay installed, and growth or replacement is suppressed until the
  eligible count falls back under the cap. For very large over-cap tables,
  rejected rows are sampled so status output stays bounded.
- `failed` / `dump_failed:*`, `install_failed:*`, `replace_failed:*`, or
  `remove_failed:*`: the runtime hit a RIB or kernel boundary error. Check
  `bgp_fib_kernel_failures_total` and daemon logs for the matching action.

For direct kernel inspection, use the configured table and metric:

```bash
ip route show table 1000
ip -6 route show table 1000
```

On coordinated shutdown, the daemon drains only rows still matching its
owned next-hop. If a row drifted underneath the daemon, it is preserved and
ownership is dropped.

**Quick smoke check** — one-shot verification that the runtime is live and
programming the kernel (substitute the configured `table_id`):

```bash
rustbgpctl rib fib                                  # per-route owned / rejected / failed state
ip route show table 1000                            # the configured table, straight from the kernel
curl -s localhost:9179/metrics | grep '^bgp_fib_'   # install / withdraw / reject / kernel-failure counters
```

### Explain a best-path decision

```bash
# Global Loc-RIB view: best route + every losing candidate annotated with
# the decisive comparison reason.
rustbgpctl rib --prefix 203.0.113.0/24 --explain

# Peer-scoped view: same shape, but every candidate the named peer would
# actually receive gets a non-zero `advertised_path_id` (rank within the
# peer's effective Add-Path send_max). Filtered candidates (export policy
# reject, family mismatch, split-horizon, iBGP / RFC 4456 RR suppression,
# beyond send_max) stay at 0 so the operator can see *why* each isn't
# advertised.
rustbgpctl rib --prefix 203.0.113.0/24 --explain --explain-peer 10.0.0.2
```

### Manage policies, peer groups, and neighbor sets

```bash
# Read
rustbgpctl policy list
rustbgpctl policy get import-from-transit
rustbgpctl neighbor-set list
rustbgpctl peer-group list

# Write — JSON file matches the proto message shape
rustbgpctl policy set import-from-transit --from-file policy.json
rustbgpctl neighbor-set set transit-peers --from-file ns.json
rustbgpctl peer-group set transit --from-file pg.json

# Apply chains globally or per-neighbor
rustbgpctl policy chain set-import import-from-transit
rustbgpctl policy chain set-import import-from-transit --neighbor 10.0.0.2
rustbgpctl policy chain show --neighbor 10.0.0.2

# Bind / unbind neighbors to a peer-group
rustbgpctl peer-group attach 10.0.0.5 --group transit
rustbgpctl peer-group detach 10.0.0.5
```

`--from-file` accepts JSON whose shape mirrors the proto message
(`PolicyDefinition` / `NeighborSetDefinition` / `PeerGroupDefinition`);
unknown fields are rejected at parse time. Empty
`chain set-{import,export}` is rejected — use the matching `clear-*`
subcommand to drop a chain.

### Graceful shutdown (daemon exit)

```bash
rustbgpctl shutdown
```

Sends NOTIFICATION to all peers, writes GR marker, exits cleanly.

### RFC 8326 graceful-shutdown community (planned maintenance)

Distinct from the daemon-shutdown RPC above. RFC 8326 lets you drain
traffic ahead of a planned EBGP session shutdown by tagging outbound
paths with the well-known `GRACEFUL_SHUTDOWN` community
(`65535:0` / `0xFFFF_0000`); receivers that honor the community
demote `LOCAL_PREF` to `0` so any non-shutting alternate becomes
preferred. By the time you actually close the session, traffic has
already moved.

**Initiator (the side going down for maintenance):**

```bash
# Start the drain on one peer
rustbgpctl gshut --peer 10.0.0.2

# Or drain every currently-managed peer at once
rustbgpctl gshut

# Wait for traffic to shift (operator-defined, typically 30s-5min
# depending on convergence in the upstream AS), then proceed with
# the actual maintenance — restart, config edit, etc.

# Clear the community when maintenance ends
rustbgpctl gshut --peer 10.0.0.2 --clear
rustbgpctl gshut --clear
```

The toggle is **operator-runtime state**, not config — it lives on
the `ManagedPeer` desired-state record, mirrors to the live session,
and survives session flaps mid-maintenance. The toggle does NOT
persist across daemon restart by design (RFC 8326 is a maintenance-
window action, not a steady state).

When the toggle flips, rustbgpd issues a `RibUpdate::RefreshPeerOutbound`
which forces re-emission of all routes already in `AdjRibOut` to the
target peer. The community appears on the wire immediately (no need
to wait for an unrelated RIB event).

**Receiver (the side honoring others' GShut):**

Set in `[global]`:

```toml
[global]
honor_graceful_shutdown = true
```

When enabled, an implicit chain-tail rule fires on every EBGP peer's
import chain — see `docs/CONFIGURATION.md` for the exact semantics.
iBGP peers are exempt because `LOCAL_PREF` is preserved within an AS.

**Verifying the drain is working:**

The community is attached on the wire by the per-peer transport layer
**after** the RIB-side advertised view is computed, so
`rustbgpctl rib advertised` does NOT show the GShut community on the
initiator side — the RIB doesn't know about the toggle. The
authoritative checks are:

```bash
# Receiver-side: routes from a draining peer that honor the community
# show explicit local_pref_attr = 0 in the RIB (proves the implicit
# chain-tail rule fired). EBGP-received routes have no LOCAL_PREF on
# the wire, so look at local_pref_attr (explicit) rather than
# local_pref (proto3 default).
rustbgpctl rib --neighbor <draining-peer> \
    | jq '.routes[] | {prefix, localPrefAttr, communities}'

# Initiator-side: confirm the toggle is set on the live session via
# the daemon log (look for "RFC 8326 graceful-shutdown advertise
# toggled" in journalctl / Docker logs).
journalctl -u rustbgpd | grep "graceful-shutdown advertise toggled"

# Or verify on the *receiving* peer's BGP table — the canonical
# observation. On FRR:
vtysh -c 'show ip bgp <prefix> json' \
    | jq '.paths[].community'

# (In a maintenance scenario you usually have control of both ends, so
# the receiver-side check is what matters for correctness.)
```

Interop is validated in M35 (`tests/interop/m35-graceful-shutdown-frr.clab.yml`)
against FRR 10.3.1 — both legs (FRR → rustbgpd inbound honor +
rustbgpd → FRR outbound advertise + clear) end-to-end.

### Explain best-path selection

```bash
rustbgpctl rib --prefix 10.0.0.0/24 --explain
```

Shows all candidates for a prefix with the decisive comparison reason
for each non-winner (e.g., `higher_local_pref`, `shorter_as_path`).

### Looking glass (birdwatcher-compatible REST API)

Optional HTTP server for external looking glass frontends (Alice-LG, etc.).
Configure in TOML:

```toml
[global.telemetry.looking_glass]
addr = "0.0.0.0:8080"
```

Endpoints: `/status`, `/protocols/bgp`, `/routes/protocol/{id}`,
`/routes/peer/{peer}`. Omit the section entirely to disable.

### EVPN Route Reflector + Bidirectional VTEP

rustbgpd has two operational EVPN modes that share the same `l2vpn_evpn`
session machinery:

- **RR mode (Phase 1):** empty `[[evpn_instances]]`. The daemon
  reflects RFC 7432 routes between iBGP-speaking VTEPs, owns no
  kernel state, and runs no DF election. External VTEPs (FRR on
  SONiC, commercial NOS) handle local origination + forwarding.
- **Bidirectional VTEP mode (Phase 2 — Gates 7a / 7b / 7b+1):**
  populated `[[evpn_instances]]`. The daemon **programs the kernel
  bridge FDB** from received Type 2 routes (downward, ADR-0054) AND
  **originates Type 2 from kernel-learned local MACs plus one Type 3
  IMET per configured L2VNI** (upward, ADR-0055). Linux-only. Gate
  7b+1 ships in v0.15.0.

> **Phase-2 status:** Gates 7a/7b/7b+1/7b+2/7c have shipped the
> bidirectional L2VNI VTEP loop: declarative instances, downward FDB
> reconciliation, local MAC and MAC+IP origination, Type 3 IMET,
> SVI MAC origination, sticky MAC config, and sub-second mobility
> wakeups. Gate 8/8b adds alpha multi-homing execution: DF election,
> Type 1/4 origination, opt-in BUM suppression, ESI-aware Type 2
> origination, aliasing projection, and receive-side mass-withdraw
> filtering. **Gate 9** ships symmetric Interface-less IRB
> end-to-end in v0.18.0 (RFC 9136 §4.4.2 / ADR-0058):
> `[[evpn_ip_vrfs]]` config schema + `[[evpn_instances]].ip_vrf`
> binding, `IpVrfStatus` readiness probe, Linux VRF / L3VXLAN
> netlink dumps, per-IP-VRF kernel-route observation with
> conservative classifier, Type 5 origination via
> `RibUpdate::InjectEvpn` gated on readiness, remote import + L3
> FIB programming through a transactional `L3OwnedState` model,
> `RTNLGRP_IPV4/IPV6_ROUTE` multicast for sub-second withdraw,
> `ListIpVrfs`/`GetIpVrf` gRPC + `rustbgpctl evpn vrfs` CLI,
> M39 manual containerlab smoke. **ADR-0059** (v0.19.0)
> adds receive-path aliasing-ECMP via FDB nexthop groups
> (slices 1-4, M40 FRR-validated); **slice 3.5 hardening**
> (PRs #91 / #92 / #93) added the `apply_aliasing_ecmp`
> per-instance off-switch, periodic `RTM_GETNEXTHOP` drift
> recovery, and homogeneous IPv6 alias members. Still ahead:
> MAC-churn variant of the Gate 8b 24h soak before flipping
> `apply_bum_enforcement` default to `true`; RFC 9135 overlay-
> index IRB; auto-derived RTs. See
> [`evpn-enablement.md`](evpn-enablement.md) for the gate ladder,
> [`evpn-alpha-soak.md`](evpn-alpha-soak.md) for the residual
> alpha-confidence checklist, and
> [`evpn-vtep-troubleshooting.md`](evpn-vtep-troubleshooting.md) for
> the operator runbook.

#### Per-neighbor knob

```toml
[[neighbors]]
address = "10.0.1.1"
remote_asn = 65000
families = ["l2vpn_evpn"]
route_reflector_client = true
```

Set `route_reflector_client = true` on every VTEP peer; the daemon's
own `cluster_id` (under `[global]`) drives the RFC 4456 ORIGINATOR_ID
+ CLUSTER_LIST stamping.

#### Inspect the EVPN RIB

```bash
rustbgpctl evpn                             # all EVPN routes
rustbgpctl evpn --route-type 2              # MAC/IP only
rustbgpctl evpn --rd 65000:100              # filter by RD
rustbgpctl evpn --peer 10.0.1.1             # filter by source peer
rustbgpctl evpn diagnose                    # alpha VTEP summary
```

`tunnel_type=8` in the output indicates the RFC 8365 VXLAN
encapsulation extended community is present.

#### Inspect the dataplane (ADR-0059 FDB nexthop groups)

```bash
rustbgpctl evpn nexthops                    # owned FDB-NHG groups / members / MAC refs
rustbgpctl evpn nexthops --json             # JSON for scripting
```

This is the rustbgpd-owned view of ADR-0059 aliasing-ECMP state —
distinct from the RIB above. Compare its `group-id`, member
`nh_id`s, and `mac-refs` against `ip nexthop show` / `bridge fdb
show` when debugging multi-homed Type 2 forwarding. The top-line
header reports `orphan-nexthops`, `pending-deletes`, and
`drift-recovery-disabled` so the periodic drift-recovery latch and
allocator GC backlog are visible without log scraping.

#### Inject a route from a controller

```bash
rustbgpctl evpn add-mac-ip --rd 65000:100 \
  --mac 02:00:00:aa:bb:cc --ip 10.0.0.5 \
  --label 100 --next-hop 10.0.0.2 \
  --rt 65000:100

rustbgpctl evpn delete-mac-ip --rd 65000:100 \
  --mac 02:00:00:aa:bb:cc --ip 10.0.0.5
```

Two complementary origination paths exist:

1. **gRPC injection (Phase 1, Gate 6):** `EvpnService.AddEvpnRoute` /
   `DeleteEvpnRoute` (the `rustbgpctl evpn add-mac-ip / add-imet /
   delete-*` commands above). The controller decides what to
   originate; rustbgpd reflects + distributes. Type 2 (MAC/IP) and
   Type 3 (IMET) are exposed; Type 5 IP-Prefix and Type 1/4
   multi-homing route injection are not exposed. Native Type 1/4
   origination is driven by `[[ethernet_segments]]`.
2. **Kernel-driven origination (Phase 2, Gate 7b+1):** with
   `[[evpn_instances]]` populated, the daemon subscribes to
   `RTNLGRP_NEIGH` (enum group id 3) and emits Type 2 routes for
   MACs the kernel learns on non-VXLAN bridge ports, plus one
   Type 3 IMET per L2VNI at startup. RFC 7432 §15.1 mobility
   sequencing is automatic. Withdraws fire on FDB age-out / `bridge
   fdb del` and on coordinated shutdown.

#### Common operational signals

- **EVPN routes counted toward `max_prefixes`.** A peer flooding EVPN
  Type 2 routes will trip the same Cease/MAX_PREFIXES that a peer
  flooding unicast prefixes would. The cap is the union of unicast
  unique prefixes + FlowSpec rules + EVPN keys.
- **GR / LLGR works for EVPN.** When a VTEP restarts, its reflected
  EVPN routes are marked stale and ranked below fresh alternatives
  (RFC 4724 §4.2 / RFC 9494 §4.7) — no fabric-wide flap.
- **Late-joining peer.** A VTEP that connects to a converged RR
  receives the existing EVPN routes in its initial dump before the
  EoR marker. (This was not always the case — see commit history for
  the regression test.)
- **MAC mobility correctness.** A MAC that moves between VTEPs
  produces a strictly-increasing MAC Mobility sequence number; the
  RR forwards the highest-sequence advertisement and downstream
  VTEPs flip their best path accordingly. Sticky MACs (RFC 7432
  §7.7) are not displaced by non-sticky ones.

For the full enablement story, gate ladder, and known limitations,
see [docs/evpn-enablement.md](evpn-enablement.md). For a step-by-step
operator checklist, see
[docs/evpn-vtep-troubleshooting.md](evpn-vtep-troubleshooting.md).

#### Troubleshooting kernel-driven origination (Gate 7b+1)

- **Local MAC learned in kernel, but Type 2 not on the wire.** Check
  in order: (a) `[[evpn_instances]]` is populated and the bridge
  named there exists with a single VXLAN port (probe reports
  `Ready` only when ADR-0054 §4's five-point check passes); (b) the
  MAC was learned on a **non-VXLAN** bridge port — the classifier
  intentionally drops VXLAN-port ifindexes (those are remote-MAC
  echoes); (c) `RUST_LOG=rustbgpd_evpn_linux=debug` shows the
  classifier hit (cache miss → `bridge_port_to_vni` doesn't yet
  contain the slave ifindex; the supervisor's periodic dump should
  populate it within 5 s); (d) the BGP session reached Established
  before the originator emitted the Inject — pre-Established
  Injects do reach the AdjRibOut and ride the initial dump, but a
  collision-replace dance can occasionally lose the window.
- **Type 3 IMET not visible on a peer.** IMET is emitted at startup
  for every configured `EvpnInstance` regardless of dataplane
  Ready/NotReady. If FRR's `show bgp l2vpn evpn route type
  multicast` doesn't show it, check that the peer reached
  Established and that the L2VPN/EVPN family was negotiated
  (`families = ["l2vpn_evpn"]`).
- **Type 2 / Type 3 not withdrawn cleanly on shutdown.** The
  shutdown order is: (1) drain originator's outstanding Withdraws;
  (2) withdraw IMET keys; (3) `PeerManagerCommand::Shutdown`. If
  peers see stale routes after a clean exit, check the structured
  log for the `draining EVPN originator` / `withdrawing EVPN Type 3
  IMET routes` lines firing **before** any peer-session-shutdown
  log lines.
- **`could not subscribe to RTNLGRP_NEIGH; local-MAC observations
  will be silent`** in the startup log. The daemon lacks
  `CAP_NET_ADMIN`. Downward FDB programming also needs the
  capability; if the dataplane reconciler is working but the
  originator is silent, the cap is partially granted (rare). Check
  `getcap` on the binary.
