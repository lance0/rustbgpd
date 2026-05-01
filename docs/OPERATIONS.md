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
  `[rpki]`, `[bmp]`, `[mrt]`, `[[evpn_instances]]`, and inline
  `policy.import` / `policy.export` legacy statements. Surfaced with
  a one-line migration hint where applicable.
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
startup; reload-time mutation lands with kernel reconciliation), and
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

### Graceful shutdown

```bash
rustbgpctl shutdown
```

Sends NOTIFICATION to all peers, writes GR marker, exits cleanly.

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

### EVPN Route Reflector (Phase 1)

rustbgpd's Phase 1 EVPN role is **Route Reflector only** — it reflects
RFC 7432 routes between iBGP-speaking VTEPs but does not own any local
EVI / VRF / VNI state, does not learn MACs from a kernel FDB, and does
not run DF election. VTEPs (typically FRR on SONiC, or commercial NOS)
handle local origination and forwarding; rustbgpd handles fan-out and
attribute integrity in the middle.

> **Phase-2 update (Gate 7a, ADR-0052):** the **declarative** half of
> VTEP mode has shipped. Operators can configure local
> `[[evpn_instances]]` (vni / rd / route_targets / local_vtep_ip /
> optional bridge / advertise_svi_mac) and inspect the resolved table
> via `EvpnService.ListEvpnInstances` and `rustbgpctl evpn instances`.
> The kernel-reconciliation half — local MAC learning, Type 2/3
> origination, MAC mobility, DF execution — remains queued as Gate 7b.
> See `examples/evpn-vtep-leaf/` for the leaf-mode config shape and
> [`evpn-enablement.md`](evpn-enablement.md) for the gate ladder.

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
```

`tunnel_type=8` in the output indicates the RFC 8365 VXLAN
encapsulation extended community is present.

#### Inject a route from a controller

```bash
rustbgpctl evpn add-mac-ip --rd 65000:100 \
  --mac 02:00:00:aa:bb:cc --ip 10.0.0.5 \
  --label 100 --next-hop 10.0.0.2 \
  --rt 65000:100

rustbgpctl evpn delete-mac-ip --rd 65000:100 \
  --mac 02:00:00:aa:bb:cc --ip 10.0.0.5
```

Phase 1 supports Type 2 (MAC/IP) and Type 3 (IMET) injection.
Type 5 IP-Prefix and Type 1/4 multi-homing origination are not
exposed via the injection RPCs in Phase 1 (the RR still reflects them
when a VTEP advertises them).

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
see [docs/evpn-enablement.md](evpn-enablement.md).
