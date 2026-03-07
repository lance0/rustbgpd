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

The daemon validates the config file at startup. Any validation error prints
a message to stderr and exits with code 1 — the daemon never starts with an
invalid config.

On success, structured JSON logs go to stdout. The daemon is ready when you
see the `starting rustbgpd` log line with version, ASN, and router ID.

---

## Configuration reload (SIGHUP)

```bash
sudo systemctl reload rustbgpd
# or: kill -HUP $(pidof rustbgpd)
```

What happens:

1. The daemon re-reads the TOML config file from disk.
2. `diff_neighbors()` computes per-peer add/remove/change deltas.
3. New peers are added, removed peers get NOTIFICATION and teardown, changed
   peers are removed and re-added.
4. Global section changes (`[global]`, `[rpki]`, `[bmp]`, `[mrt]`) are logged
   as warnings and **require a full restart** to take effect.

Reload failures are logged per-peer. If reconciliation fails, the daemon
keeps the previous in-memory config and continues running.

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

All metrics are exposed on the Prometheus endpoint configured in
`prometheus_addr`.

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
