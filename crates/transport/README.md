# rustbgpd-transport

TCP connection management and BGP session runtime for rustbgpd.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Architecture

Two tokio tasks per peer (ADR-0051): a session task, and a dedicated
outbound writer task that owns the TCP write half plus a bounded bulk /
unbounded priority queue, so TCP back-pressure cannot park the session
loop. The session task's `tokio::select!` multiplexes TCP reads,
hold/connect-retry/reconnect timers, inbound commands, outbound route
updates from the RIB, and outbound-connect completion. The KEEPALIVE
cadence is owned by the writer task (ADR-0078), so it keeps running
while the session task is parked on a blocking RIB delivery.

The transport layer intercepts UPDATEs (parse, validate, apply policy)
before forwarding to the RIB — the FSM sees only payloadless events.

## Features

- **Inbound + outbound peering** — accepts incoming TCP and initiates
  outbound connections; passive mode supported
- **TCP MD5 signatures** (RFC 2385) and **GTSM** (RFC 5082) via raw
  socket options
- **TCP-AO** (RFC 5925) — ordered static-neighbor and direct dynamic-prefix
  keyrings are installed on active-open and accept sockets, with fail-closed
  inspection and `GlobalService.GetGlobal` / `rbgp global` capability status;
  SIGHUP can append nonpreferred successor keys, later observation-gate
  selection/deprecation, and later delete deprecated MKTs that are neither
  Current nor RNext; key edits/reordering and protected-owner changes remain
  restart-required
- **Import/export policy** — policy chains evaluated inline during
  UPDATE processing
- **Import-decision explain** (ADR-0073) — a bounded per-session LRU
  cache of import-policy decisions (permit and deny) backing
  `PolicyService.ExplainImportPolicy` / `rbgp policy explain`;
  diagnostic state only, resets on session reset / restart. **Opt-in:**
  `TransportConfig::explain_enabled` defaults to `false` (daemon knob
  `[policy.explain] enabled`), because the cache is per session and its
  cost multiplies by session count. Embedders that want the surface set
  the field explicitly after `TransportConfig::new`.
- **Rejected-route retention** — a bounded per-session store of
  import-rejected routes with canonical reject reasons, backing
  `PolicyService.ListRejectedRoutes` / `rbgp rib received <peer>
  --rejected` (`[policy.reject_retention]`). **On by default:**
  `TransportConfig::reject_retention_enabled` defaults to `true`, unlike the
  opt-in import-explain cache above. The `ListRejectedRoutes` reply reports
  `enabled`, `capacity`, and `evictions_since_reset`; `enabled = false` makes
  an empty result a configuration fact, zero evictions proves no retained
  rejection was displaced by capacity since the session reset, and a nonzero
  count means the bounded listing may be incomplete. Entries and the eviction
  count are diagnostic state and reset with the session.
- **Private AS removal** — strip/replace private ASNs before eBGP export
- **Route server transparency** — preserve original NEXT_HOP and skip
  local ASN prepend for route-server clients
- **BMP hooks** — raw PDU capture and event emission for Peer Up,
  Peer Down, and Route Monitoring
- **Extended messages** (RFC 8654) — dynamic buffer sizing up to 65535 bytes
- **Add-Path** (RFC 7911) — per-family path ID encode/decode
- **Extended next hop** (RFC 8950) — IPv4 NLRI over IPv6 next hop
- **Graceful Restart + LLGR** (RFC 4724, RFC 9494) — stale-route retention
  across peer restart, with long-lived retention via `llgr_stale_time`
- **BGP Roles + Only-to-Customer** (RFC 9234) — OPEN-time role-mismatch
  NOTIFICATION 2/11 plus the OTC ingress/egress leak gates
- **Outbound route filtering** (RFC 5291/5292) — inbound ORF ROUTE-REFRESH
  handling applied to the peer's Adj-RIB-Out
- **Enhanced route refresh** (RFC 7313) — BoRR/EoRR demarcation accounting
  per inbound refresh window
- **Slow-peer detection** — outbound-backlog episodes flagged via
  `slow_peer_threshold_pct` / `slow_peer_duration`, with opt-in isolation
  (`slow_peer_isolation`, default off — detection alone is observational)

## License

MIT OR Apache-2.0
