# rustbgpd-transport

TCP connection management and BGP session runtime for rustbgpd.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Architecture

Single tokio task per peer. `tokio::select!` multiplexes TCP reads,
keepalive/hold/connect timers, inbound commands, and outbound route
updates. The transport layer intercepts UPDATEs (parse, validate, apply
policy) before forwarding to the RIB — the FSM sees only payloadless
events.

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
  --rejected` (`[policy.reject_retention]`); diagnostic state only,
  resets on session reset
- **Private AS removal** — strip/replace private ASNs before eBGP export
- **Route server transparency** — preserve original NEXT_HOP and skip
  local ASN prepend for route-server clients
- **BMP hooks** — raw PDU capture and event emission for Peer Up,
  Peer Down, and Route Monitoring
- **Extended messages** (RFC 8654) — dynamic buffer sizing up to 65535 bytes
- **Add-Path** (RFC 7911) — per-family path ID encode/decode
- **Extended next hop** (RFC 8950) — IPv4 NLRI over IPv6 next hop

## License

MIT OR Apache-2.0
