# rustbgpd-mrt

MRT dump export implementing RFC 6396 TABLE_DUMP_V2.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Features

- **TABLE_DUMP_V2** (type 13) — PEER_INDEX_TABLE, RIB_IPV4_UNICAST,
  RIB_IPV6_UNICAST, plus Add-Path subtypes (RFC 8050)
- **Periodic + on-demand** — configurable dump interval or gRPC
  `TriggerMrtDump` for immediate snapshots
- **Optional gzip** compression via flate2
- **Atomic writes** — temp file + rename to prevent partial dumps
- **NH synthesis** — IPv4 routes get NEXT_HOP attribute, IPv6 get
  MP_REACH_NLRI, RFC 8950 IPv4-with-IPv6-NH get MP_REACH_NLRI

## License

MIT OR Apache-2.0
