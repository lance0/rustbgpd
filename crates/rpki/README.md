# rustbgpd-rpki

RPKI origin validation and ASPA path verification for rustbgpd — VRP
table, ASPA table, RTR protocol client, and multi-cache management.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Features

- **VRP table** with a family-split, prefix-length-bucketed index (one binary
  search per ancestor length over masked networks) for ~constant-time RFC 6811
  origin validation; `Arc<VrpTable>` snapshot pattern for lock-free reads
- **RTR client** (RFC 8210 / draft-ietf-sidrops-8210bis) — prefers RTR
  protocol v2 for ASPA, falls back to v1 on server rejection; persistent TCP
  sessions, Serial Query / Reset Query, Serial Notify handling,
  expire_interval enforcement
- **ASPA path verification** — ASPA table + AS_PATH verification per
  draft-ietf-sidrops-aspa-verification (§6.2), fed over RTR v2
- **Multi-cache merge** — `VrpManager` combines VRPs from multiple cache
  servers into a single authoritative table
- **Best-path integration** — Valid > NotFound > Invalid at step 0.5
  (between stale demotion and LOCAL_PREF)
- **Policy matching** — `match_rpki_validation` in policy statements

## Key types

- **`VrpEntry`** — prefix, max_length, origin ASN
- **`VrpTable`** — prefix-length-indexed VRP store with `validate(prefix, origin_asn)` lookup
- **`AspaTable`** / **`AspaRecord`** — ASPA lookup table and a single ASPA record (customer → providers)
- **`RtrClient`** — async per-cache RTR session
- **`VrpManager`** — multi-cache merge and distribution to RIB

## License

MIT OR Apache-2.0
