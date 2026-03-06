# rustbgpd-rpki

RPKI origin validation for rustbgpd — VRP table, RTR protocol client,
and multi-cache management.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Features

- **VRP table** with sorted-Vec binary search for prefix containment
  lookups; `Arc<VrpTable>` snapshot pattern for lock-free reads
- **RTR client** (RFC 8210 v1) — persistent TCP sessions, Serial Query /
  Reset Query, Serial Notify handling, expire_interval enforcement
- **Multi-cache merge** — `VrpManager` combines VRPs from multiple cache
  servers into a single authoritative table
- **Best-path integration** — Valid > NotFound > Invalid at step 0.5
  (between stale demotion and LOCAL_PREF)
- **Policy matching** — `match_rpki_validation` in policy statements

## Key types

- **`VrpEntry`** — prefix, max_length, origin ASN
- **`VrpTable`** — sorted VRP store with `validate(prefix, origin_asn)` lookup
- **`RtrClient`** — async per-cache RTR session
- **`VrpManager`** — multi-cache merge and distribution to RIB

## License

MIT OR Apache-2.0
