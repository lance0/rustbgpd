# ADR-0044: MRT Dump Export (RFC 6396)

**Status:** Accepted
**Date:** 2026-03-05

## Context

MRT (Multi-Threaded Routing Toolkit) is the standard format for BGP RIB
snapshots and UPDATE archives. Route collectors (RIPE RIS, RouteViews) and
offline analysis tools consume MRT files. GoBGP supports MRT dump; rustbgpd
should too for operational parity.

RFC 6396 defines the MRT format. TABLE_DUMP_V2 (type 13) is the modern RIB
snapshot format, superseding the original TABLE_DUMP (type 12). RFC 8050
extends TABLE_DUMP_V2 with Add-Path subtypes (8/9) for path-ID-aware dumps.

The key challenge is that rustbgpd strips next-hop and MP_REACH_NLRI
attributes from routes per the MP-BGP architecture (ADR-0023). The MRT
codec must synthesize these attributes when encoding.

## Decision

### New crate: `crates/mrt/`

A new `rustbgpd-mrt` crate with four modules:

- **`codec.rs`** -- Pure encoding functions for TABLE_DUMP_V2 records.
  `PEER_INDEX_TABLE` (subtype 1), `RIB_IPV4_UNICAST` (2),
  `RIB_IPV6_UNICAST` (4), and Add-Path variants (8/9 per RFC 8050).
  `EncodeError` enum for explicit length-overflow handling -- no silent
  truncation.

- **`writer.rs`** -- Atomic file writer (temp + rename). Optional gzip
  via flate2. Collision-resistant filenames:
  `{prefix}.{YYYYMMDD.HHMMSS}.{nanos:09}.mrt[.gz]`.

- **`manager.rs`** -- `MrtManager` with `tokio::select!` over a periodic
  interval timer and a trigger channel for on-demand dumps. Queries the
  RIB via `QueryMrtSnapshot`, encodes via `spawn_blocking`, writes
  atomically.

- **`types.rs`** -- `MrtWriterConfig` and re-exports of `MrtPeerEntry`
  and `MrtSnapshotData` from the rib crate.

### Next-hop synthesis

`synthesize_attributes()` reconstructs stripped next-hop attributes:

- **IPv4 prefix, IPv4 next-hop:** `PathAttribute::NextHop(ipv4)` inserted
  in canonical position (after ORIGIN and AS_PATH).
- **IPv6 prefix:** `PathAttribute::MpReachNlri` with IPv6 next-hop, empty
  NLRI (prefix is in the RIB entry header per TABLE_DUMP_V2).
- **IPv4 prefix, IPv6 next-hop (RFC 8950):**
  `PathAttribute::MpReachNlri` with `Afi::Ipv4`, `Safi::Unicast`, and
  the IPv6 next-hop. No `NextHop` attribute is emitted.

### Snapshot source: Adj-RIB-In only

`QueryMrtSnapshot` collects routes from all per-peer Adj-RIB-In tables.
Loc-RIB is not overlaid, which avoids duplicate entries for the best-path
winner (who would appear in both Adj-RIB-In and Loc-RIB).

### Peer metadata tracking

`RibManager` gains `peer_asn: HashMap<IpAddr, u32>` and
`peer_bgp_id: HashMap<IpAddr, Ipv4Addr>`, populated on `PeerUp` and
cleared on `PeerDown`. These are **not** cleared during
`PeerGracefulRestart` or LLGR transitions, so dumps taken during a GR
window still include correct PEER_INDEX_TABLE entries.

Routes from peers not in the explicit metadata (e.g., injected routes
from the sentinel `0.0.0.0` peer) are included with a synthetic peer
entry (`bgp_id = 0.0.0.0`, `asn = 0`).

### Deterministic output

`encode_snapshot()` sorts peers by (address family, IP, ASN, BGP ID),
prefixes by (family, address, length), and routes within each prefix by
(peer index, path_id). This ensures byte-identical output for identical
RIB state.

### Integration points

- **gRPC:** `TriggerMrtDump` RPC on `ControlService`. Returns the file
  path of the produced dump. `FAILED_PRECONDITION` when MRT is not
  configured.
- **CLI:** `rustbgpctl mrt-dump` subcommand.
- **Config:** `[mrt]` TOML section with `output_dir`, `dump_interval`
  (default 7200), `compress` (default false), `file_prefix` (default
  "rib").
- **SIGHUP:** MRT config changes logged as warning, require restart
  (same as other global config).

### What is not included

- **TABLE_DUMP (type 12)** -- legacy format, not implemented.
- **BGP4MP (type 16/17)** -- UPDATE stream recording. Deferred; BMP
  Route Monitoring serves a similar role.
- **FlowSpec RIB entries** -- TABLE_DUMP_V2 is defined for unicast NLRI.
  FlowSpec dump is not standard and is deferred.
- **Loc-RIB overlay** -- intentionally excluded to prevent duplication.

## Consequences

### Positive

- Completes the monitoring/archival story alongside BMP. MRT files are
  consumable by standard tools (bgpdump, pybgpstream, mrtparse).
- GoBGP parity for the monitoring category reaches 100%.
- Atomic writes and gzip prevent partial/corrupt dumps.
- Deterministic output enables diff-based regression testing.
- Zero overhead when unconfigured (no manager task spawned).

### Negative

- Snapshot encoding is allocation-heavy for very large RIBs (groups
  routes by prefix, clones attributes per entry). Tracked as a deferred
  hardening item, not a correctness issue.
- `peer_asn`/`peer_bgp_id` HashMaps add two small maps to RibManager
  state. Negligible memory impact.

### Neutral

- MRT config changes require daemon restart (consistent with BMP, RPKI).
- On-demand trigger returns the file path synchronously, blocking the
  gRPC handler until the dump completes. For very large RIBs this could
  be slow; a future enhancement could make it async with a status poll.
