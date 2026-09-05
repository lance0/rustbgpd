# rustbgpd-mrt

MRT TABLE_DUMP_V2 export and read-back implementing RFC 6396.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Features

- **TABLE_DUMP_V2** (type 13) emits these six subtypes:
  - `PEER_INDEX_TABLE` (subtype 1)
  - `RIB_IPV4_UNICAST` (subtype 2)
  - `RIB_IPV6_UNICAST` (subtype 4)
  - `RIB_GENERIC` (subtype 6) for L2VPN/EVPN (AFI 25 / SAFI 70), following
    RFC 6396 section 4.3.5
  - `RIB_IPV4_UNICAST_ADDPATH` (subtype 8), following RFC 8050
  - `RIB_IPV6_UNICAST_ADDPATH` (subtype 10), following RFC 8050
- **Periodic + on-demand** — configurable dump interval or gRPC
  `TriggerMrtDump` for immediate snapshots
- **Optional gzip** compression via flate2
- **Atomic writes** — temp file + rename to prevent partial dumps
- **NH synthesis** — IPv4 routes get NEXT_HOP attribute, IPv6 get
  MP_REACH_NLRI, RFC 8950 IPv4-with-IPv6-NH get MP_REACH_NLRI
- **TABLE_DUMP_V2 reader** — `SnapshotReader` parses `PEER_INDEX_TABLE` +
  `RIB_IPV4_UNICAST` / `RIB_IPV6_UNICAST` records into
  `SnapshotEntry` / `SnapshotNlri`, with gzip auto-detection
  (`decompress_if_gzip`). A RIB entry's `MP_REACH_NLRI` is accepted in both
  the RFC 6396 section 4.3.4 reduced form (next-hop length, next hop) and the
  full RFC 4760 form other collectors write (AFI, SAFI, next-hop length, next
  hop, optional reserved octet), told apart by the leading octet; a next-hop
  length other than 4, 16, or 32, a truncated next hop, an AFI that disagrees
  with the next-hop length, or trailing octets is a malformed-record error.
  The decoder is `rustbgpd-wire`'s `decode_table_dump_v2_mp_reach_next_hop`,
  which `rbgp diff snapshot from-mrt` also uses, so both read the same bytes
  the same way. Defensive revised attribute decoding keeps an entry
  only when every recovered issue is attribute-discard, using the conservative
  internal-neighbor classification when the snapshot lacks session evidence.
  Separate path-attribute and BGP-LS NLRI discard counters make that bounded
  interoperability recovery observable; stronger dispositions remain fatal
- **Dump health metrics** — `MrtManager` records `mrt_dump_interval_seconds`,
  `mrt_last_dump_success_timestamp_seconds`,
  `mrt_last_dump_duration_milliseconds`, `mrt_dump_bytes_written_total`, and
  `mrt_dump_failures_total{stage}` (`preflight` / `snapshot` / `encode` /
  `write`; a caller-canceled on-demand dump is not counted). The shipped alert
  pack's `MrtDumpStale` guards on a non-zero `mrt_dump_interval_seconds` and
  fires once the newest dump is older than twice it

## Warm bundle

Durable, fail-closed warm-checkpoint bundle storage (`warm_bundle` module),
used by coordinated-shutdown checkpointing. A bundle directory holds a
content-addressed MRT snapshot artifact; publication fsyncs and renames that
artifact before atomically replacing `manifest.json` (the commit point), then
fsyncs the directory, so a crash can never observe a half-written manifest or
snapshot.

Public entry points:

- `WarmBundleDirectory::open` — pins a preexisting, owner-verified bundle
  directory as a file descriptor; every subsequent read, create, rename,
  unlink, and fsync is descriptor-relative, so path replacement and symlink
  races cannot redirect publication or loading.
- `write_warm_bundle` / `write_warm_bundle_bounded` — atomically publish a format-version-2
  bundle (the bounded form additionally observes a shutdown cancellation
  token and deadline, safe to cancel at any point before the manifest
  rename).
- `load_warm_bundle` — loads only an exact, fresh, byte- and
  semantically-valid bundle against an independently derived expectation.

Format version 2 requires RFC 8050 Add-Path encoding. All version-1
manifests are rejected before snapshot decoding, including non-Add-Path
bundles. Regenerate checkpoints with this version; there is no automatic
conversion of historical malformed Add-Path artifacts. The existing directory
name, Rust type names, and resolved-policy digest framing remain unchanged.

Warm bundles remain lossless and fail closed: publication and loading reject
snapshots whose reader reports any discarded path attributes or BGP-LS NLRIs,
with both counts preserved in the typed validation error.

**Scope boundary:** this module stops at storage and identity validation. It
never restores a route, mutates the RIB, runs selection, releases RFC 4724
deferral, or advertises a recovered candidate — a later boot coordinator must
keep all recovered candidates behind that gate.

## License

MIT OR Apache-2.0
