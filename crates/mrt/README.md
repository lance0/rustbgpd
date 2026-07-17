# rustbgpd-mrt

MRT TABLE_DUMP_V2 export and read-back implementing RFC 6396.

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
- **TABLE_DUMP_V2 reader** — `SnapshotReader` parses `PEER_INDEX_TABLE` +
  `RIB_IPV4_UNICAST` / `RIB_IPV6_UNICAST` records into
  `SnapshotEntry` / `SnapshotNlri`, with gzip auto-detection
  (`decompress_if_gzip`)

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
- `write_warm_bundle` / `write_warm_bundle_bounded` — atomically publish a V1
  bundle (the bounded form additionally observes a shutdown cancellation
  token and deadline, safe to cancel at any point before the manifest
  rename).
- `load_warm_bundle` — loads only an exact, fresh, byte- and
  semantically-valid bundle against an independently derived expectation.

**Scope boundary:** this module stops at storage and identity validation. It
never restores a route, mutates the RIB, runs selection, releases RFC 4724
deferral, or advertises a recovered candidate — a later boot coordinator must
keep all recovered candidates behind that gate.

## License

MIT OR Apache-2.0
