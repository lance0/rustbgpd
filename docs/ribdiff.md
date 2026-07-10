# `rbgp diff advertised` — live Adj-RIB-Out vs incumbent snapshot

Compares what rustbgpd is advertising to each peer (the live Adj-RIB-Out,
read over gRPC) against a snapshot of what an incumbent route server
advertises to the same peers, and reports semantic divergence. Built for
the route-server shadow trial: run both stacks against the same members,
export the incumbent's advertised view, and prove the views match before
cutover ([cookbook/route-server-migration.md](cookbook/route-server-migration.md)).

The command is strictly read-only (`ListNeighbors` + `ListAdvertisedRoutes`
are the only RPCs issued) and fail-closed: **equality is never asserted
from incomplete, truncated, over-limit, stale, or malformed input.**

```console
$ rbgp diff advertised --peer 192.0.2.1 --against incumbent.ndjson
$ echo $?
0
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Both inputs complete, no semantic differences |
| 1 | Both inputs complete, differences found (listed in the report) |
| 2 | Incomplete / malformed / stale / mixed-generation / unsupported / over-limit input, or an operational error — equality refused |

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--peer <IP>` | all snapshot peers | Peer to compare; repeatable |
| `--against <PATH>` | required | Incumbent `rbgp-ribsnap/1` NDJSON snapshot |
| `--family <F>` | ipv4\_unicast + ipv6\_unicast | Family filter; repeatable |
| `--ignore-attribute <A>` | none | Exclude an attribute from comparison on both sides; repeatable (`origin`, `as_path`, `next_hop`, `med`, `local_pref`, `communities`, `extended_communities`, `large_communities`) |
| `--max-routes <N>` | 4,000,000 | Maximum retained routes per side; exceeding refuses the comparison |
| `--max-input-bytes <N>` | 1 GiB | Maximum snapshot bytes read; exceeding refuses the comparison |
| `--detail <N>` | 20 | Maximum difference rows in human output (`--json` is always complete) |
| `--deadline <SECS>` | 120 | Overall wall-clock budget; expiry refuses the comparison |
| `--json` | off | Full machine-readable report (`rbgp-ribdiff/1` schema) |

Ignored-attribute choices and the live-source normalization notes are
emitted in both the human and JSON reports, so a report is always
self-describing about what it did not compare.

## What is compared

Routes are compared as a **multiset of semantic paths per (peer, family,
NLRI)**. RFC 7911 path identifiers are locally assigned and never
compared (they are retained for diagnostics). Communities are compared
order-insensitively; duplicate identical paths are a multiplicity
difference, not equality. Divergence classes: `incumbent_only`,
`rustbgpd_only`, `attribute_changed`, `multiplicity_changed`.

Live-source limitations (also printed in every report):

- **MED**: the daemon proto carries MED as a bare integer, so MED-absent
  and MED 0 are indistinguishable over gRPC. Live `med=0` is compared as
  absent; snapshot producers should omit `med` when it is zero or absent,
  or pass `--ignore-attribute med`.
- **AS_PATH**: compared as a single flattened `AS_SEQUENCE` on both sides
  (the proto exposes a flat ASN list); `AS_SET` structure is not compared.
- **Unknown attributes**: path attributes outside the typed set are not
  visible over gRPC and are not compared.
- **Generation**: the route-listing API exposes no RIB generation token.
  Listing drift during pagination is detected via per-page `total_count`
  (any movement refuses the comparison); the snapshot header's
  `generation` is adopted for the live side.

## Fail-closed behaviors

- Snapshot completeness is explicit: a missing completion trailer means
  the file may be truncated — **EOF alone is never completeness** (exit 2).
- The trailer's `routes` count must equal the number of route records in
  the file (exit 2 on mismatch).
- Unknown fields in snapshot records are malformed (a misspelled
  attribute must not silently compare as absent), as are blank lines,
  records after the trailer, and conflicting ASNs for one peer (exit 2).
- Live pagination refuses repeated or non-advancing page tokens (the same
  page twice), `total_count` drift between pages (the RIB changed under
  the walk), and a fetched count that differs from the server's
  `total_count` (exit 2).
- `--max-routes` and `--max-input-bytes` are enforced before buffering,
  on both sides (exit 2).
- The aggregate equal verdict is refused when **any** requested peer or
  family is unavailable: a peer missing from the daemon, a snapshot/daemon
  ASN mismatch, or an explicitly requested family the peer does not
  negotiate all make the comparison `incomparable` (exit 2).

Memory is bounded by processing one peer at a time: live pages stream
into that peer's route set as they arrive, and each peer's data is
released once its diff folds into the report — the two full sides are
never held simultaneously.

## Snapshot format: `rbgp-ribsnap/1`

One JSON object per line (NDJSON). Three record kinds:

**Header** — must be the first line:

```json
{"record":"header","schema":"rbgp-ribsnap/1","source":"bird-rs1","generation":1}
```

- `source`: free-form provenance label, echoed in reports.
- `generation`: capture round. Snapshots you intend to compare against
  the same live capture session share one generation value; any u64 works.

**Route** — one per advertised path (repeat the line for Add-Path
duplicates; multiplicity is compared):

```json
{"record":"route","peer":"192.0.2.1","peer_asn":64501,"prefix":"203.0.113.0/24","origin":0,"as_path":[64500,65010],"next_hop":"192.0.2.254","local_pref":100,"communities":["64500:100",3356622],"extended_communities":[9223372036854775808],"large_communities":["64500:1:100"],"med":5,"path_id":2}
```

- `peer` / `peer_asn`: the member the route is advertised **to** (must
  match the daemon's configured neighbor and ASN).
- `prefix`: `addr/len`; the family is inferred from the address.
- `origin`: 0 = IGP, 1 = EGP, 2 = INCOMPLETE. Omit when absent.
- `as_path`: flat ASN list (compared as one `AS_SEQUENCE`). Omit or `[]`
  for an empty path.
- `med`, `local_pref`: omit when the attribute is absent — absent and 0
  are distinct in the comparison (but see the MED live-source note above:
  omit `med` when it is zero).
- `communities`: `"ASN:value"` strings (well-known aliases like
  `NO_EXPORT` accepted) or raw u32 values.
- `extended_communities`: raw 8-octet values as unsigned integers
  (big-endian wire order).
- `large_communities`: `"global:data1:data2"` strings.
- `path_id`: optional; diagnostics only, never compared.

Unknown fields are rejected (typo protection). All fields except
`record`, `peer`, `peer_asn`, and `prefix` are optional.

**Trailer** — must be the last line; declares the route-record count:

```json
{"record":"trailer","routes":42}
```

### Producing a snapshot

Any process that can list the incumbent's per-member advertised routes
can produce the format. Python sketch (adapt `export_routes()` to your
incumbent — `birdc show route export`, `vtysh -c "show ip bgp neighbor X
advertised-routes json"`, an API, etc.):

```python
import json, sys

def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")

emit({"record": "header", "schema": "rbgp-ribsnap/1",
      "source": "incumbent-rs1", "generation": 1})
count = 0
for member, routes in export_routes():          # your incumbent's export
    for r in routes:
        rec = {"record": "route", "peer": member.ip, "peer_asn": member.asn,
               "prefix": r.prefix, "origin": r.origin, "as_path": r.as_path,
               "next_hop": r.next_hop, "communities": r.communities}
        if r.med:                                # omit MED 0 (see note above)
            rec["med"] = r.med
        if r.local_pref is not None:
            rec["local_pref"] = r.local_pref
        emit(rec)
        count += 1
emit({"record": "trailer", "routes": count})
```

Or with `jq`, from a JSON export shaped like
`[{"peer":..., "peer_asn":..., "routes":[...]}, ...]`:

```bash
{
  jq -nc '{record:"header",schema:"rbgp-ribsnap/1",source:"incumbent-rs1",generation:1}'
  jq -c '.[] as $m | $m.routes[] | {record:"route",peer:$m.peer,peer_asn:$m.peer_asn}
         + (with_entries(select(.value != null)))' export.json
  jq -nc --argjson n "$(jq '[.[].routes | length] | add' export.json)" \
     '{record:"trailer",routes:$n}'
} > incumbent.ndjson
```

## JSON report

`--json` emits the versioned `rbgp-ribdiff/1` report: verdict,
per-(peer, family) summaries, every diverging NLRI with both sides'
paths and field-level deltas, the normalization profile, plus two
command-level extensions: `ignored_attributes` (the `--ignore-attribute`
choices) and `live_source_notes` (the limitations listed above). Output
is deterministic — byte-identical across runs over identical inputs.
