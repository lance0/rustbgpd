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

Bundled adapters cover MRT `TABLE_DUMP_V2` dumps and the three common
incumbent stacks — see [Snapshot adapters](#snapshot-adapters) below.
Beyond those, any process that can list the incumbent's per-member
advertised routes can produce the format. Python sketch (adapt
`export_routes()` to your incumbent — `birdc show route export`,
`vtysh -c "show ip bgp neighbor X advertised-routes json"`, an API,
etc.):

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

## Snapshot adapters

Four adapters turn an incumbent's own output into `rbgp-ribsnap/1`
NDJSON. Each is a versioned contract: the header's `source` field is
`<adapter>/<contract-version> view=adj-rib-out-capture [label]`, so a
report always names which adapter (and which of its revisions) produced
the incumbent side. Common rules:

- **Completeness** is the counted trailer, written only after the whole
  input converts; any parse failure exits 2 with nothing on stdout, so a
  half-converted snapshot with a valid trailer cannot exist.
- **No fabrication**: an attribute the source view does not expose is
  omitted, never defaulted. Attribute kinds a source renders only
  symbolically (BIRD/FRR/GoBGP extended communities) are skipped with a
  note on stderr — compare with `--ignore-attribute extended_communities`.
- **MED 0 is omitted** like an absent MED, matching the live side's
  documented MED conflation.

| Adapter | Capture command (verified against) | Form |
|---------|-------------------------------------|------|
| `from-mrt/1` | `rbgp diff snapshot from-mrt <file> --view adj-rib-out-capture --peer <ip> --peer-asn <asn>` (RFC 6396 `TABLE_DUMP_V2`, RFC 8050 Add-Path subtypes) | in-binary subcommand |
| `bird2-export/1` | `birdc show route export <member-proto> all` (BIRD 2.0.12) | [`scripts/ribsnap/bird2-export-to-ribsnap.py`](../scripts/ribsnap/bird2-export-to-ribsnap.py) |
| `frr-advertised/1` | `vtysh -c "show ip bgp neighbor <ip> advertised-routes detail json"` (FRR 10.3.1) | [`scripts/ribsnap/frr-advertised-to-ribsnap.py`](../scripts/ribsnap/frr-advertised-to-ribsnap.py) |
| `gobgp-adjout/1` | `gobgp neighbor <ip> adj-out -j` (GoBGP 3.37.0) | [`scripts/ribsnap/gobgp-adjout-to-ribsnap.py`](../scripts/ribsnap/gobgp-adjout-to-ribsnap.py) |

The converters are stdlib-only Python 3; all take
`--peer <ip> --peer-asn <asn> [--source <label>] [--generation <n>]` and
read the capture from a file argument or stdin. Exit codes: 0 snapshot
on stdout, 2 refused. Per-incumbent capture prerequisites, view
limitations, and worked examples live in the
[route-server migration cookbook](cookbook/route-server-migration.md#capturing-the-incumbents-advertised-view).

### `rbgp diff snapshot from-mrt` and the `--view` contract

RFC 6396 `TABLE_DUMP_V2` is, by default, a **collector RIB view** — best
paths as seen by a collector, not what any client was sent after export
policy. The required `--view` flag is the producer's attestation of what
the dump actually is:

- `adj-rib-out-capture` — the dump was produced by capturing one
  client's post-policy advertised routes (e.g. a shadow session feeding
  a dump tool). Accepted; this is the only view comparable against an
  Adj-RIB-Out.
- `loc-rib` / `adj-rib-in` — refused (exit 2, nothing emitted). A
  Loc-RIB or pre-policy view compared against an Adj-RIB-Out would
  report every export-policy effect as divergence — or worse, mask a
  real divergence as an expected one. The adapter labels the input
  non-comparable instead of pretending.

Wire handling: AS_PATH is decoded as 4-octet (mandatory in
`TABLE_DUMP_V2`); both the §4.3.4 abbreviated `MP_REACH_NLRI` (next-hop
only) and the full RFC 4760 form some collectors emit are accepted (a
leading zero octet can only be an AFI high byte, which disambiguates);
RFC 8050 Add-Path entries carry their path identifier through as
`path_id`. Extended and large communities are emitted from the raw
attribute bytes.

### Golden fixtures

Each converter is pinned by golden tests in `cargo test -p rustbgpctl`
(`commands::diff::tests::adapters`): a raw capture taken from a real
container (the M83 route-server multi-stack lab: BIRD 2.0.12,
FRR 10.3.1, GoBGP 3.37.0) must convert byte-for-byte to its checked-in
`.expected.ndjson`, parse as a complete snapshot, and diff clean against
the same capture's wire-truth values. An upstream output-format change
breaks these tests first. The fixture-refresh procedure (redeploy the
lab, recapture, re-run the converters with `BLESS=1`) is documented in
the test module.

## JSON report

`--json` emits the versioned `rbgp-ribdiff/1` report: verdict,
per-(peer, family) summaries, every diverging NLRI with both sides'
paths and field-level deltas, the normalization profile, plus two
command-level extensions: `ignored_attributes` (the `--ignore-attribute`
choices) and `live_source_notes` (the limitations listed above). Output
is deterministic — byte-identical across runs over identical inputs.
