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
$ rbgp diff advertised --neighbor 192.0.2.1 --against incumbent.ndjson
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
| `--neighbor <IP>` | all snapshot peers | Peer to compare; repeatable |
| `--against <PATH>` | required | Incumbent `rbgp-ribsnap/1` NDJSON snapshot |
| `--family <F>` | ipv4\_unicast + ipv6\_unicast | Family filter; repeatable |
| `--ignore-attribute <A>` | none | Exclude an attribute from comparison on both sides; repeatable (`origin`, `as_path`, `next_hop`, `med`, `local_pref`, `communities`, `extended_communities`, `large_communities`, `unknown`) |
| `--max-routes <N>` | 4,000,000 | Maximum retained routes per side; exceeding refuses the comparison |
| `--max-input-bytes <N>` | 1 GiB | Maximum snapshot bytes read; exceeding refuses the comparison |
| `--detail <N>` | 20 | Maximum difference rows in human output (`--json` is always complete) |
| `--deadline <SECS>` | 120 | Aggregate live-query budget, started after bounded local snapshot parsing and shared by neighbor discovery plus every advertised-route page; expiry refuses the comparison |
| `--json` | off | Full machine-readable report (`rbgp-ribdiff/1` schema) |

When exactly one family is selected, the live request sends that concrete
`AddressFamily` so the daemon can narrow its walk. The default and an explicit
two-family selection send `ADDRESS_FAMILY_UNSPECIFIED`; the client still
validates every returned route against the requested family set.

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

- **MED** (older daemons only): daemons that populate the `med_attr`
  proto field are compared exactly — MED-absent and MED 0 are distinct —
  and no MED note appears in the report. Older daemons carry MED as a
  bare integer only, where absent and 0 are indistinguishable over gRPC:
  their live `med=0` is compared as absent (and the report says so);
  snapshot producers targeting them should omit `med` when it is zero or
  absent, or pass `--ignore-attribute med`.
- **AS_PATH**: compared as a single flattened `AS_SEQUENCE` on both sides
  (the proto exposes a flat ASN list); `AS_SET` structure is not compared.
- **Unknown attributes**: path attributes outside the typed set are not
  visible over gRPC and are not compared.
- **Generation**: `ListRoutesResponse.page_version` exposes an opaque
  process-local `{epoch, generation}` consistency fence, not a numeric RIB
  snapshot generation. The adapter pins the complete pair across every live
  page and peer walk and refuses a change. It never compares or substitutes
  `page_version.generation` with the producer-local `rbgp-ribsnap/1` header
  generation. The header value remains the report's live-side generation only
  to preserve the `rbgp-ribdiff/1` report schema; it does not validate the live
  capture. Opaque continuation tokens still bind the RPC scope and canonical
  filters and abort on a mid-walk mutation, while per-page `total_count` checks
  remain defense in depth.

## Fail-closed behaviors

- Snapshot completeness is explicit: a missing completion trailer means
  the file may be truncated — **EOF alone is never completeness** (exit 2).
- The trailer's `routes` count must equal the number of route records in
  the file (exit 2 on mismatch).
- Unknown fields in snapshot records are malformed (a misspelled
  attribute must not silently compare as absent), as are blank lines,
  records after the trailer, and conflicting ASNs for one peer (exit 2).
- Live pagination refuses repeated or non-advancing page tokens (the same
  page twice), a changed `page_version`, mixed present/absent versions,
  `total_count` drift between pages, and a fetched count that differs from the
  server's `total_count` (exit 2). An older daemon whose every response omits
  `page_version` is supported only when the deduplicated request selects
  exactly one peer; multi-peer legacy captures are incomparable (exit 2).
- `--max-routes` and `--max-input-bytes` are enforced before buffering,
  on both sides (exit 2). The live route ceiling is one aggregate count across
  all returned rows from all requested peers, including defensively discarded
  rows from a family the daemon should have filtered.
- `--deadline` starts only after the bounded local snapshot parse completes.
  One absolute cutoff then covers `ListNeighbors` and every
  `ListAdvertisedRoutes` page across all requested peers; time spent in an
  earlier RPC or page reduces what remains for every later one. Expiry, zero
  budget, or a value outside the monotonic clock's range exits 2 without
  rendering a partial equality verdict.
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
  are distinct in the comparison (when targeting an older daemon without
  `med_attr`, also omit `med` when it is zero — see the MED live-source
  note above).
- `communities`: `"ASN:value"` strings (well-known aliases like
  `NO_EXPORT` accepted) or raw u32 values.
- `extended_communities`: raw 8-octet values as unsigned integers
  (big-endian wire order).
- `large_communities`: `"global:data1:data2"` strings.
- `unknown_attrs`: optional; attributes outside the typed set, preserved
  as `{"type_code":N,"flags":N,"value":"<hex>"}` wire triples (the
  from-bmp adapter emits them; e.g. ORIGINATOR_ID or OTC). Compared
  byte-exact by the engine — but the live gRPC side cannot see unknown
  attributes, so a snapshot carrying them diverges against a live
  comparison unless `--ignore-attribute unknown` is passed (an explicit
  operator decision, never a silent drop).
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
        if r.med is not None:                    # omit MED 0 too for older
            rec["med"] = r.med                   # daemons (see note above)
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

Five adapters turn an incumbent's own output into `rbgp-ribsnap/1`
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
- **MED 0 is omitted** like an absent MED, matching the historical live
  MED conflation. Against a daemon that populates `med_attr`, an
  explicit live MED 0 therefore reports as a MED difference — pass
  `--ignore-attribute med` until the adapter contracts are revised.

| Adapter | Capture command (verified against) | Form |
|---------|-------------------------------------|------|
| `from-mrt/1` | `rbgp diff snapshot from-mrt <file> --view adj-rib-out-capture --peer <ip> --peer-asn <asn>` (RFC 6396 `TABLE_DUMP_V2`, RFC 8050 Add-Path subtypes) | in-binary subcommand |
| `from-bmp/1` | `rbgp diff snapshot from-bmp <capture> [--peer <ip>]` (RFC 7854 BMP v3 byte stream carrying the RFC 8671 post-policy Adj-RIB-Out view, O=1/L=1) | in-binary subcommand |
| `bird2-export/1` | `birdc show route export <member-proto> all` (BIRD 2.0.12); `birdc show route export table <channel> all` (BIRD 3.3.1) | [`scripts/ribsnap/bird2-export-to-ribsnap.py`](../scripts/ribsnap/bird2-export-to-ribsnap.py) |
| `frr-advertised/1` | `vtysh -c "show ip bgp neighbor <ip> advertised-routes detail json"` (FRR 10.3.1) | [`scripts/ribsnap/frr-advertised-to-ribsnap.py`](../scripts/ribsnap/frr-advertised-to-ribsnap.py) |
| `gobgp-adjout/1` | `gobgp neighbor <ip> adj-out -j` (GoBGP 3.37.0, 4.7.0) | [`scripts/ribsnap/gobgp-adjout-to-ribsnap.py`](../scripts/ribsnap/gobgp-adjout-to-ribsnap.py) |

`bird2-export/1` remains the stable legacy source identifier for both BIRD
versions. The converters are stdlib-only Python 3; all take
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

### `rbgp diff snapshot from-bmp` — RFC 8671 post-policy BMP captures

If the incumbent exports BMP with the RFC 8671 post-policy Adj-RIB-Out
view enabled, its own BMP feed is a wire-true source of what it sent
each member — including attributes no CLI view renders. Capture the
feed's raw bytes **from the start of the BMP session** (the adapter is
offline; streaming-socket ingestion is out of scope), then convert:

```bash
# Stand in as the incumbent's BMP station and capture the raw stream;
# stop once every peer's dump has completed (End-of-RIB seen).
nc -l 11019 > incumbent.bmp        # or: socat TCP-LISTEN:11019 - > incumbent.bmp
rbgp diff snapshot from-bmp incumbent.bmp > incumbent.ndjson
```

The capture must begin at session start because the Peer Up messages
carry the negotiated OPENs — without them the adapter cannot know the
per-family Add-Path state (RFC 7911: path IDs appear in the incumbent's
UPDATEs toward a member iff the incumbent advertised *send* and the
member advertised *receive*) and refuses rather than misparse NLRI.

View selection is per Route Monitoring message, from its per-peer
header flags (O/L flags on Peer Up/Down select nothing):

- **O=1, L=1** (post-policy Adj-RIB-Out) — the comparison source; folded
  into the snapshot.
- **O=0** (pre-policy Adj-RIB-In, the RFC 7854 default most feeds also
  carry) — skipped with a stderr note, never folded.
- **O=1, L=0** (pre-policy Adj-RIB-Out) — refused (exit 2): a
  pre-policy view compared against a post-policy Adj-RIB-Out would
  report every export-policy effect as divergence, or mask a real one.

State is kept per (connection generation, peer, family, NLRI, source
path ID); a later update supersedes an earlier one, so live updates
interleaved with the initial dump fold correctly. A reconnect (new
Initiation) invalidates everything; a Peer Up resets its peer; a Peer
Down discards it. **A peer/family is complete only after its End-of-RIB
in the current generation** — a capture cut before End-of-RIB is
refused (exit 2, nothing emitted), because `rbgp-ribsnap/1`'s counted
trailer would otherwise present a truncated view as complete and the
downstream diff could assert a false "in sync". Use `--peer` to emit a
complete subset when an uninteresting peer never finished. RFC 8671
stat types 15/17 arriving after End-of-RIB are cross-checked against
the folded counts (a mismatch means a decode gap and refuses);
completeness never requires them.

Scope and bounds: BMP version 3 streams; global-instance peers
(RD/local-instance peers are skipped with a note); IPv4/IPv6 unicast
NLRI (other families are skipped with a note). The per-peer-header A flag
selects the ordinary AS width. On an A=0 legacy stream, type 2/17 and type
7/18 pairs normalize to one four-octet logical path and one canonical
eight-byte type 7 record in `unknown_attrs`; compatibility types 17/18 are
not re-emitted. ORIGINATOR_ID, CLUSTER_LIST, OTC, and other attributes the
decoder leaves untyped retain their value bytes and semantic flags in
`unknown_attrs`; the Extended Length bit is cleared because it is an encoding
artifact. Compare with
`--ignore-attribute unknown` if accepting that gRPC cannot verify them.
Hard limits (not flags) bound input bytes (1 GiB), per-message length
(1 MiB), peers (4096), routes (4M), and paths per NLRI (64); exceeding
any refuses the conversion.

### Golden fixtures

Each converter is pinned by golden tests in `cargo test -p rustbgpctl`
(`commands::diff::tests::adapters`): a raw capture taken from a real
container must convert byte-for-byte to its checked-in
`.expected.ndjson`, parse as a complete snapshot, and diff clean against
the same capture's wire-truth values. An upstream output-format change
breaks these tests first. The M83 refresh covers BIRD 2.0.12, FRR 10.3.1,
and GoBGP 3.37.0. The separate BIRD 3.3.1 recipe uses its upstream tag at
commit `695c7b74`: source AS64501 (`10.92.6.11`) advertises
`203.0.113.0/24` with MED 120, community `64501:111`, and large community
`64501:92:6` through the RS fixture
[`bird3.conf`](../crates/cli/tests/fixtures/import/bird3.conf) (AS65500,
`10.92.6.12`) to target AS64502 (`10.92.6.13`). After both protocols are
Established, capture `show route export table target_member.ipv4 all`.
The full commands and fixture-refresh arguments are in the test module.
The from-bmp golden is built synthetically instead,
framed by the daemon's own RFC-pinned BMP encoder (an M83 capture would
carry rustbgpd's own view, not an incumbent's), and its end-to-end
tests prove capture → canonical records → in-sync, divergent, and
incomplete verdicts.

## JSON report

`--json` emits the versioned `rbgp-ribdiff/1` report: verdict,
per-(peer, family) summaries, every diverging NLRI with both sides'
paths and field-level deltas, the normalization profile, plus two
command-level extensions: `ignored_attributes` (the `--ignore-attribute`
choices) and `live_source_notes` (the limitations listed above). Output
is deterministic — byte-identical across runs over identical inputs.
