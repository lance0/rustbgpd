#!/usr/bin/env python3
"""gobgp-adjout/1 — convert GoBGP `gobgp neighbor <X> adj-out -j` output
into an `rbgp-ribsnap/1` NDJSON snapshot for `rbgp diff advertised`.

Capture (on the incumbent GoBGP route server, one run per member):

    gobgp neighbor <member-ip> adj-out -j > gobgp-<member>.json
    gobgp-adjout-to-ribsnap.py --peer <member-ip> --peer-asn <member-asn> \
        gobgp-<member>.json > gobgp-<member>.ndjson

Verified against GoBGP 3.37.0. adj-out is the true post-policy
Adj-RIB-Out: AS_PATH includes GoBGP's own prepend and the next hop is
the rewritten wire value, so no attribute needs to be ignored.

Honesty notes (see docs/ribdiff.md for the adapter matrix):
  - Add-Path: when Add-Path send is negotiated, adj-out -j emits one
    entry per path but exposes NO path identifier (verified on 3.37.0);
    duplicates are emitted as repeated route records (the snapshot
    format compares multiplicity, and path IDs are never compared).
  - Extended communities (attr type 16) are rendered structurally and
    cannot be reconstructed into raw 8-octet values without guessing;
    they are skipped with a note on stderr.
  - MED 0 is omitted like an absent MED (the consumer's documented
    normalization).

Exit codes: 0 snapshot on stdout; 2 refused (unexpected structure or
malformed JSON), nothing on stdout.
"""

import argparse
import json
import sys

SCHEMA = "rbgp-ribsnap/1"
ADAPTER = "gobgp-adjout/1"

ORIGIN_ATTR = 1
AS_PATH_ATTR = 2
NEXT_HOP_ATTR = 3
MED_ATTR = 4
LOCAL_PREF_ATTR = 5
COMMUNITIES_ATTR = 8
MP_REACH_ATTR = 14
EXT_COMMUNITIES_ATTR = 16
LARGE_COMMUNITIES_ATTR = 32


def fail(msg):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(2)


def note(msg):
    print(f"note: {msg}", file=sys.stderr)


def convert_entry(prefix, entry, args):
    route = {
        "record": "route",
        "peer": args.peer,
        "peer_asn": args.peer_asn,
        "prefix": prefix,
    }
    for attr in entry.get("attrs", []):
        kind = attr.get("type")
        if kind == ORIGIN_ATTR:
            route["origin"] = attr["value"]
        elif kind == AS_PATH_ATTR:
            flattened = []
            for segment in attr.get("as_paths") or []:
                # AS_SET segments are flattened too (the snapshot format
                # compares a flattened AS_SEQUENCE — documented consumer
                # limitation).
                flattened.extend(segment.get("asns", []))
            if flattened:
                route["as_path"] = flattened
        elif kind == NEXT_HOP_ATTR:
            route["next_hop"] = attr["nexthop"]
        elif kind == MED_ATTR:
            if attr["metric"]:  # MED 0 omitted like absent (consumer contract)
                route["med"] = attr["metric"]
        elif kind == LOCAL_PREF_ATTR:
            route["local_pref"] = attr["value"]
        elif kind == COMMUNITIES_ATTR:
            route["communities"] = attr["communities"]
        elif kind == MP_REACH_ATTR:
            route["next_hop"] = attr["nexthop"]
        elif kind == EXT_COMMUNITIES_ATTR:
            note(
                f"{prefix}: extended communities are rendered structurally "
                "by gobgp and cannot be reconstructed into raw values; "
                "skipped (compare with --ignore-attribute "
                "extended_communities)"
            )
        elif kind == LARGE_COMMUNITIES_ATTR:
            route["large_communities"] = [
                f"{lc['ASN']}:{lc['LocalData1']}:{lc['LocalData2']}"
                for lc in attr["value"]
            ]
        else:
            note(f"{prefix}: path attribute type {kind} has no snapshot "
                 "representation; skipped")
    return route


def convert(doc, args):
    if not isinstance(doc, dict):
        fail("top-level JSON is not an object: is this "
             "'gobgp neighbor <X> adj-out -j' output?")
    routes = []
    for prefix, entries in doc.items():
        if not isinstance(entries, list):
            fail(f"{prefix}: expected a list of paths")
        # Multiple entries per prefix = Add-Path duplicates; GoBGP
        # 3.37.0 exposes no path identifier in adj-out -j, so they stay
        # repeated records without path_id (multiplicity is compared).
        for entry in entries:
            try:
                routes.append(convert_entry(prefix, entry, args))
            except (KeyError, TypeError) as e:
                fail(f"{prefix}: unexpected attribute shape ({e})")
    return routes


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--peer", required=True,
                        help="member address the routes are advertised to")
    parser.add_argument("--peer-asn", required=True, type=int)
    parser.add_argument("--source", default="",
                        help="free-form provenance label for the header")
    parser.add_argument("--generation", default=1, type=int)
    parser.add_argument("input", nargs="?", default="-",
                        help="capture file (default: stdin)")
    args = parser.parse_args()

    try:
        if args.input == "-":
            doc = json.load(sys.stdin)
        else:
            with open(args.input) as f:
                doc = json.load(f)
    except json.JSONDecodeError as e:
        fail(f"invalid JSON: {e}")

    routes = convert(doc, args)
    source = f"{ADAPTER} view=adj-rib-out-capture"
    if args.source:
        source += f" {args.source}"
    out = [{"record": "header", "schema": SCHEMA, "source": source,
            "generation": args.generation}]
    out.extend(routes)
    out.append({"record": "trailer", "routes": len(routes)})
    # Buffered emit: the counted trailer only ever follows a fully
    # converted snapshot (any earlier failure exits 2 with no stdout).
    sys.stdout.write("".join(json.dumps(rec, separators=(",", ":")) + "\n"
                             for rec in out))


if __name__ == "__main__":
    main()
