#!/usr/bin/env python3
"""frr-advertised/1 — convert FRR `show ip bgp neighbor <X>
advertised-routes detail json` output into an `rbgp-ribsnap/1` NDJSON
snapshot for `rbgp diff advertised`.

Capture (on the incumbent FRR route server, one run per member):

    vtysh -c "show ip bgp neighbor <member-ip> advertised-routes detail json" \
        > frr-<member>.json
    frr-advertised-to-ribsnap.py --peer <member-ip> --peer-asn <member-asn> \
        frr-<member>.json > frr-<member>.ndjson

Verified against FRR 10.3.1 (quay.io/frrouting/frr:10.3.1). Both the
summary and detail forms reflect the outbound route-map (post-policy
attributes), but only the DETAIL form carries communities — the summary
form is refused so a communities difference can never be silently
invisible.

Honesty notes (see docs/ribdiff.md for the adapter matrix):
  - The detail form lists EVERY RIB path for each advertised prefix,
    including paths that are not advertised to this neighbor (e.g. the
    path learned from the neighbor itself). Only the bestpath
    (`bestpath.overall == true`) is what a single-best FRR session
    advertises, so only that path is converted. FRR members with
    Add-Path send (`addpath-tx-all-paths`) are NOT supported by this
    converter.
  - The view is PRE-PREPEND and PRE-NEXTHOP-REWRITE: `aspath` excludes
    FRR's own ASN and self-originated routes show next hop 0.0.0.0. A
    route server neither prepends nor rewrites toward
    `route-server-client` members, so for the migration case the view
    equals the wire; placeholder next hops (0.0.0.0 / ::) are OMITTED,
    never fabricated (compare with --ignore-attribute next_hop if your
    capture includes self-originated routes).
  - `extendedCommunity` is rendered symbolically and cannot be
    reconstructed into raw 8-octet values; it is skipped with a note on
    stderr.
  - MED 0 (`metric: 0`) is omitted like an absent MED (the consumer's
    documented normalization) — FRR emits `metric` even when no MED was
    set, so 0 and absent are already conflated at the source.

Exit codes: 0 snapshot on stdout; 2 refused (summary-form input,
unexpected structure, or malformed JSON), nothing on stdout.
"""

import argparse
import json
import sys

SCHEMA = "rbgp-ribsnap/1"
ADAPTER = "frr-advertised/1"
ORIGIN = {"igp": 0, "egp": 1, "incomplete": 2}


def fail(msg):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(2)


def note(msg):
    print(f"note: {msg}", file=sys.stderr)


def convert_path(prefix, path, args):
    route = {
        "record": "route",
        "peer": args.peer,
        "peer_asn": args.peer_asn,
        "prefix": prefix,
    }
    origin = path.get("origin")
    if origin is not None:
        if origin.lower() not in ORIGIN:
            fail(f"{prefix}: unknown origin {origin!r}")
        route["origin"] = ORIGIN[origin.lower()]
    aspath = path.get("aspath")
    if aspath is not None:
        if not isinstance(aspath.get("segments"), list):
            fail(f"{prefix}: aspath without a segments list")
        flattened = []
        for segment in aspath["segments"]:
            # AS_SET segments are flattened too (the snapshot format
            # compares a flattened AS_SEQUENCE — documented consumer
            # limitation).
            flattened.extend(segment.get("list", []))
        if flattened:
            route["as_path"] = flattened
    nexthops = path.get("nexthops") or []
    if nexthops:
        ip = nexthops[0].get("ip", "")
        # 0.0.0.0/:: are FRR's self-originated placeholders, not wire
        # values: omitted, never fabricated.
        if ip and ip not in ("0.0.0.0", "::"):
            route["next_hop"] = ip
    med = path.get("metric")
    if med:  # MED 0 is omitted like absent (consumer contract)
        route["med"] = med
    local_pref = path.get("locPrf")
    if local_pref is not None:
        route["local_pref"] = local_pref
    community = path.get("community")
    if community is not None:
        if not isinstance(community.get("list"), list):
            fail(f"{prefix}: community without a list")
        route["communities"] = community["list"]
    large = path.get("largeCommunity")
    if large is not None:
        if not isinstance(large.get("list"), list):
            fail(f"{prefix}: largeCommunity without a list")
        route["large_communities"] = large["list"]
    if path.get("extendedCommunity") is not None:
        note(
            f"{prefix}: extendedCommunity is rendered symbolically by FRR "
            "and cannot be reconstructed into raw values; skipped (compare "
            "with --ignore-attribute extended_communities)"
        )
    return route


def convert(doc, args):
    if not isinstance(doc, dict) or "advertisedRoutes" not in doc:
        fail("no advertisedRoutes object: is this "
             "'show ip bgp neighbor <X> advertised-routes detail json' output?")
    routes = []
    for prefix, entry in doc["advertisedRoutes"].items():
        if "paths" not in entry:
            fail(
                f"{prefix}: no paths array — this looks like the summary "
                "form, which omits communities; re-capture with "
                "'advertised-routes detail json'"
            )
        best = [p for p in entry["paths"]
                if p.get("bestpath", {}).get("overall") is True]
        if not best:
            fail(f"{prefix}: no bestpath among {len(entry['paths'])} paths; "
                 "refusing to guess which path was advertised")
        for path in best:
            routes.append(convert_path(prefix, path, args))
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
