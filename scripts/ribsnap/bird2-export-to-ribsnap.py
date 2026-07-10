#!/usr/bin/env python3
"""bird2-export/1 — convert BIRD 2 `birdc show route export <proto> all`
output into an `rbgp-ribsnap/1` NDJSON snapshot for `rbgp diff advertised`.

Capture (on the incumbent BIRD 2 route server, one run per member):

    birdc show route export <member-protocol> all > bird-<member>.txt
    bird2-export-to-ribsnap.py --peer <member-ip> --peer-asn <member-asn> \
        bird-<member>.txt > bird-<member>.ndjson

Verified against BIRD 2.0.12. `show route export P` applies P's export
filters, so attribute rewrites made by the export filter are reflected.

Honesty notes (see docs/ribdiff.md for the adapter matrix):
  - The export view is PRE-ENCODING: BGP.as_path / BGP.next_hop show the
    table values after the export filter, not the wire encoding. A
    transparent route server neither prepends nor rewrites next hop
    toward `rs client` members, so for the route-server migration case
    the view equals the wire. Locally-originated routes (statics) carry
    no BGP.as_path/BGP.next_hop/BGP.origin at all — those fields are
    OMITTED, never fabricated (compare with --ignore-attribute).
  - BGP.ext_community is rendered symbolically by birdc and cannot be
    reconstructed into raw 8-octet values without guessing; it is
    skipped with a note on stderr.
  - MED 0 is omitted like an absent MED (the consumer's documented
    normalization).

Exit codes: 0 snapshot on stdout; 2 refused (unrecognized/malformed
input), nothing on stdout.
"""

import argparse
import json
import re
import sys

SCHEMA = "rbgp-ribsnap/1"
ADAPTER = "bird2-export/1"

# "100.65.0.0/24        blackhole [statics 02:00:42.574] * (200)"
ROUTE_HEAD = re.compile(
    r"^(?P<prefix>[0-9a-fA-F:.]+/\d+)?\s+"
    r"(?P<dest>unicast|blackhole|unreachable|prohibit)\s+"
    r"\[(?P<proto>\S+)\s"
)
ORIGIN = {"IGP": 0, "EGP": 1, "Incomplete": 2}


def fail(msg):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(2)


def note(msg):
    print(f"note: {msg}", file=sys.stderr)


def parse_attr(route, key, value, line_no):
    if key == "BGP.origin":
        if value not in ORIGIN:
            fail(f"line {line_no}: unknown BGP.origin {value!r}")
        route["origin"] = ORIGIN[value]
    elif key == "BGP.as_path":
        # Flatten; AS_SET braces are dropped (the snapshot format
        # compares a flattened AS_SEQUENCE — documented consumer
        # limitation).
        asns = [tok for tok in value.replace("{", " ").replace("}", " ").split() if tok]
        try:
            route["as_path"] = [int(a) for a in asns]
        except ValueError:
            fail(f"line {line_no}: unparseable BGP.as_path {value!r}")
    elif key == "BGP.next_hop":
        # IPv6 may list "global link-local"; the global address is the
        # comparable one.
        route["next_hop"] = value.split()[0]
    elif key == "BGP.med":
        med = parse_int(value, key, line_no)
        if med != 0:  # MED 0 is omitted like absent (consumer contract)
            route["med"] = med
    elif key == "BGP.local_pref":
        route["local_pref"] = parse_int(value, key, line_no)
    elif key == "BGP.community":
        route["communities"] = [
            f"{a}:{b}" for a, b in parse_tuples(value, 2, key, line_no)
        ]
    elif key == "BGP.large_community":
        route["large_communities"] = [
            f"{a}:{b}:{c}" for a, b, c in parse_tuples(value, 3, key, line_no)
        ]
    elif key == "BGP.ext_community":
        note(
            f"line {line_no}: BGP.ext_community is rendered symbolically by "
            "birdc and cannot be reconstructed into raw values; skipped "
            "(compare with --ignore-attribute extended_communities)"
        )
    # Anything else (Type, via, BGP.otc, ...) is not part of the
    # snapshot schema; leave it out rather than guess a mapping.


def parse_int(value, key, line_no):
    try:
        return int(value)
    except ValueError:
        fail(f"line {line_no}: unparseable {key} {value!r}")


def parse_tuples(value, arity, key, line_no):
    """Parse birdc community lists: "(65001,111) (65001,666)" — large
    communities print with spaces: "(65001, 1, 1)"."""
    tuples = []
    for group in re.findall(r"\(([^)]*)\)", value):
        parts = [p.strip() for p in group.split(",")]
        if len(parts) != arity or not all(p.isdigit() for p in parts):
            fail(f"line {line_no}: unparseable {key} element ({group})")
        tuples.append(tuple(int(p) for p in parts))
    if not tuples:
        fail(f"line {line_no}: unparseable {key} {value!r}")
    return tuples


def convert(text, args):
    routes = []
    current_prefix = None
    saw_table = False
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if line.startswith("BIRD ") and line.rstrip().endswith("ready."):
            continue
        if re.match(r"^Table \S+:$", line.strip()):
            saw_table = True
            continue
        head = ROUTE_HEAD.match(line)
        if head:
            if head.group("prefix"):
                current_prefix = head.group("prefix")
            if current_prefix is None:
                fail(f"line {line_no}: route entry before any prefix")
            routes.append(
                {
                    "record": "route",
                    "peer": args.peer,
                    "peer_asn": args.peer_asn,
                    "prefix": current_prefix,
                }
            )
            continue
        if line.startswith("\t"):
            if not routes:
                fail(f"line {line_no}: attribute line before any route")
            key, sep, value = line.strip().partition(":")
            if sep:
                parse_attr(routes[-1], key.strip(), value.strip(), line_no)
            continue
        fail(f"line {line_no}: unrecognized line {line.strip()!r}")
    if not saw_table and not routes:
        fail("no 'Table ...:' section and no routes: is this "
             "'birdc show route export <proto> all' output?")
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

    if args.input == "-":
        text = sys.stdin.read()
    else:
        with open(args.input) as f:
            text = f.read()

    routes = convert(text, args)
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
