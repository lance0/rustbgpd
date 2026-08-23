#!/usr/bin/env python3
import difflib
import json
import os
from pathlib import Path
import re
import sys

EXPECTED = {
    "status": 200,
    "protocols": 200,
    "protocol": 200,
    "symbols": 200,
    "protocol_routes": 200,
    "table_routes": 200,
    "export_routes": 200,
    "protocol_count": 200,
    "table_count": 200,
    "export_count": 200,
    "lookup_protocol": 200,
    "lookup_table": 200,
    "lookup_export": 200,
    "wildcard": 200,
    "bad_prefix": 400,
    "over_limit": 403,
    "missing_protocol": 404,
    "bird_failure": 503,
}
UNSUPPORTED = {
    "defined-only-rejected-route-reason-emission",
    "full-ixp-manager-ui-filter-policy-engine",
    "full-table-count",
    "direct-runtime-protocol-alias-reconfiguration",
    "live-hold-keepalive-countdowns",
}
RUNTIME_SUPPORTED = {
    "exact-protocol-route",
    "exact-export-route",
    "filtered-prefix-wildcard",
    "less-specific-longest-prefix-match",
    "atomic-full-table-snapshot",
    "atomic-all-candidate-prefix-snapshot",
    "file-backed-runtime-protocol-alias-reconfiguration",
    "active-rejected-route-reason-inventory",
    "live-session-transport-detail",
}
ADAPTER_API_VERSION = {"kind": "product-identity", "prefix": "rustbgpd "}
FILTERED_PREFIX_QUERY = {"global_admin": 65001, "function": 1101}
LIVE_SESSION_DETAIL = {
    "fields": ["source_address", "keepalive", "connection", "bgp_session"],
    "connection": "empty-or-leading-space-fsm",
    "route_server_session": ["external", "route-server", "AS4-if-negotiated"],
    "inventory_rpc": "ListNeighbors",
    "unsupported_countdowns": ["hold_timer_now", "keepalive_now"],
}
FILTERED_RETENTION_METADATA = {
    "fields": ["enabled", "capacity", "evictions_since_reset", "may_be_incomplete"],
    "unknown_evictions": None,
    "bounded_store_exempts_generic_max": True,
    "api_max_routes": "retention_capacity",
    "store_eviction_status": 200,
    "store_eviction_retained_rows_preserved": True,
}
REJECT_REASONS = {
    "display": {
        str(reason_id): meaning
        for reason_id, meaning in enumerate([
            "PREFIX LENGTH TOO LONG", "PREFIX LENGTH TOO SHORT", "BOGON",
            "BOGON ASN", "AS PATH TOO LONG", "AS PATH TOO SHORT",
            "FIRST AS NOT PEER AS", "NEXT HOP NOT PEER IP",
            "IRRDB PREFIX FILTERED", "IRRDB ORIGIN AS FILTERED",
            "PREFIX NOT IN ORIGIN AS", "RPKI UNKNOWN", "RPKI INVALID",
            "TRANSIT FREE ASN", "TOO MANY COMMUNITIES",
        ], 1)
    },
    "active_ids": [1, 3, 5, 6, 7, 8, 9, 10, 13, 14],
    "defined_only_ids": [2, 4, 11, 12, 15],
    "fallback_id": 0,
}
NAGIOS_MONITORING = {
    "router_filter": "api_type = Birdseye",
    "generators": ["birdseye-daemons", "birdseye-bgp-sessions"],
    "daemon_check": "nagios-check-birdseye.php",
    "session_protocol": "pb_{vlan_interface_id:04}_as{asn}",
}
MANUAL_CONFIG_EXPORT = {
    "schema": "rustbgpd.ixp-manager.router-config/v2",
    "ixp_manager_version": "7.4.0",
    "router_handle": "b2-rs1-lan1-ipv4",
    "strict_receipt_required": True,
    "no_transit": {
        "effective_default_source": "IXP_MANAGER_EFFECTIVE_DEFAULT",
        "explicit_override_source": "IXP_NO_TRANSIT_ASNS_OVERRIDE",
        "legacy_implicit_source": "IXP_MANAGER_IMPLICIT_DEFAULT refused",
        "default_asns": [
            174, 701, 1299, 2914, 3257, 3320, 3356, 3491, 4134, 5511,
            6453, 6461, 6762, 6830, 7018,
        ],
        "precedence": "default exclusions apply before explicit override replacement",
        "version_skew": "fail-closed",
    },
    "birdwatcher_protocol_aliases": {
        "candidate_path": "birdwatcher-protocol-aliases.conf",
        "current_path": "<runtime-state-dir>/activation/current/birdwatcher-protocol-aliases.conf",
        "line": "pb_{vlan_interface_id:04}_as{asn}={peer_address}@master{protocol}",
        "tables": {"4": "master4", "6": "master6"},
        "cap": 4096,
    },
    "own_as_large_community_scrub": {
        "syntax": "remove large-community <router-asn>:*:*",
        "global_export_chain_position": "last",
        "client_override_export_chain_position": "last",
        "foreign_global_admins": "preserved",
    },
    "ui_filters": {
        "advertise_actions": [
            "AS_IS", "NO_ADVERTISE", "PREPEND_ONCE", "PREPEND_TWICE",
            "PREPEND_THRICE",
        ],
        "receive_actions": [
            "AS_IS", "NO_ADVERTISE", "PREPEND_ONCE", "PREPEND_TWICE",
            "PREPEND_THRICE",
        ],
        "global_receive_prepend": "path-first-with-optional-received-prefix",
        "peer_receive_prepend": "literal-peer-asn",
        "overlapping_receive_prepend": True,
        "compiled_receive_cell_cap": 4096,
        "per_client_cap": 256,
        "total_cap": 4096,
    },
}
FULL_UI_FILTERS = [
    {
        "id": 31, "customer_id": 2, "peer": None,
        "received_prefix": None, "advertised_prefix": None, "protocol": 4,
        "action_advertise": "NO_ADVERTISE", "action_receive": "NO_ADVERTISE",
        "order_by": 2,
    },
    {
        "id": 33, "customer_id": 2,
        "peer": {"customer_id": 4, "asn": 112},
        "received_prefix": "192.175.48.0/24",
        "advertised_prefix": "77.72.72.0/21", "protocol": 4,
        "action_advertise": "PREPEND_TWICE",
        "action_receive": "PREPEND_TWICE", "order_by": 4,
    },
    {
        "id": 35, "customer_id": 2, "peer": None,
        "received_prefix": None, "advertised_prefix": None, "protocol": None,
        "action_advertise": "AS_IS", "action_receive": "AS_IS", "order_by": 6,
    },
]
SUPPORTED_UI_FILTERS = [
    {
        "id": 32, "customer_id": 2, "peer": None,
        "received_prefix": None, "advertised_prefix": None,
        "protocol": 4, "action_advertise": "AS_IS",
        "action_receive": "PREPEND_ONCE", "order_by": 3,
    },
    FULL_UI_FILTERS[1],
    FULL_UI_FILTERS[2],
]

# Runtime divergence allow-list (contract.json runtime_divergences) and the
# pinned Bird's Eye route inventory (contract.json birdseye_routes). Every
# entry carries exactly one classification:
#   must_match  - a real gap the compatibility flip is gated on; converge and
#                 remove the entry
#   intentional - deliberate, permanent divergence (product identity; no
#                 fabricated BIRD internals)
#   unsupported - capability deliberately not provided
#   extension   - the live side provides more than the oracle; harmless to
#                 the pinned consumers
CLASSIFICATIONS = ("must_match", "intentional", "unsupported", "extension")
ROW = ["api/protocols/bgp", "api/protocol/{protocol}"]
ROUTE_VIEWS = [
    "api/routes/protocol/{protocol}", "api/routes/table/{table}",
    "api/routes/export/{protocol}", "api/route/{net}/protocol/{protocol}",
    "api/route/{net}/table/{table}", "api/route/{net}/export/{protocol}",
    "api/routes/lc-zwild/protocol/{protocol}/{x}/{y}",
]
LC_ZWILD = "api/routes/lc-zwild/protocol/{protocol}/{x}/{y}"


def row(path):
    return [f"protocols.*.{path}", f"protocol.{path}"]


RUNTIME_DIVERGENCES = [
    {
        "endpoint": "*", "path": "api.version", "kind": "value",
        "classification": "intentional",
        "birdseye": "Bird's Eye semantic version (2.1.0)",
        "adapter": "rustbgpd <version> product identity",
        "rationale": "api.version names the implementation, not the contract; the gate keeps asserting the rustbgpd prefix",
        "consumer_visible": True,
    },
    {
        "endpoint": "*", "path": "api.Version", "kind": "extra",
        "classification": "extension",
        "birdseye": "absent", "adapter": "duplicate of api.version",
        "rationale": "Birdwatcher-shaped api block; the Alice-LG surface of the same adapter reads it",
        "consumer_visible": False,
    },
    {
        "endpoint": "*", "path": "api.result_from_cache", "kind": "extra",
        "classification": "extension",
        "birdseye": "absent", "adapter": "always false",
        "rationale": "Birdwatcher-shaped api block; there is no cache to skip",
        "consumer_visible": False,
    },
    {
        "endpoint": "api/status", "path": "status.version", "kind": "value",
        "classification": "intentional",
        "birdseye": "BIRD version (2.0.12)", "adapter": "rustbgpd <version>",
        "rationale": "product identity; the pinned looking-glass layout prints it as the router version",
        "consumer_visible": True,
    },
    {
        "endpoint": "api/status", "path": "status.message", "kind": "value",
        "classification": "intentional",
        "birdseye": "last show status line (Daemon is up and running)", "adapter": "rustbgpd AS<asn>",
        "rationale": "product identity; no pinned consumer reads status.message",
        "consumer_visible": False,
    },
    {
        "endpoint": "api/status", "path": "status.current_server", "kind": "extra",
        "classification": "extension",
        "birdseye": "absent", "adapter": "current wall-clock timestamp",
        "rationale": "Birdwatcher status field; no pinned consumer reads it",
        "consumer_visible": False,
    },
    {
        "endpoint": "api/status", "path": ["http_status", "body.message"], "kind": "value",
        "classification": "intentional",
        "birdseye": "HTTP 503 {\"message\": \"Error querying bird\"} when birdc cannot reach BIRD",
        "adapter": "HTTP 502 {\"message\": \"Upstream daemon request failed\"} when the gRPC backend is down",
        "rationale": "backend-failure journey: Bird's Eye reports its own backend error as 503 while the adapter is a gateway and honestly reports 502; the pinned consumer collapses every non-2xx to \"\" either way",
        "consumer_visible": False,
    },
    {
        "endpoint": ROW, "path": row("connection"), "kind": "value",
        "classification": "intentional",
        "birdseye": "BIRD 2 info column with its padding (\"  Established   \")",
        "adapter": "\" Established\" (one leading space)",
        "rationale": "whitespace only; the bgp-summary modal and the diagnostics suite read connection but HTML collapses the padding",
        "consumer_visible": True,
    },
    {
        "endpoint": ROW, "path": row("hold_timer_now") + row("keepalive_now"), "kind": "missing",
        "classification": "unsupported",
        "birdseye": "live countdowns from the BIRD timers", "adapter": "absent",
        "rationale": "live-hold-keepalive-countdowns is an unsupported entry; the daemon exposes negotiated values only, and the diagnostics suite guards them with isset",
        "consumer_visible": True,
    },
    {
        "endpoint": ROW, "path": row("preference"), "kind": "missing",
        "classification": "intentional",
        "birdseye": "BIRD protocol preference (100)", "adapter": "absent",
        "rationale": "BIRD-internal route preference with no rustbgpd equivalent; shown by the bgp-summary modal when present",
        "consumer_visible": True,
    },
    {
        "endpoint": ROW, "path": row("input_filter") + row("output_filter"), "kind": "missing",
        "classification": "intentional",
        "birdseye": "BIRD filter names (ACCEPT)", "adapter": "absent",
        "rationale": "rustbgpd policy chains have no BIRD filter identity; shown by the bgp-summary modal when present",
        "consumer_visible": True,
    },
    {
        "endpoint": ROW, "path": row("route_changes.*.*"), "kind": "missing",
        "classification": "unsupported",
        "birdseye": "BIRD per-channel route change statistics", "adapter": "absent",
        "rationale": "the gRPC NeighborState carries no import/export update and withdraw counters; the bgp-summary modal renders the block when present",
        "consumer_visible": True,
    },
    {
        "endpoint": ROW, "path": row("routes.preferred"), "kind": "missing",
        "classification": "intentional",
        "birdseye": "always 0 (the pinned parser's Routes: regex drops BIRD's preferred count)", "adapter": "absent",
        "rationale": "the oracle value is a parser constant, not a best count; the adapter omits rather than fabricate one",
        "consumer_visible": True,
    },
    {
        "endpoint": ROW, "path": row("routes.filtered"), "kind": "extra",
        "classification": "extension",
        "birdseye": "absent", "adapter": "retained-reject count",
        "rationale": "Birdwatcher protocol field backing the filtered-route views; no pinned consumer reads it",
        "consumer_visible": False,
    },
    {
        "endpoint": ROW, "path": row("neighbor_capabilities.*"), "kind": "extra",
        "classification": "extension",
        "birdseye": "absent (BIRD 2 prints a multi-line Neighbor capabilities block the pinned Neighbor caps: regex never matches)",
        "adapter": "negotiated capability list (refresh, AS4)",
        "rationale": "the adapter keeps the BIRD 1 shape; the bgp-summary modal renders the list when present",
        "consumer_visible": True,
    },
    {
        "endpoint": ROUTE_VIEWS, "path": "routes.*.interface", "kind": "value",
        "classification": "intentional",
        "birdseye": "BIRD egress interface (eth0)", "adapter": "\"\"",
        "rationale": "a route server has no kernel interface to report; no pinned consumer reads it",
        "consumer_visible": False,
    },
    {
        "endpoint": ROUTE_VIEWS, "path": "routes.*.learnt_from", "kind": "value",
        "classification": "intentional",
        "birdseye": "\"\" (BIRD prints from <address> only when it differs from the next hop)", "adapter": "peer address",
        "rationale": "no pinned consumer reads it",
        "consumer_visible": False,
    },
    {
        "endpoint": ROUTE_VIEWS, "path": "routes.*.metric", "kind": "value",
        "classification": "intentional",
        "birdseye": "BIRD route preference (100)", "adapter": "0",
        "rationale": "BIRD-internal preference; the pinned route view prints metric",
        "consumer_visible": True,
    },
    {
        "endpoint": LC_ZWILD, "path": "retention.*", "kind": "extra",
        "classification": "extension",
        "birdseye": "absent", "adapter": "retention completeness metadata",
        "rationale": "filtered_retention_metadata block; no pinned consumer reads it",
        "consumer_visible": False,
    },
    {
        "endpoint": LC_ZWILD, "path": "api.max_routes", "kind": "value",
        "classification": "extension",
        "birdseye": "MAX_ROUTES", "adapter": "retention capacity for the daemon (x, y)",
        "rationale": "filtered_retention_metadata.api_max_routes; the pinned layout prints api.max_routes",
        "consumer_visible": True,
    },
    {
        "endpoint": "api/symbols", "path": "symbols.protocol.*", "kind": "semantics",
        "classification": "intentional",
        "birdseye": "every BIRD protocol, including device1", "adapter": "BGP sessions only",
        "rationale": "the daemon has no BIRD symbol table; the pinned route-search view lists symbols.protocol",
        "consumer_visible": True,
    },
    {
        "endpoint": "api/symbols", "path": "symbols.undefined.*", "kind": "missing",
        "classification": "intentional",
        "birdseye": "BIRD 2.0.12 show symbols reports configuration keywords under an undefined class", "adapter": "absent",
        "rationale": "Bird's Eye passes every class through; no pinned consumer reads undefined",
        "consumer_visible": False,
    },
]

BIRDSEYE_ROUTES = {
    "in_scope": [
        "api/status",
        "api/protocols/bgp",
        "api/protocol/{protocol}",
        "api/symbols",
        "api/routes/protocol/{protocol}",
        "api/routes/table/{table}",
        "api/routes/export/{protocol}",
        "api/routes/lc-zwild/protocol/{protocol}/{x}/{y}",
        "api/route/{net}/table/{table}",
        "api/route/{net}/protocol/{protocol}",
        "api/route/{net}/export/{protocol}",
    ],
    "out_of_scope": [
        "test",
        "/",
        "api/symbols/tables",
        "api/symbols/protocols",
        "api/routes/count/protocol/{protocol}",
        "api/routes/count/table/{table}",
        "api/routes/count/export/{protocol}",
        "api/route/{net}",
        "lg/",
        "lg/protocols/bgp",
        "lg/routes/protocol/{protocol}",
        "lg/routes/table/{table}",
        "lg/routes/export/{protocol}",
        "lg/route",
        "lg/route/{net}/protocol/{protocol}",
        "lg/route/{net}/table/{table}",
    ],
}

# --- populated oracle leg -------------------------------------------------------
POPULATED_TOPOLOGY = {
    "network": {"ipv4": "198.51.100.0/24", "ipv6": "2001:db8:5100::/64"},
    "route_servers": {
        "oracle": {
            "software": "BIRD 2.0.12 + Bird's Eye 2.1.0",
            "ipv4": "198.51.100.3", "ipv6": "2001:db8:5100::3",
        },
        "live": {
            "software": "rustbgpd + birdwatcher-adapter",
            "ipv4": "198.51.100.1", "ipv6": "2001:db8:5100::1",
        },
    },
    "router_id": "10.0.0.1",
    "asn": 65001,
    "max_routes": 100,
    "protocols": {
        "member-v4": "pb_as64496",
        "member-v6": "pb6_as64496",
        "second-member-v4": "pb_as64497",
        "second-member-v6": "pb6_as64497",
    },
    "announcers": {
        "64496": {
            "ipv4": "198.51.100.2", "ipv6": "2001:db8:5100::2",
            "ipv4_routes": ["203.0.113.0/24", "203.0.113.128/25", "203.0.113.64/26"],
            "ipv6_routes": ["2001:db8:a::/48", "2001:db8:b::/48"],
        },
        "64497": {
            "ipv4": "198.51.100.4", "ipv6": "2001:db8:5100::4",
            "ipv4_routes": ["192.0.2.0/24"],
            "ipv6_routes": ["2001:db8:c::/48"],
        },
    },
}
POPULATED_NORMALIZATION = [
    "timestamps -> <timestamp>",
    "rustbgpd <semver> -> rustbgpd <version>",
    "hold_timer_now and keepalive_now -> <countdown>",
    "each leg's own route-server addresses -> <route-server>",
    "routes sorted by network, symbol lists sorted",
    "route_changes counters -> <counter>",
]
TIMESTAMP = re.compile(
    r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\+00:00)?$|^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$"
)
PRODUCT_VERSION = re.compile(r"^rustbgpd \d+\.\d+\.\d+\S*$")


def mask_counters(value):
    """Keep the shape of BIRD's per-channel route change statistics, drop the
    numbers: they count how many times BIRD processed updates, which depends
    on announcer arrival order."""
    if isinstance(value, dict):
        return {k: mask_counters(v) for k, v in value.items()}
    return "<counter>"


def raw_counters(document):
    """Numeric leaves under any route_changes key: a fixture still carrying
    them is itself a bug."""
    return [
        path for path, value in flatten(document).items()
        if ".route_changes." in path and json_type(value) == "number"
    ]


def normalize_value(value, key, own_addresses):
    if key == "route_changes" and isinstance(value, dict):
        return mask_counters(value)
    if isinstance(value, dict):
        return {k: normalize_value(v, k, own_addresses) for k, v in value.items()}
    if isinstance(value, list):
        items = [normalize_value(v, key, own_addresses) for v in value]
        if key == "routes":
            items.sort(key=lambda route: (route.get("network", ""), json.dumps(route, sort_keys=True)))
        return items
    if key in ("hold_timer_now", "keepalive_now"):
        return "<countdown>"
    if isinstance(value, str):
        if TIMESTAMP.match(value):
            return "<timestamp>"
        if PRODUCT_VERSION.match(value):
            return "rustbgpd <version>"
        if value in own_addresses:
            return "<route-server>"
    return value


def normalize_leg(raw, leg):
    own = set(POPULATED_TOPOLOGY["route_servers"][leg].values())
    journeys = {}
    for name, journey in raw["journeys"].items():
        response = journey["response"]
        if response != "":
            response = normalize_value(json.loads(response), None, own)
            if "symbols" in response:
                response["symbols"] = {k: sorted(v) for k, v in response["symbols"].items()}
        journeys[name] = {"endpoint": journey["endpoint"], "response": response}
    return {
        "provenance": {
            "leg": leg,
            "software": POPULATED_TOPOLOGY["route_servers"][leg]["software"],
            "birdseye_commit": manifest["birdseye_commit"],
            "ixp_manager_commit": raw["ixp_manager_commit"],
            "normalization": POPULATED_NORMALIZATION,
        },
        "journeys": journeys,
    }


def flatten(value, prefix=""):
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            out.update(flatten(v, f"{prefix}.{k}" if prefix else k))
        return out
    if isinstance(value, list):
        out = {}
        for i, v in enumerate(value):
            out.update(flatten(v, f"{prefix}.{i}" if prefix else str(i)))
        return out
    return {prefix: value}


def json_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    return "string"


def journey_diffs(oracle, live):
    """Classified differences for one journey: (path, kind, oracle, live)."""
    if oracle == "" or live == "":
        if oracle == live:
            return []
        return [("<response>", "semantics", oracle, live)]
    flat_oracle = flatten(oracle)
    flat_live = flatten(live)
    diffs = []
    for path in sorted(set(flat_oracle) | set(flat_live)):
        if path not in flat_live:
            diffs.append((path, "missing", flat_oracle[path], None))
        elif path not in flat_oracle:
            diffs.append((path, "extra", None, flat_live[path]))
        elif flat_oracle[path] != flat_live[path]:
            kind = "type" if json_type(flat_oracle[path]) != json_type(flat_live[path]) else "value"
            diffs.append((path, kind, flat_oracle[path], flat_live[path]))
    return diffs


def path_matches(pattern, path, semantics):
    """Segment-wise glob; a semantics entry covers the whole subtree under it."""
    want = pattern.split(".")
    have = path.split(".")
    if len(have) < len(want) or (not semantics and len(have) != len(want)):
        return False
    return all(w in ("*", h) for w, h in zip(want, have))


def entry_matches(entry, endpoint, diff):
    endpoints = entry["endpoint"] if isinstance(entry["endpoint"], list) else [entry["endpoint"]]
    paths = entry["path"] if isinstance(entry["path"], list) else [entry["path"]]
    if "*" not in endpoints and endpoint not in endpoints:
        return False
    semantics = entry["kind"] == "semantics"
    if not semantics and diff[1] != entry["kind"]:
        return False
    return any(path_matches(p, diff[0], semantics) for p in paths)


def check_divergences(oracle_doc, live_doc, entries):
    """Return (unlisted differences, stale entries) after applying the allow-list."""
    unlisted = []
    used = [False] * len(entries)
    for name, journey in oracle_doc["journeys"].items():
        endpoint = journey["endpoint"]
        if live_doc["journeys"][name]["endpoint"] != endpoint:
            fail(f"populated journey {name}: endpoint label drifted between legs")
        for diff in journey_diffs(journey["response"], live_doc["journeys"][name]["response"]):
            matched = False
            for index, entry in enumerate(entries):
                if entry_matches(entry, endpoint, diff):
                    used[index] = True
                    matched = True
            if not matched:
                unlisted.append((name, endpoint) + diff)
    stale = [entry for entry, hit in zip(entries, used) if not hit]
    return unlisted, stale


def parse_birdseye_routes(web_php):
    """Every route literal registered in Bird's Eye routes/web.php, with the
    looking-glass group's prefix applied to the literals inside it."""
    lg_group = web_php.find("'prefix' => 'lg'")
    routes = set()
    for match in re.finditer(r"\$router->get\(\s*'([^']*)'", web_php):
        literal = match.group(1)
        routes.add(f"lg/{literal}" if lg_group != -1 and match.start() > lg_group else literal)
    return routes


def verify_populated(capture_dir: Path, web_php: Path) -> None:
    raw = {
        leg: json.loads((capture_dir / f"populated-{leg}.raw.json").read_text())
        for leg in ("oracle", "live")
    }
    for leg, document in raw.items():
        if document.get("ixp_manager_commit") != manifest["ixp_manager_commit"]:
            fail(f"populated {leg} capture: IXP Manager consumer commit drifted")
    docs = {leg: normalize_leg(document, leg) for leg, document in raw.items()}
    exercised = {j["endpoint"] for j in docs["oracle"]["journeys"].values()}
    if exercised != set(BIRDSEYE_ROUTES["in_scope"]):
        fail(
            "populated journeys do not cover exactly the in-scope endpoints: "
            f"missing={sorted(set(BIRDSEYE_ROUTES['in_scope']) - exercised)} "
            f"unexpected={sorted(exercised - set(BIRDSEYE_ROUTES['in_scope']))}"
        )
    for leg, document in docs.items():
        for name, journey in document["journeys"].items():
            if journey["response"] == "":
                fail(f"populated {leg} capture: {name} returned a collapsed non-2xx response")
    # The deterministic backend-failure journey is captured directly (the
    # pinned consumer collapses every non-2xx to ""), so status and body are
    # asserted here rather than only pinned by the fixture bytes.
    for leg, expected in (
        ("live", {"http_status": 502, "body": {"message": "Upstream daemon request failed"}}),
        ("oracle", {"http_status": 503, "body": {"message": "Error querying bird"}}),
    ):
        observed = docs[leg]["journeys"].get("backend_failure", {}).get("response")
        if observed != expected:
            fail(
                f"backend-failure journey ({leg}): expected {expected}, "
                f"captured {observed}"
            )
    print(
        "backend failure proof: with both backends stopped the adapter answered "
        "HTTP 502 and Bird's Eye HTTP 503, each with its pinned JSON error body",
        file=sys.stderr,
    )
    for leg, document in docs.items():
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        fixture = root / "fixtures" / f"populated-{leg}.json"
        if os.getenv("CAPTURE_FIXTURES") == "1":
            output = Path(os.environ["CAPTURE_OUTPUT"])
            output.mkdir(parents=True, exist_ok=True)
            (output / fixture.name).write_text(text)
        else:
            pinned = fixture.read_text()
            if raw_counters(json.loads(pinned)):
                fail(f"{fixture.name} carries raw route_changes counters; re-capture it")
            if pinned != text:
                sys.stderr.writelines(difflib.unified_diff(
                    pinned.splitlines(True), text.splitlines(True),
                    fromfile=str(fixture), tofile=f"populated-{leg}-capture",
                ))
                fail(f"populated {leg} capture drifted from its fixture")

    unlisted, stale = check_divergences(docs["oracle"], docs["live"], RUNTIME_DIVERGENCES)
    for item in unlisted:
        print(f"unlisted divergence: journey={item[0]} endpoint={item[1]} path={item[2]} "
              f"kind={item[3]} oracle={item[4]!r} live={item[5]!r}", file=sys.stderr)
    if unlisted:
        fail(f"{len(unlisted)} oracle/live difference(s) are not on the runtime divergence allow-list")
    for entry in stale:
        print(f"stale allow-list entry: endpoint={entry['endpoint']} path={entry['path']} "
              f"kind={entry['kind']}", file=sys.stderr)
    if stale:
        fail(f"{len(stale)} runtime divergence allow-list entries no longer match a real difference")
    # The allow-list check proves itself fail-closed on every run: dropping any
    # one entry must surface an unlisted difference, and a bogus entry must be
    # reported stale.
    for index in range(len(RUNTIME_DIVERGENCES)):
        trimmed = RUNTIME_DIVERGENCES[:index] + RUNTIME_DIVERGENCES[index + 1:]
        if not check_divergences(docs["oracle"], docs["live"], trimmed)[0]:
            fail(f"allow-list entry {index} is redundant: removing it surfaces no difference")
    bogus = {"endpoint": "api/status", "path": "status.router_id", "kind": "value"}
    if check_divergences(docs["oracle"], docs["live"], RUNTIME_DIVERGENCES + [bogus])[1] != [bogus]:
        fail("allow-list self-check: a bogus entry was not reported stale")

    routes = parse_birdseye_routes(web_php.read_text())
    pinned = set(BIRDSEYE_ROUTES["in_scope"]) | set(BIRDSEYE_ROUTES["out_of_scope"])
    if routes != pinned:
        fail(
            "pinned Bird's Eye routes/web.php route set differs from scope and out-of-scope: "
            f"new={sorted(routes - pinned)} gone={sorted(pinned - routes)}"
        )
    journeys = len(docs["oracle"]["journeys"])
    breakdown = ", ".join(
        f"{sum(1 for e in RUNTIME_DIVERGENCES if e['classification'] == c)} {c}"
        for c in CLASSIFICATIONS
    )
    print(
        f"populated oracle proof: {journeys} journeys over {len(BIRDSEYE_ROUTES['in_scope'])} "
        f"endpoints diffed BIRD 2.0.12 + Bird's Eye against rustbgpd + adapter; "
        f"{len(RUNTIME_DIVERGENCES)} allow-listed divergences ({breakdown}), 0 unlisted, 0 stale; "
        f"{len(routes)} pinned routes/web.php routes accounted for",
        file=sys.stderr,
    )


def fail(message: str) -> None:
    raise SystemExit(message)


root = Path(__file__).resolve().parent
manifest = json.loads((root / "contract.json").read_text())
open_must_match = []
for entry in manifest.get("runtime_divergences", []):
    classification = entry.get("classification")
    if classification not in CLASSIFICATIONS:
        fail(
            f"runtime divergence entry endpoint={entry.get('endpoint')} "
            f"path={entry.get('path')} carries missing or unknown classification "
            f"{classification!r}; expected one of {list(CLASSIFICATIONS)}"
        )
    if classification == "must_match":
        open_must_match.append(f"{entry.get('endpoint')} {entry.get('path')}")
if manifest.get("runtime_compatibility") is not False and open_must_match:
    fail(
        f"runtime_compatibility cannot be promoted with {len(open_must_match)} "
        "open must_match divergence(s): " + "; ".join(open_must_match)
    )
if manifest.get("runtime_compatibility") is not False:
    fail("contract oracle must not promote a runtime compatibility claim")
if set(manifest.get("unsupported", [])) != UNSUPPORTED:
    fail("unsupported compatibility matrix drifted")
if set(manifest.get("runtime_supported", [])) != RUNTIME_SUPPORTED:
    fail("supported runtime matrix drifted")
if manifest.get("adapter_api_version") != ADAPTER_API_VERSION:
    fail("adapter api.version must remain an honest product identity")
if manifest.get("filtered_prefix_query") != FILTERED_PREFIX_QUERY:
    fail("filtered-prefix namespace drifted")
if manifest.get("live_session_detail") != LIVE_SESSION_DETAIL:
    fail("live session-detail contract drifted")
if manifest.get("filtered_retention_metadata") != FILTERED_RETENTION_METADATA:
    fail("filtered retention completeness contract drifted")
if manifest.get("reject_reasons") != REJECT_REASONS:
    fail("pinned reject-reason display or active partition drifted")
if manifest.get("manual_config_export") != MANUAL_CONFIG_EXPORT:
    fail("strict manual v2 export contract drifted")
if manifest.get("nagios_monitoring") != NAGIOS_MONITORING:
    fail("pinned Nagios monitoring contract drifted")
if manifest.get("populated_topology") != POPULATED_TOPOLOGY:
    fail("populated oracle topology drifted")
if manifest.get("birdseye_routes") != BIRDSEYE_ROUTES:
    fail("pinned Bird's Eye route scope drifted")
if manifest.get("runtime_divergences") != RUNTIME_DIVERGENCES:
    fail("runtime divergence allow-list drifted")
consumer_source = (root / "config-consumer.php").read_text()
for required in [
    "$router->template = 'api/v4/router/server/bird2/standard';",
    "whereIn('id', [32, 33])->update(['enabled' => 1]);",
    "substr_count($birdCandidate, $prepend) - substr_count($birdBaseline, $prepend) !== 3",
    "substr_count($birdCandidate, $peerGuard) - substr_count($birdBaseline, $peerGuard) !== 1",
    "$globalPosition >= $specificPosition",
    "$birdBaseline,",
    "$birdCandidate,",
]:
    if required not in consumer_source:
        fail(f"pinned in-memory BIRD path-first proof drifted: {required}")
if manifest.get("protocol_aliases") != {
    "member-v4": "pb_as64496",
    "member-v4-reloaded": "pb_reloaded_as64496",
}:
    fail("explicit protocol alias matrix drifted")
if manifest.get("routing_tables") != ["master4"]:
    fail("live routing-table identity drifted")

if sys.argv[1] == "--nagios":
    # The live-adapter leg writes this after both pinned Nagios generators and
    # the pinned daemon plugin ran; a missing or drifted file means the step
    # did not execute, which is exactly the silent failure under test.
    summary = json.loads(Path(sys.argv[2]).read_text())
    handle = MANUAL_CONFIG_EXPORT["router_handle"]
    if summary.get("router_handle") != handle:
        fail("nagios capture: router handle drifted")
    if f"host_name               bird-{handle}\n" not in summary.get("daemon_host", ""):
        fail("nagios capture: birdseye-daemons host stanza omitted the router")
    if summary.get("session_protocols") != ["pb_0001_as1213", "pb_0004_as112"]:
        fail("nagios capture: birdseye-bgp-sessions client protocols drifted")
    if not re.fullmatch(
        r"OK: Bird rustbgpd \S+\. Bird's Eye rustbgpd \S+\. Router ID \S+\. "
        r"Uptime: \d+ days\. Last Reconfigure: \d{4}-\d\d-\d\d \d\d:\d\d:\d\d\."
        r"0 BGP sessions up of 1\.",
        summary.get("daemon_check", ""),
    ):
        fail("nagios capture: pinned nagios-check-birdseye.php line drifted")
    if not summary.get("last_reconfig"):
        fail("nagios capture: daemon check Last Reconfigure is empty")
    sys.exit(0)

if sys.argv[1] == "--populated":
    verify_populated(Path(sys.argv[2]), Path(sys.argv[3]))
    sys.exit(0)

capture = Path(sys.argv[1])
if len(sys.argv) == 3:
    config_capture = Path(sys.argv[2])
    default_asns = MANUAL_CONFIG_EXPORT["no_transit"]["default_asns"]
    no_transit_cases = {
        "config-default.json": ("IXP_MANAGER_EFFECTIVE_DEFAULT", default_asns),
        "config-default-excluded.json": (
            "IXP_MANAGER_EFFECTIVE_DEFAULT", default_asns[2:],
        ),
        "config-default-all-excluded.json": ("IXP_MANAGER_EFFECTIVE_DEFAULT", []),
        "config-explicit-empty.json": ("IXP_NO_TRANSIT_ASNS_OVERRIDE", []),
        "config-explicit-nonempty.json": (
            "IXP_NO_TRANSIT_ASNS_OVERRIDE", [64511, 64512],
        ),
        "config-implicit.json": ("IXP_MANAGER_IMPLICIT_DEFAULT", []),
    }
    for name, (source, asns) in no_transit_cases.items():
        policy = json.loads((config_capture / name).read_text())["policy"]["no_transit"]
        if policy != {"source": source, "asns": asns}:
            fail(f"{name}: effective no-transit capture drifted")
    full = json.loads((config_capture / "config-ui-filter.json").read_text())
    supported = json.loads(
        (config_capture / "ixp-manager-v7.4-rustbgpd.json").read_text()
    )
    for name, document, filters in [
        ("full", full, FULL_UI_FILTERS),
        ("row-31-disabled", supported, SUPPORTED_UI_FILTERS),
    ]:
        if document.get("schema") != MANUAL_CONFIG_EXPORT["schema"]:
            fail(f"{name} UI-filter capture schema drifted")
        if document.get("ui_filters") != filters:
            fail(f"{name} UI-filter capture row objects drifted")
        if document.get("complete", {}).get("ui_filter_count") != len(filters):
            fail(f"{name} UI-filter capture completion count drifted")
        if document.get("unsupported", {}).get("active_ui_filters") != []:
            fail(f"{name} UI-filter capture retained a v1 refusal marker")

responses = {}
for name, expected_status in EXPECTED.items():
    body_path = capture / f"{name}.body"
    meta_path = capture / f"{name}.meta"
    if not body_path.is_file() or not meta_path.is_file():
        fail(f"required case silently skipped: {name}")
    metadata = meta_path.read_text().splitlines()
    if len(metadata) != 2:
        fail(f"{name}: incomplete HTTP metadata capture")
    status = int(metadata[0])
    content_type = metadata[1]
    if status != expected_status:
        fail(f"{name}: expected HTTP {expected_status}, got {status}")
    expected_content_type = "application/json"
    if content_type != expected_content_type:
        fail(f"{name}: expected Content-Type {expected_content_type!r}, got {content_type!r}")
    body = body_path.read_text()
    if status == 200:
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as error:
            fail(f"{name}: HTTP 200 body is not JSON: {error}; body={body[:160]!r}")
        api = parsed.get("api", {})
        leaked = {"env", "cache_disabled", "ip_whitelisted"} & set(api)
        if leaked:
            fail(f"{name}: production response leaked debug-only API keys: {sorted(leaked)}")
    responses[name] = {"status": status, "content_type": content_type, "body": body}

actual = json.dumps(
    {
        "provenance": {
            "birdseye_commit": manifest["birdseye_commit"],
            "license": "MIT",
            "source": "https://github.com/inex/birdseye",
            "synthetic_data": "RFC 5737 and RFC 5398 documentation values",
        },
        "responses": responses,
    },
    indent=2,
    sort_keys=True,
) + "\n"
fixture = root / "fixtures" / "birdseye-contract.json"
if os.getenv("CAPTURE_FIXTURES") == "1":
    output = Path(os.environ["CAPTURE_OUTPUT"])
    output.mkdir(parents=True, exist_ok=True)
    (output / fixture.name).write_text(actual)
    sys.exit(0)

expected = fixture.read_text()
if actual != expected:
    sys.stderr.writelines(difflib.unified_diff(
        expected.splitlines(True), actual.splitlines(True),
        fromfile=str(fixture), tofile="live-birdseye-capture",
    ))
    fail("pinned Bird's Eye contract drifted")
