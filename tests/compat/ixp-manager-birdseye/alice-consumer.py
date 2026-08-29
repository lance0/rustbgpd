#!/usr/bin/env python3
"""Bounded Alice-LG consumer proof for the populated adapter oracle leg."""

import json
import sys
import urllib.error
import urllib.parse
import urllib.request


def fail(message):
    raise SystemExit(f"alice consumer mismatch: {message}")


def get_json(base, path):
    try:
        with urllib.request.urlopen(base + path, timeout=5) as response:
            if response.status != 200:
                fail(f"{path} answered HTTP {response.status}")
            return json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        fail(f"{path} could not be decoded: {error}")


def routes_path(peer, kind):
    return f"/routeservers/rs0/neighbors/{urllib.parse.quote(peer, safe='')}/routes/{kind}"


def route_key(route):
    return route.get("network"), tuple(route.get("bgp", {}).get("as_path", []))


def nested_label(document, section, community):
    value = document.get(section, {})
    for component in community.split(":"):
        if not isinstance(value, dict) or component not in value:
            fail(f"{section} omitted full key {community}")
        value = value[component]
    if not isinstance(value, str):
        fail(f"{section} label for {community} is not a string")
    return value


def main():
    if len(sys.argv) != 2:
        fail("usage: alice-consumer.py BASE_URL")
    base = sys.argv[1].rstrip("/")

    status = get_json(base, "/status")
    if status.get("version") != "6.2.0":
        fail(f"expected Alice-LG 6.2.0, got {status.get('version')!r}")

    config = get_json(base, "/config")
    if config.get("prefix_lookup_enabled") is not False:
        fail("prefix lookup must remain disabled")
    if config.get("noexport", {}).get("load_on_demand") is not True:
        fail("noexport must be load-on-demand")
    reject_labels = {
        0: "Unrecognized rejection reason",
        1: "Denied by import policy",
        2: "Only-to-Customer role leak",
        3: "NEXT_HOP is not the peer address",
        4: "Receiver AS appears in AS_PATH",
        5: "Route-reflection loop",
        6: "Malformed attribute treatment",
    }
    noexport_labels = {
        0: "Unrecognized export suppression",
        1: "Route originated from the target peer",
        2: "Route-reflection rules",
        3: "Address family not negotiated",
        4: "Long-lived stale route",
        5: "Outbound route filter",
        6: "RT membership",
        7: "Denied by export policy",
    }
    for reason, label in reject_labels.items():
        actual = nested_label(config, "reject_reasons", f"64496:65520:{reason}")
        if actual != label:
            fail(f"rejection label {reason} drifted: {actual!r}")
    for reason, label in noexport_labels.items():
        actual = nested_label(config, "noexport_reasons", f"64496:65521:{reason}")
        if actual != label:
            fail(f"noexport label {reason} drifted: {actual!r}")

    route_servers = get_json(base, "/routeservers").get("routeservers")
    if not isinstance(route_servers, list) or [item.get("id") for item in route_servers] != ["rs0"]:
        fail(f"expected exactly route server rs0, got {route_servers!r}")
    if route_servers[0].get("group") != "rustbgpd-contract":
        fail(f"route server group drifted: {route_servers[0]!r}")

    neighbors = get_json(base, "/routeservers/rs0/neighbors").get("neighbors")
    if not isinstance(neighbors, list):
        fail("neighbors is not an array")
    expected_peers = {
        "pb_as64496",
        "pb6_as64496",
        "pb_as64497",
        "pb6_as64497",
    }
    by_id = {neighbor.get("id"): neighbor for neighbor in neighbors}
    if set(by_id) != expected_peers:
        fail(f"neighbor IDs drifted: {sorted(str(value) for value in by_id)}")
    down = sorted(peer for peer, neighbor in by_id.items() if neighbor.get("state") != "up")
    if down:
        fail(f"neighbors not up: {down}")

    expected_routes = {
        "pb_as64496": {
            ("203.0.113.0/24", (64496, 64510, 64520)),
            ("203.0.113.128/25", (64496,)),
            ("203.0.113.64/26", (64496,)),
        },
        "pb6_as64496": {
            ("2001:db8:a::/48", (64496, 64510)),
            ("2001:db8:b::/48", (64496,)),
        },
        "pb_as64497": {("192.0.2.0/24", (64497,))},
        "pb6_as64497": {("2001:db8:c::/48", (64497, 64530))},
    }
    accepted_total = 0
    for peer in sorted(expected_peers):
        received = get_json(base, routes_path(peer, "received")).get("imported")
        if not isinstance(received, list):
            fail(f"{peer} accepted response omitted imported array")
        actual = {route_key(route) for route in received}
        if len(actual) != len(received) or actual != expected_routes[peer]:
            fail(f"{peer} accepted route set drifted: {sorted(actual)!r}")
        accepted_total += len(received)

        filtered = get_json(base, routes_path(peer, "filtered")).get("filtered")
        if filtered != []:
            fail(f"{peer} filtered view must be empty, got {filtered!r}")
    if accepted_total != 7:
        fail(f"expected 7 accepted routes, got {accepted_total}")

    noexport = get_json(base, routes_path("pb_as64497", "not-exported")).get("not_exported")
    if not isinstance(noexport, list) or len(noexport) != 1:
        fail(f"expected one deterministic split-horizon route, got {noexport!r}")
    route = noexport[0]
    if route_key(route) != ("192.0.2.0/24", (64497,)):
        fail(f"split-horizon route identity drifted: {route!r}")
    large = route.get("bgp", {}).get("large_communities", [])
    if [64496, 65521, 1] not in large:
        fail(f"split-horizon community missing from {large!r}")

    print(
        "alice consumer proof: Alice-LG 6.2.0 read rs0 with 4 up neighbors, "
        "7 accepted routes, 0 filtered routes, and the labeled split-horizon noexport route"
    )


if __name__ == "__main__":
    main()
