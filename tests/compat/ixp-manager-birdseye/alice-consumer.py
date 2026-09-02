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


def lookup(base, prefix):
    document = get_json(base, "/lookup/prefix?q=" + urllib.parse.quote(prefix, safe=""))
    imported = document.get("imported", {}).get("routes")
    filtered = document.get("filtered", {}).get("routes")
    if not isinstance(imported, list) or not isinstance(filtered, list):
        fail(f"lookup {prefix} omitted the imported/filtered route arrays")
    return imported, filtered


def lookup_key(route):
    return (
        route.get("network"),
        route.get("state"),
        route.get("neighbor", {}).get("id"),
        route.get("routeserver", {}).get("id"),
    )


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
    filtered_flag_invalid = len(sys.argv) == 4 and sys.argv[3] != "--filtered-peer"
    if len(sys.argv) not in (3, 4) or filtered_flag_invalid:
        fail("usage: alice-consumer.py BASE_URL EXPECTED_VERSION [--filtered-peer]")
    base = sys.argv[1].rstrip("/")
    expected_version = sys.argv[2]
    filtered_peer = len(sys.argv) == 4

    status = get_json(base, "/status")
    if status.get("version") != expected_version:
        fail(f"expected Alice-LG {expected_version}, got {status.get('version')!r}")
    store_totals = status.get("routes", {}).get("total_routes", {})
    expected_totals = {"imported": 7, "filtered": 2 if filtered_peer else 0}
    if store_totals != expected_totals:
        fail(f"routes store totals drifted: {store_totals!r}")

    config = get_json(base, "/config")
    if config.get("prefix_lookup_enabled") is not True:
        fail("prefix lookup must be enabled")
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
    if filtered_peer:
        expected_peers.add("pb_as64498")
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
    for peer in sorted(expected_routes):
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

    if filtered_peer:
        received = get_json(base, routes_path("pb_as64498", "received")).get("imported")
        if received != []:
            fail(f"pb_as64498 accepted view must be empty, got {received!r}")
        filtered = get_json(base, routes_path("pb_as64498", "filtered")).get("filtered")
        if not isinstance(filtered, list) or len(filtered) != 2:
            fail(f"pb_as64498 must expose exactly two filtered routes, got {filtered!r}")
        expected_rejections = {
            ("198.18.0.0/24", (64498, 65001)): (4, "Receiver AS appears in AS_PATH"),
            ("198.18.1.0/24", (64498,)): (1, "Denied by import policy"),
        }
        if {route_key(route) for route in filtered} != set(expected_rejections):
            fail(f"pb_as64498 filtered route identities drifted: {filtered!r}")
        for route in filtered:
            reason_id, label = expected_rejections[route_key(route)]
            reject_community = [64496, 65520, reason_id]
            large = route.get("bgp", {}).get("large_communities")
            if large != [reject_community]:
                fail(f"pb_as64498 rejection community drifted: {large!r}")
            reason = nested_label(
                config,
                "reject_reasons",
                ":".join(str(component) for component in reject_community),
            )
            if reason != label:
                fail(f"pb_as64498 rejection label drifted: {reason!r}")

    noexport = get_json(base, routes_path("pb_as64497", "not-exported")).get("not_exported")
    if not isinstance(noexport, list) or len(noexport) != 1:
        fail(f"expected one deterministic split-horizon route, got {noexport!r}")
    route = noexport[0]
    if route_key(route) != ("192.0.2.0/24", (64497,)):
        fail(f"split-horizon route identity drifted: {route!r}")
    large = route.get("bgp", {}).get("large_communities", [])
    if [64496, 65521, 1] not in large:
        fail(f"split-horizon community missing from {large!r}")

    # Global prefix lookup reads Alice's routes store, filled from the
    # adapter's /routes/table/<table> and /routes/table/<table>/filtered dumps.
    imported, filtered = lookup(base, "192.0.2.0/24")
    if [lookup_key(route) for route in imported] != [
        ("192.0.2.0/24", "imported", "pb_as64497", "rs0")
    ]:
        fail(f"accepted prefix lookup drifted: {imported!r}")
    if filtered != []:
        fail(f"accepted prefix lookup must find no filtered route, got {filtered!r}")
    expected_lookups = {
        "198.18.0.0/24": [64496, 65520, 4],
        "198.18.1.0/24": [64496, 65520, 1],
    }
    for prefix, community in expected_lookups.items():
        imported, filtered = lookup(base, prefix)
        if imported != []:
            fail(f"{prefix} lookup must find no accepted route, got {imported!r}")
        if not filtered_peer:
            if filtered != []:
                fail(f"{prefix} lookup must be empty before the fifth peer, got {filtered!r}")
            continue
        if [lookup_key(route) for route in filtered] != [(prefix, "filtered", "pb_as64498", "rs0")]:
            fail(f"{prefix} filtered lookup drifted: {filtered!r}")
        large = filtered[0].get("bgp", {}).get("large_communities")
        if large != [community]:
            fail(f"{prefix} filtered lookup community drifted: {large!r}")

    if filtered_peer:
        print(
            f"alice filtered proof: Alice-LG {expected_version} read rs0 with 5 up neighbors, "
            "preserved 7 accepted routes and 4 empty baseline filtered views, joined an "
            "AS-path-loop and an import-policy rejection to their exact labels, and found "
            "both through prefix lookup"
        )
    else:
        print(
            f"alice consumer proof: Alice-LG {expected_version} read rs0 with 4 up neighbors, "
            "7 accepted routes, 0 filtered routes, the labeled split-horizon noexport route, "
            "and one accepted prefix-lookup hit"
        )


if __name__ == "__main__":
    main()
