#!/usr/bin/env python3
"""M120 daemon, kernel and SR Linux state proof; packet checks run separately.

Capture kernel-routes.json with `ip -j route show table all` and
kernel-neighbors.json with `ip -j neigh show` to retain table/device identity.
"""

from copy import deepcopy
from ipaddress import IPv4Address, IPv4Network
import json
from pathlib import Path
import re
import sys

import m119_bundle_oracle as l2

LOCAL_VTEP = "10.0.119.1"
REMOTE_VTEP = "192.0.2.2"
LOCAL_ROUTER_MAC = "02:00:00:01:20:01"
REMOTE_RD = "192.0.2.2:50120"
DEVICE = "l3vxlan50120"
ZERO_ESI = "00:00:00:00:00:00:00:00:00:00"
CONNECTED = ("198.18.10.0/24", "198.18.20.0/24")
LOCAL_PREFIXES = (*CONNECTED, "198.19.121.0/24", "198.19.124.0/24")
REMOTE_PREFIXES = (*CONNECTED, "198.19.120.0/24", "198.19.120.2/32",
                   "198.19.123.0/24", "198.19.123.2/32")
WITHDRAWN_PREFIXES = ("198.19.120.0/24", "198.19.120.2/32")
RT = (2 << 48) | (65000 << 32) | 50120
VXLAN = 0x030C000000000008

require = l2.require
read = l2.read


def remote_prefixes(mode):
    require(mode in ("full", "remote-withdrawn"), f"unknown phase {mode}")
    return tuple(p for p in REMOTE_PREFIXES
                 if mode != "remote-withdrawn" or p not in WITHDRAWN_PREFIXES)


def daemon_l3(rows, remote_mac, mode="full"):
    prefixes = remote_prefixes(mode)
    routes = [row for row in rows if row["route_type"] == 5]
    require(len(routes) == len(LOCAL_PREFIXES) + len(prefixes), "Type 5 inventory differs")
    for local, expected in ((True, LOCAL_PREFIXES), (False, prefixes)):
        vtep = LOCAL_VTEP if local else REMOTE_VTEP
        router_mac = LOCAL_ROUTER_MAC if local else remote_mac
        rd = f"{LOCAL_VTEP}:50120" if local else REMOTE_RD
        rmac = (0x0603 << 48) | int(router_mac.replace(":", ""), 16)
        for prefix in expected:
            matches = [r for r in routes if r["rd"] == rd and r["prefix"] == prefix]
            require(len(matches) == 1, f"Type 5 {rd} {prefix} missing or duplicate")
            row = matches[0]
            wanted = {"ethernet_tag": "0", "esi": ZERO_ESI, "gateway": "0.0.0.0",
                      "label": 50120, "label2": 0, "tunnel_type": 8, "next_hop": vtep,
                      "peer": "0.0.0.0" if local else "10.0.119.2", "mac": "", "ip": ""}
            require(all(row.get(k) == v for k, v in wanted.items()), f"Type 5 {rd} {prefix} fields differ")
            communities = row["extended_communities"]
            require([c for c in communities if c >> 48 in (2, 258, 514)] == [RT],
                    f"Type 5 {rd} {prefix} RT differs")
            require([c for c in communities if c >> 48 == 0x030C] == [VXLAN],
                    f"Type 5 {rd} {prefix} encapsulation differs")
            require([c for c in communities if c >> 48 == 0x0603] == [rmac],
                    f"Type 5 {rd} {prefix} Router MAC differs")


def tenant_table(row):
    value = row.get("table")
    return (type(value) is int and value == 50120) or (type(value) is str and value == "50120")


def kernel_prefix(row):
    prefix = row.get("dst")
    require(isinstance(prefix, str), "tenant route destination must be an IPv4 string")
    network = IPv4Network("0.0.0.0/0" if prefix == "default" else prefix, strict=True)
    require(prefix == "default" or prefix == str(network)
            or (network.prefixlen == 32 and prefix == str(network.network_address)),
            "tenant route destination must be canonical CIDR, a bare host or default")
    return network


def kernel_routes(rows, mode="full"):
    # The foreign-prefix guard preserves local connected routes even though
    # the peer advertises those same prefixes as Type 5 routes.
    prefixes = tuple(p for p in remote_prefixes(mode) if p not in CONNECTED)
    for tag in (10, 20):
        connected = [r for r in rows if tenant_table(r)
                     and r.get("dst") == f"198.18.{tag}.0/24" and r.get("protocol") == "kernel"]
        require(len(connected) == 1 and connected[0].get("dev") == f"svi{tag}"
                and connected[0].get("scope") == "link" and "gateway" not in connected[0],
                f"local connected member {tag} was lost or redirected")
    owned = [r for r in rows if tenant_table(r) and r.get("protocol") == "bgp"]
    require(sorted(str(kernel_prefix(r)) for r in owned) == sorted(prefixes), "tenant BGP route inventory differs")
    for row in owned:
        require(row.get("gateway") == REMOTE_VTEP and row.get("dev") == DEVICE
                and "onlink" in row.get("flags", [])
                and row.get("type", "unicast") == "unicast"
                and "nhid" not in row and "nexthops" not in row,
                f"wrong tenant route destination: {row}")
    probes = (IPv4Address("198.19.120.2"), IPv4Address("198.19.123.2"))
    for row in rows:
        if not tenant_table(row):
            continue
        network = kernel_prefix(row)
        if network.prefixlen >= 24 and any(probe in network for probe in probes):
            require(row in owned, f"tenant competing route covers probe: {row['dst']}")
    for prefix in set(REMOTE_PREFIXES) - set(CONNECTED):
        aliases = (prefix, prefix.removesuffix("/32"))
        matches = [r for r in rows if r.get("dst") in aliases]
        require(len(matches) == int(prefix in prefixes)
                and all(r in owned for r in matches), f"remote-only prefix leaked or survived withdrawal: {prefix}")


def kernel_neighbor(rows, remote_mac):
    selected = [r for r in rows if r.get("dev") == DEVICE]
    require(len(selected) == 1, "L3VXLAN neighbor inventory differs")
    row = selected[0]
    require(row.get("dst") == REMOTE_VTEP and row.get("lladdr", "").lower() == remote_mac
            and row.get("state") == ["PERMANENT"] and row.get("extern_learn", False) is None
            and row.get("protocol") == "bgp", "wrong or unowned L3VXLAN neighbor")


def device(row):
    return row[row.index("dev") + 1] if "dev" in row else None


def kernel_fdb(text, remote_mac):
    rows = [line.lower().split() for line in text.splitlines() if line.strip()]
    layer3 = [r for r in rows if device(r) == DEVICE]
    destinations = [r for r in layer3 if "dst" in r]
    require(len(destinations) == 1, "L3VXLAN FDB destination inventory differs")
    row = destinations[0]
    require(row[0] == remote_mac and row[row.index("dst") + 1] == REMOTE_VTEP
            and "self" in row and "extern_learn" in row and "master" not in row,
            "wrong or unowned L3VXLAN FDB destination")
    require([r for r in layer3 if "extern_learn" in r] == destinations,
            "unexpected managed L3VXLAN FDB row")
    # The L3 device is independently checked above. Pass every other row to
    # M119 so its managed-row census also rejects unrelated extra MACs.
    subset = [r for r in rows if device(r) != DEVICE]
    l2.fdb("\n".join(" ".join(r) for r in subset))


def daemon_l2(rows, instances, irb_macs, *, local_host_ips=None):
    require(set(irb_macs) == {10, 20}, "independent IRB member inventory differs")
    require(all(row["route_type"] in (2, 3, 5) for row in rows), "unexpected EVPN route type")
    subset = [r for r in rows if r["route_type"] in (2, 3)]
    irb_rows = []
    for tag, mac in irb_macs.items():
        for ip in ("", f"198.18.{tag}.253"):
            wanted = {"route_type": 2, "rd": f"{REMOTE_VTEP}:{100 + (tag == 20)}",
                      "ethernet_tag": str(tag), "mac": mac, "ip": ip,
                      "esi": ZERO_ESI, "label": 10000 + tag, "label2": 0,
                      "next_hop": REMOTE_VTEP, "peer": "10.0.119.2", "tunnel_type": 8}
            matches = [r for r in subset if all(r.get(k) == v for k, v in wanted.items())]
            require(len(matches) == 1, f"daemon IRB Type 2 differs: {wanted}")
            communities = matches[0]["extended_communities"]
            require([c for c in communities if c >> 48 in (2, 258, 514)] == [842122827661412]
                    and [c for c in communities if c >> 48 == 0x030C] == [VXLAN],
                    f"daemon IRB Type 2 tag {tag} RT or encapsulation differs")
            irb_rows.extend(matches)
    l2.daemon_rib([r for r in subset if r not in irb_rows], local_host_ips=local_host_ips)
    require(sorted(row["vni"] for row in instances) == [10010, 10020], "bundle member inventory differs")
    for row in instances:
        tag = row["vni"] - 10000
        require(row["ethernet_tag"] == row["bridge_vlan"] == tag
                and row["bridge"] == "brbundle" and row["service_interface"] == "vlan_aware_bundle"
                and row["route_targets"] == ["65000:100"] and row["readiness"] == "ready"
                and not any(drop["count"] for drop in row["remote_route_drop_counts"]),
                f"bundle member {tag} is not ready or changed identity")


def ip_vrf(row, mode="full"):
    wanted = {"name": "tenant", "vni": 50120, "rd": f"{LOCAL_VTEP}:50120",
              "route_targets": ["65000:50120"], "local_vtep_ip": LOCAL_VTEP,
              "router_mac": LOCAL_ROUTER_MAC, "vrf_device": "tenant", "l3vxlan_device": DEVICE,
              "table_id": 50120, "readiness": "ready", "not_ready_reasons": [],
              "originated_routes_count": len(LOCAL_PREFIXES),
              "installed_routes_count": len(set(remote_prefixes(mode)) - set(CONNECTED))}
    require(all(row.get(k) == v for k, v in wanted.items()), "IP-VRF identity, readiness or route count differs")
    require(all(drop["reason"] == "self_originated" or drop["count"] == 0
                for drop in row["remote_prefix_drop_counts"]), "unexpected IP-VRF projection drop")


def remote_router_mac(observation):
    tunnels = [r for r in observation["tunnel-interface"] if r["name"] == "vxlan1"]
    require(len(tunnels) == 1, "missing unique SR Linux tunnel interface")
    members = [r for r in tunnels[0]["vxlan-interface"] if r["index"] == 50120]
    require(len(members) == 1, "missing unique SR Linux L3VXLAN member")
    require(members[0]["type"] == "routed" and members[0]["oper-state"] == "up"
            and members[0]["ingress"]["vni"] == 50120, "SR Linux L3VXLAN identity or readiness differs")
    mac = members[0]["egress"]["inner-ethernet-header"]["used-source-mac"]
    require(isinstance(mac, str), "SR Linux Router MAC is missing")
    mac = mac.lower()
    require(re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac) is not None,
            "SR Linux Router MAC is malformed")
    require(int(mac.replace(":", ""), 16) != 0 and int(mac[:2], 16) & 1 == 0,
            "SR Linux Router MAC must be non-zero unicast")
    return mac


def effective_config(config, unlinked=False):
    members = config["evpn_instances"]
    require(sorted(r["vni"] for r in members) == [10010, 10020], "effective bundle inventory differs")
    for row in members:
        tag = row["vni"] - 10000
        require(row["ethernet_tag"] == tag and row["service_interface"] == "vlan_aware_bundle",
                f"effective member {tag} changed identity")
        if unlinked and tag == 10:
            require("ip_vrf" not in row, "member 10 remains linked in unlinked phase")
        else:
            require(row.get("ip_vrf") == "tenant", f"effective member {tag} lost tenant binding")
    vrfs = config["evpn_ip_vrfs"]
    require(len(vrfs) == 1 and vrfs[0]["name"] == "tenant" and vrfs[0]["vni"] == 50120
            and vrfs[0]["overlay_index_mode"] == "interface_less", "effective tenant overlay mode differs")
    require(config.get("ethernet_segments", []) == [], "effective config added an Ethernet Segment")


def runtime(row):
    require(row["lifecycle"] == "active" and row["evpn_instances_count"] == 2
            and row["evpn_ip_vrfs_count"] == 1 and row["ethernet_segments_count"] == 0
            and row["ethernet_segment_member_vnis_count"] == 0, "runtime is not active with two single-homed members")
    require(type(row["generation"]) is int and row["generation"] >= 0, "invalid runtime generation")
    return row["generation"]


def session(directory):
    peer = read(directory, "peer.json")
    require(peer["address"] == "10.0.119.2" and peer["state"] == "Established"
            and peer["flap_count"] == peer["notifications_received"] == peer["notifications_sent"] == 0,
            f"daemon session failed in {directory.name}")
    networks = read(directory, "srl-peer.json")["network-instance"]
    require(len(networks) == 1 and networks[0]["name"] == "default", "wrong SR Linux peer network")
    peers = networks[0]["protocols"]["bgp"]["neighbor"]
    require(len(peers) == 1 and peers[0]["peer-address"] == LOCAL_VTEP
            and peers[0]["session-state"] == "established", f"SR Linux session failed in {directory.name}")
    transitions = int(peers[0]["established-transitions"])
    require(transitions > 0, "SR Linux session has never established")
    return transitions


# Observed in pinned 25.10.1: referenced Type 5 attributes and the resolved
# tenant NH -> default tunnel NH chain, not nearby unrelated RIB values.
SRL_ROUTER_MAC_COMMUNITY_PREFIX = "mac-nh:"
SRL_IFL_NEXT_HOP_TYPE = "indirect"


def vendor_unique(rows, field, value, context):
    selected = [row for row in rows if row.get(field) == value]
    require(len(selected) == 1, f"{context}: {field}={value!r} is missing or duplicated")
    return selected[0]


def vendor_network(observation, name):
    return vendor_unique(observation["network-instance"], "name", name, "network instance")


def vendor_fib_programmed(row, context, *, group=False):
    # Pinned 25.10.1 omits suppressed on NHGs. Route objects must provide
    # it explicitly; both object types must provide completed programming.
    programming = row["fib-programming"]
    require(programming.get("suppressed", False) is False if group else programming["suppressed"] is False,
            f"{context}: FIB suppressed")
    require(programming["pending-operation-type"] == "none", f"{context}: FIB pending")
    require(programming["last-successful-operation-type"] in ("add", "modify"),
            f"{context}: no successful FIB install")
    # last-failed-operation-type records history, so an old failed attempt
    # must not invalidate a later successful install by itself.


def vendor_l3_rib(observation, remote_mac, mode="full"):
    require(SRL_ROUTER_MAC_COMMUNITY_PREFIX is not None,
            "bind the Router MAC community prefix from a pinned live SR Linux snapshot")
    rib = vendor_network(observation, "default")["bgp-rib"]
    family = vendor_unique(rib["afi-safi"], "afi-safi-name", "evpn", "BGP family")
    rows = family["evpn"]["local-rib"]["ip-prefix-route"]
    attr_rows = rib["attr-sets"]["attr-set"]
    attrs = {row["index"]: row for row in attr_rows}
    require(len(attrs) == len(attr_rows), "duplicate BGP attribute-set index")
    expected_srl = remote_prefixes(mode)
    require(len(rows) == len(LOCAL_PREFIXES) + len(expected_srl), "vendor Type 5 inventory differs")
    for from_rust, prefixes in ((True, LOCAL_PREFIXES), (False, expected_srl)):
        rd = f"{LOCAL_VTEP}:50120" if from_rust else REMOTE_RD
        vtep = LOCAL_VTEP if from_rust else REMOTE_VTEP
        mac = LOCAL_ROUTER_MAC if from_rust else remote_mac
        for prefix in prefixes:
            selected = [row for row in rows if row["route-distinguisher"] == rd
                        and row["ip-prefix"] == prefix]
            require(len(selected) == 1, f"vendor Type 5 {rd} {prefix} missing or duplicated")
            row = selected[0]
            require(row["ethernet-tag-id"] == 0 and row["ip-prefix-length"] == IPv4Network(prefix).prefixlen
                    and row["neighbor"] == (LOCAL_VTEP if from_rust else "0.0.0.0")
                    and row["path-id"] == 0 and row["esi"] == ZERO_ESI
                    and row["gateway-ip"] == "0.0.0.0"
                    and row["label"] == {"value": 50120, "value-type": "vni"},
                    f"vendor Type 5 {rd} {prefix} NLRI differs")
            require(row["valid-route"] is True and row["best-route"] is True
                    and row["stale-route"] is False and row["pending-delete"] is False,
                    f"vendor Type 5 {rd} {prefix} is not live and best")
            if from_rust:
                require(row["imported-network-instances"] == ["tenant"],
                        f"vendor Type 5 {rd} {prefix} imported into wrong tenant")
                if prefix not in CONNECTED:
                    require(row["used-route"] is True and row.get("fib-disabled", False) is False,
                            f"vendor Type 5 {rd} {prefix} is not used")
            attr = attrs[row["attr-id"]]
            require(attr["next-hop"] == vtep, f"vendor Type 5 {rd} {prefix} next hop differs")
            communities = attr["communities"]["ext-community"]
            require([c for c in communities if c.startswith("target:")] == ["target:65000:50120"],
                    f"vendor Type 5 {rd} {prefix} RT differs")
            require([c for c in communities if c.startswith("bgp-tunnel-encap:")] ==
                    ["bgp-tunnel-encap:VXLAN"], f"vendor Type 5 {rd} {prefix} encapsulation differs")
            require([c.lower() for c in communities
                     if c.lower().startswith(SRL_ROUTER_MAC_COMMUNITY_PREFIX.lower())] ==
                    [SRL_ROUTER_MAC_COMMUNITY_PREFIX.lower() + mac.lower()],
                    f"vendor Type 5 {rd} {prefix} Router MAC differs")


def vendor_l3_fib(tenant_observation, default_observation):
    require(SRL_IFL_NEXT_HOP_TYPE is not None, "bind the pinned SR Linux IFL next-hop type")
    tenant = vendor_network(tenant_observation, "tenant")
    default = vendor_network(default_observation, "default")
    networks = {"tenant": tenant, "default": default}
    routes = tenant["route-table"]["ipv4-unicast"]["route"]
    expected_remote = {"198.19.121.0/24", "198.19.124.0/24"}
    active_evpn = [r for r in routes if r["active"] is True and r["route-type"] == "bgp-evpn"]
    require({r["ipv4-prefix"] for r in active_evpn} == expected_remote
            and len(active_evpn) == len(expected_remote), "vendor active EVPN prefix inventory differs")
    probes = (IPv4Address("198.19.121.1"), IPv4Address("198.19.124.1"))
    for route in routes:
        prefix = route.get("ipv4-prefix")
        require(isinstance(prefix, str), "vendor IPv4 prefix must be a CIDR string")
        network = IPv4Network(prefix, strict=True)
        require(str(network) == prefix, "vendor IPv4 prefix must be canonical CIDR")
        # A foreign /32 or equal-prefix route can divert the reverse probe
        # even while the expected EVPN /24 remains present and programmed.
        if (route["active"] is True and network.prefixlen >= 24
                and any(probe in network for probe in probes)):
            require(route in active_evpn, f"vendor competing route covers reverse probe: {prefix}")
    for route in active_evpn:
        require(route["route-owner"] == "bgp_evpn_mgr" and route["origin-network-instance"] == "tenant",
                "vendor route owner or origin differs")
        vendor_fib_programmed(route, "vendor EVPN route")
        ni = route.get("next-hop-group-network-instance", "tenant")
        require(ni in networks, "unobserved next-hop-group network instance")
        table = networks[ni]["route-table"]
        group = vendor_unique(table["next-hop-group"], "index", route["next-hop-group"], "route NHG")
        vendor_fib_programmed(group, "vendor EVPN NHG", group=True)
        require(group["backup-active"] is False, "vendor route uses backup NHG")
        require(len(group["next-hop"]) == 1, "vendor IFL route has unexpected next-hop fanout")
        member = group["next-hop"][0]
        require(member["resolved"] == "true"
                and member["resource-allocation-failed"] is False, "vendor NHG member unavailable")
        hop = vendor_unique(table["next-hop"], "index", member["next-hop"], "NHG next hop")
        require(hop["type"] == SRL_IFL_NEXT_HOP_TYPE, "vendor next-hop type differs")
        require(hop["resource-allocation-failed"] is False, "vendor next-hop allocation failed")
        require(hop["ip-address"] == LOCAL_VTEP, "vendor remote VTEP differs")
        require(hop["vxlan-encapsulation"] == {
            "vni": 50120, "interface": "vxlan1", "destination-mac": LOCAL_ROUTER_MAC},
            "vendor next hop uses wrong VNI, VXLAN interface, or Router MAC")
        indirect = hop["indirect"]
        require(indirect["resolved"] is True, "vendor indirect next hop is unresolved")
        resolver = indirect["resolving-tunnel"]
        require(resolver["ip-prefix"] == f"{LOCAL_VTEP}/32"
                and resolver["tunnel-type"] == "vxlan" and resolver["tunnel-owner"] == "vxlan_mgr"
                and type(resolver["tunnel-id"]) is int and resolver["tunnel-id"] > 0,
                "vendor indirect resolver identity differs")
        underlay = default["route-table"]
        tunnel_group = vendor_unique(underlay["next-hop-group"], "index", resolver["next-hop-group"],
                                     "resolved tunnel NHG")
        vendor_fib_programmed(tunnel_group, "resolved tunnel NHG", group=True)
        require(tunnel_group["backup-active"] is False and len(tunnel_group["next-hop"]) == 1,
                "resolved tunnel NHG uses backup or unexpected fanout")
        terminal_member = tunnel_group["next-hop"][0]
        require(terminal_member["resolved"] == "not-applicable"
                and terminal_member["resource-allocation-failed"] is False,
                "resolved tunnel NHG member unavailable")
        terminal = vendor_unique(underlay["next-hop"], "index", terminal_member["next-hop"],
                                 "resolved tunnel next hop")
        require(terminal["type"] == "tunnel" and terminal["resource-allocation-failed"] is False
                and type(terminal["tunnel"]["tunnel-id"]) is int
                and terminal["tunnel"] == {"ip-prefix": resolver["ip-prefix"], "type": "vxlan",
                                           "owner": "vxlan_mgr", "tunnel-id": resolver["tunnel-id"],
                                           "network-instance": "default"}
                and terminal["vxlan-encapsulation"] == {"vni": 0, "destination-mac": "00:00:00:00:00:00"},
                "resolved terminal tunnel identity differs")
    # Export-only withdrawal must leave the SR Linux endpoint and both shared
    # member subnets installed locally. It must not make the ping fail merely
    # by deleting its destination address.
    endpoints = [(p, "local") for p in (*CONNECTED, "198.19.120.0/24", "198.19.123.0/24")]
    endpoints.extend((p, "host") for p in ("198.19.120.2/32", "198.19.123.2/32"))
    for prefix, kind in endpoints:
        candidates = [r for r in routes if r["ipv4-prefix"] == prefix and r["active"] is True]
        require(len(candidates) == 1 and candidates[0]["route-type"] == kind
                and candidates[0]["route-owner"] == "net_inst_mgr"
                and candidates[0]["origin-network-instance"] == "tenant",
                f"vendor connected prefix {prefix} missing or redirected")
        vendor_fib_programmed(candidates[0], f"vendor connected prefix {prefix}")


def vendor_l3_state(directory, mode="full"):
    mac = remote_router_mac(read(directory, "srl-tunnels.json"))
    vendor_l3_rib(read(directory, "srl-rib.json"), mac, mode)
    vendor_l3_fib(read(directory, "srl-tenant.json"), read(directory, "srl-default-fib.json"))


def vendor_irb_macs(directory):
    tenant = vendor_network(read(directory, "srl-tenant.json"), "tenant")
    macs = {}
    for tag in (10, 20):
        interface = vendor_unique(tenant["interface"], "name", f"irb0.{tag}", "tenant IRB interface")
        require(interface["oper-state"] == "up", f"tenant IRB member {tag} is down")
        bd = vendor_network(read(directory, f"srl-bd{tag}.json"), f"bd{tag}")
        row = vendor_unique(bd["bridge-table"]["mac-table"]["mac"], "type", "irb-interface",
                            f"bd{tag} IRB MAC")
        require(row["destination-type"] == row["destination"] == "irb-interface"
                and row["is-protected"] is True and "not-programmed-reason" not in row,
                f"bd{tag} IRB MAC is not an installed protected interface")
        require(isinstance(row["address"], str), f"bd{tag} IRB MAC is not a string")
        mac = row["address"].lower()
        require(re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac) is not None
                and int(mac.replace(":", ""), 16) != 0 and int(mac[:2], 16) & 1 == 0,
                f"bd{tag} IRB MAC is not non-zero unicast")
        macs[tag] = mac
    return macs


def vendor_l2_rib(observation, irb_macs, *, local_host_ips=None):
    # Type 5 is independently checked by vendor_l3_rib. Validate the full
    # inventory before passing precisely the Type 2/3 subset to M119.
    subset = deepcopy(observation)
    rib = vendor_network(subset, "default")["bgp-rib"]
    family = vendor_unique(rib["afi-safi"], "afi-safi-name", "evpn", "vendor EVPN family")
    routes = family["evpn"]["local-rib"]
    require(set(routes) == {"mac-ip-route", "imet-route", "ip-prefix-route"},
            "unexpected combined vendor EVPN route inventory")
    require(set(irb_macs) == {10, 20}, "independent IRB member inventory differs")
    attributes = rib["attr-sets"]["attr-set"]
    attrs = {row["index"]: row for row in attributes}
    require(len(attrs) == len(attributes), "duplicate BGP attribute-set index")
    irb_rows = []
    for tag, mac in irb_macs.items():
        for ip in ("0.0.0.0", f"198.18.{tag}.253"):
            matches = [r for r in routes["mac-ip-route"]
                       if r["route-distinguisher"] == f"{REMOTE_VTEP}:{100 + (tag == 20)}"
                       and r["ethernet-tag-id"] == tag and r["mac-address"].lower() == mac
                       and r["ip-address"] == ip]
            require(len(matches) == 1, f"vendor IRB Type 2 tag {tag} IP {ip} inventory differs")
            row = matches[0]
            require(row["mac-length"] == 48 and row["esi"] == ZERO_ESI
                    and row["label1"] == {"value": 10000 + tag, "value-type": "vni"}
                    and "label2" not in row and row["neighbor"] == "0.0.0.0" and row["path-id"] == 0
                    and row["valid-route"] is True and row["best-route"] is True
                    and row["stale-route"] is False and row["pending-delete"] is False,
                    f"vendor IRB Type 2 tag {tag} NLRI or path differs")
            attr = attrs[row["attr-id"]]
            communities = attr["communities"]["ext-community"]
            require(attr["next-hop"] == REMOTE_VTEP
                    and [c for c in communities if c.startswith("target:")] == ["target:65000:100"]
                    and [c for c in communities if c.startswith("bgp-tunnel-encap:")] ==
                    ["bgp-tunnel-encap:VXLAN"], f"vendor IRB Type 2 tag {tag} attributes differ")
            irb_rows.extend(matches)
    routes["mac-ip-route"] = [r for r in routes["mac-ip-route"] if r not in irb_rows]
    del routes["ip-prefix-route"]
    l2.srl_rib({"network-instance": [{"name": "default", "bgp-rib": rib}]},
               local_host_ips=local_host_ips)


def vendor_l2_imported(directory):
    tunnels = read(directory, "srl-tunnels.json")["tunnel-interface"]
    require(len(tunnels) == 1 and tunnels[0]["name"] == "vxlan1", "unexpected tunnel interface")
    members = tunnels[0]["vxlan-interface"]
    require(sorted(r["index"] for r in members) == [10, 20, 50120],
            "unexpected combined VXLAN member inventory")
    for tag in (10, 20):
        networks = read(directory, f"srl-bd{tag}.json")["network-instance"]
        require(len(networks) == 1 and networks[0]["name"] == f"bd{tag}", "wrong MAC-VRF snapshot")
        macs = networks[0]["bridge-table"].get("mac-table", {}).get("mac", [])
        evpn = [m for m in macs if m["type"].startswith("evpn")]
        require(len(evpn) == 1, f"bd{tag} EVPN MAC inventory differs")
        row = evpn[0]
        require(row["address"].lower() == l2.LOCAL_MAC and row["type"] == "evpn"
                and row["destination-type"] == "vxlan"
                and row["destination"] ==
                f"vxlan-interface:vxlan1.{tag} vtep:{LOCAL_VTEP} vni:{10000 + tag}"
                and "not-programmed-reason" not in row, f"bd{tag} MAC destination differs")
        member = next(r for r in members if r["index"] == tag)
        require(member["ingress"]["vni"] == 10000 + tag and member["oper-state"] == "up",
                f"VXLAN member {tag} is not ready")
        destinations = member.get("bridge-table", {}).get("multicast-destinations", {}).get("destination", [])
        require(len(destinations) == 1, f"tag {tag} flood inventory differs")
        row = destinations[0]
        require((row["vtep"], row["vni"], row["multicast-forwarding"]) ==
                (LOCAL_VTEP, 10000 + tag, "BUM") and "not-programmed-reason" not in row,
                f"tag {tag} flood destination differs")



PHASES = ("startup", "initial", "remote-withdrawn", "restored", "rejected-reload", "unlinked", "relinked", "final")


def state(directory, mode="full"):
    require(directory.name in PHASES, "unknown M120 phase")
    # Warmup ARP replaces each local MAC-only NLRI with its configured host
    # MAC/IP NLRI. Require that handoff in every later phase on both peers.
    local_host_ips = {tag: "" if directory.name == "startup" else f"198.18.{tag}.1"
                      for tag in (10, 20)}
    effective_config(read(directory, "effective-config.json"), directory.name == "unlinked")
    runtime(read(directory, "runtime.json"))
    session(directory)
    remote_mac = remote_router_mac(read(directory, "srl-tunnels.json"))
    irb_macs = vendor_irb_macs(directory)
    rows = read(directory, "routes.json")
    daemon_l3(rows, remote_mac, mode)
    daemon_l2(rows, read(directory, "instances.json"), irb_macs, local_host_ips=local_host_ips)
    kernel_routes(read(directory, "kernel-routes.json"), mode)
    kernel_neighbor(read(directory, "kernel-neighbors.json"), remote_mac)
    kernel_fdb((directory / "fdb.txt").read_text(), remote_mac)
    ip_vrf(read(directory, "ip-vrf.json"), mode)
    vendor_l3_state(directory, mode)
    vendor_l2_rib(read(directory, "srl-rib.json"), irb_macs, local_host_ips=local_host_ips)
    vendor_l2_imported(directory)


def capture_witness(text, remote_mac):
    """Require the complete routed probe before stopping the live capture."""
    rows = [line.split("\t") for line in text.splitlines()]
    require(all(len(row) == 7 for row in rows), "incomplete capture witness row")
    requests = [row for row in rows if row[2:5] == ["198.18.10.1", "198.19.120.2", "8"]]
    require(len(requests) == 3, "capture has not observed exactly three probe requests")
    require(sorted(row[6] for row in requests) == ["1", "2", "3"],
            "capture probe sequences differ")
    identifiers = {row[5] for row in requests}
    require(len(identifiers) == 1 and next(iter(identifiers)).isdigit(),
            "capture probe ICMP identifiers differ or are missing")
    require(all(row[0] == "50120" and row[1].lower() == remote_mac for row in requests),
            "capture probe VNI or inner Router MAC differs")


def replay(directory):
    generation = runtime(read(directory / "initial", "runtime.json"))
    transitions = set()
    for phase in PHASES:
        phase_dir = directory / phase
        state(phase_dir, "remote-withdrawn" if phase == "remote-withdrawn" else "full")
        increment = 2 if phase in ("relinked", "final") else int(phase == "unlinked")
        require(runtime(read(phase_dir, "runtime.json")) == generation + increment,
                f"wrong committed generation in {phase}")
        transitions.add(session(phase_dir))
    require(len(transitions) == 1, "SR Linux session re-established during receipt")
    initial = sorted(json.dumps(row, sort_keys=True) for row in read(directory / "initial", "routes.json"))
    final = sorted(json.dumps(row, sort_keys=True) for row in read(directory / "final", "routes.json"))
    require(initial == final, "complete EVPN RIB changed across withdrawal, reload and restore")
    require(sorted((directory / "initial/fdb.txt").read_text().splitlines()) ==
            sorted((directory / "final/fdb.txt").read_text().splitlines()),
            "complete FDB inventory changed across withdrawal and restore")


if __name__ == "__main__":
    try:
        directory = Path(sys.argv[1])
        mode = sys.argv[2] if len(sys.argv) > 2 else "full"
        if mode == "capture-witness":
            capture_witness((directory / "capture-witness.tsv").read_text(),
                            remote_router_mac(read(directory / "initial", "srl-tunnels.json")))
        elif mode == "replay":
            replay(directory)
        else:
            state(directory, mode)
    except (ValueError, KeyError, IndexError, TypeError, OSError) as error:
        print(f"M120 daemon/kernel assertion failed: {error}", file=sys.stderr)
        sys.exit(1)
