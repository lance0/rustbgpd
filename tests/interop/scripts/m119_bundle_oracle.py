#!/usr/bin/env python3
"""Replay M119 vendor RIB, imported state, kernel and fresh-ARP observations."""

import json
from pathlib import Path
import sys

LOCAL_MAC = "02:aa:bb:01:19:01"
REMOTE_MAC = "02:aa:bb:01:19:02"
LOCAL_VTEP = "10.0.119.1"
REMOTE_VTEP = "192.0.2.2"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(directory, name):
    return json.loads((directory / name).read_text())


def fdb(text, tags=(10, 20)):
    rows = [line.lower().split() for line in text.splitlines()]
    remote = [r for r in rows if r and r[0] == REMOTE_MAC]
    flood = [r for r in rows if r and r[0] == "00:00:00:00:00:00"]
    require(len([r for r in rows if "extern_learn" in r]) == 3 * len(tags),
            "unexpected managed FDB row")
    require(len(remote) == 2 * len(tags), "remote MAC FDB inventory differs")
    require(len(flood) == len(tags), "IMET flood FDB inventory differs")
    for tag in tags:
        dev = f"vxlan{10000 + tag}"
        selected = [r for r in remote if "dev" in r and r[r.index("dev") + 1] == dev]
        master = [r for r in selected if "master" in r and "vlan" in r
                  and r[r.index("master") + 1] == "brbundle"
                  and r[r.index("vlan") + 1] == str(tag) and "extern_learn" in r]
        tunnel = [r for r in selected if "self" in r and "dst" in r
                  and r[r.index("dst") + 1] == REMOTE_VTEP and "extern_learn" in r]
        require(len(selected) == 2 and len(master) == len(tunnel) == 1,
                f"tag {tag} lacks its VLAN master and VXLAN destination")
        owned = [r for r in flood if "dev" in r and r[r.index("dev") + 1] == dev
                 and "dst" in r and r[r.index("dst") + 1] == REMOTE_VTEP
                 and "self" in r and "extern_learn" in r]
        require(len(owned) == 1, f"tag {tag} lacks its owned IMET flood row")


def neighbors(directory, tag):
    for side, destination, mac in (("vtep", 2, REMOTE_MAC), ("client", 1, LOCAL_MAC)):
        rows = read(directory, f"{side}-h{tag}-neighbors.json")
        require(len(rows) == 1, f"{side} tag {tag} neighbor inventory differs")
        row = rows[0]
        require((row.get("dst"), row.get("dev"), row.get("lladdr")) ==
                (f"198.18.{tag}.{destination}", f"host{tag}", mac),
                f"{side} tag {tag} learned wrong neighbor")
        require(set(row.get("state", [])) in ({"REACHABLE"}, {"STALE"}, {"DELAY"}, {"PROBE"}),
                f"{side} tag {tag} neighbor was not dynamically resolved")


def srl_rib(observation, local_tags=(10, 20), remote_tags=(10, 20)):
    rib = observation["network-instance"][0]["bgp-rib"]
    families = [f for f in rib["afi-safi"] if f["afi-safi-name"] == "evpn"]
    require(len(families) == 1, "missing unique EVPN AFI/SAFI")
    routes = families[0]["evpn"]["local-rib"]
    require(set(routes) == {"mac-ip-route", "imet-route"}, "unexpected EVPN route type")
    attributes = rib["attr-sets"]["attr-set"]
    attrs = {a["index"]: a for a in attributes}
    require(len(attrs) == len(attributes), "duplicate attribute-set index")
    for kind in ("mac-ip-route", "imet-route"):
        expected = []
        for local, tags in ((True, local_tags if kind == "mac-ip-route" else (10, 20)),
                            (False, remote_tags)):
            vtep = LOCAL_VTEP if local else REMOTE_VTEP
            for tag in tags:
                rd = f"{vtep}:{tag if local else 100 + (tag == 20)}"
                matches = [r for r in routes[kind] if r["route-distinguisher"] == rd
                           and r["ethernet-tag-id"] == tag]
                require(len(matches) == 1, f"{kind} {rd} tag {tag} inventory differs")
                row = matches[0]
                expected.append(row)
                require(row["neighbor"] == (LOCAL_VTEP if local else "0.0.0.0")
                        and row["path-id"] == 0 and row["valid-route"]
                        and row["best-route"] and not row["stale-route"]
                        and not row["pending-delete"], f"{kind} {rd} route is not live and best")
                attr = attrs[row["attr-id"]]
                require(attr["next-hop"] == vtep, f"{kind} {rd} next hop differs")
                communities = attr["communities"]["ext-community"]
                require([c for c in communities if c.startswith("target:")] == ["target:65000:100"],
                        f"{kind} {rd} RT differs")
                require([c for c in communities if c.startswith("bgp-tunnel-encap:")] ==
                        ["bgp-tunnel-encap:VXLAN"], f"{kind} {rd} encapsulation differs")
                if kind == "mac-ip-route":
                    require(row["mac-length"] == 48 and row["mac-address"].lower() ==
                            (LOCAL_MAC if local else REMOTE_MAC)
                            and row["ip-address"] == "0.0.0.0"
                            and row["esi"] == "00:00:00:00:00:00:00:00:00:00"
                            and row["label1"] == {"value": 10000 + tag, "value-type": "vni"}
                            and "label2" not in row, f"{kind} {rd} NLRI differs")
                else:
                    require(row["originating-router"] == vtep, f"{kind} {rd} originator differs")
                    require(attr["pmsi-tunnel"] == {
                        "tunnel-type": "ingress-replication", "tunnel-endpoint": vtep,
                        "label": {"value": 10000 + tag, "value-type": "vni"}},
                        f"{kind} {rd} PMSI differs")
        require(len(routes[kind]) == len(expected), f"extra {kind} routes")


def imported(directory, local_tags=(10, 20), active_tags=(10, 20)):
    tunnels = read(directory, "srl-tunnels.json")["tunnel-interface"]
    require(len(tunnels) == 1 and tunnels[0]["name"] == "vxlan1", "unexpected tunnel interface")
    members = tunnels[0]["vxlan-interface"]
    require(sorted(r["index"] for r in members) == [10, 20], "unexpected VXLAN member inventory")
    for tag in (10, 20):
        networks = read(directory, f"srl-bd{tag}.json")["network-instance"]
        require(len(networks) == 1 and networks[0]["name"] == f"bd{tag}", "wrong MAC-VRF snapshot")
        macs = networks[0]["bridge-table"].get("mac-table", {}).get("mac", [])
        evpn = [m for m in macs if m["type"].startswith("evpn")]
        expected = int(tag in local_tags and tag in active_tags)
        require(len(evpn) == expected, f"bd{tag} EVPN MAC inventory differs")
        if expected:
            row = evpn[0]
            require(row["address"].lower() == LOCAL_MAC and row["type"] == "evpn"
                    and row["destination-type"] == "vxlan"
                    and row["destination"] ==
                    f"vxlan-interface:vxlan1.{tag} vtep:{LOCAL_VTEP} vni:{10000 + tag}"
                    and "not-programmed-reason" not in row, f"bd{tag} MAC destination differs")
        member = next(r for r in members if r["index"] == tag)
        require(member["ingress"]["vni"] == 10000 + tag and member["oper-state"] == "up",
                f"VXLAN member {tag} is not ready")
        destinations = member.get("bridge-table", {}).get("multicast-destinations", {}).get("destination", [])
        require(len(destinations) == int(tag in active_tags), f"tag {tag} flood inventory differs")
        if destinations:
            row = destinations[0]
            require((row["vtep"], row["vni"], row["multicast-forwarding"]) ==
                    (LOCAL_VTEP, 10000 + tag, "BUM") and "not-programmed-reason" not in row,
                    f"tag {tag} flood destination differs")



def daemon_rib(rows, local_tags=(10, 20), remote_tags=(10, 20)):
    expected = []
    for local, tags in ((True, local_tags), (False, remote_tags)):
        vtep = LOCAL_VTEP if local else REMOTE_VTEP
        for kind in (2, 3):
            for tag in ((10, 20) if local and kind == 3 else tags):
                wanted = {"route_type": kind, "rd": f"{vtep}:{tag if local else 100 + (tag == 20)}",
                          "ethernet_tag": str(tag), "next_hop": vtep,
                          "peer": "0.0.0.0" if local else "10.0.119.2", "tunnel_type": 8,
                          "mac": (LOCAL_MAC if local else REMOTE_MAC) if kind == 2 else "",
                          "ip": "" if kind == 2 else vtep, "label": 10000 + tag if kind == 2 else 0,
                          "label2": 0, "esi": "00:00:00:00:00:00:00:00:00:00" if kind == 2 else ""}
                matches = [r for r in rows if all(r.get(k) == v for k, v in wanted.items())]
                require(len(matches) == 1, f"daemon route differs: {wanted}")
                communities = matches[0]["extended_communities"]
                require([c for c in communities if (c >> 48) in (2, 258, 514)] == [842122827661412]
                        and communities.count(219550481834311688) == 1, "daemon RT or encapsulation differs")
                expected.extend(matches)
    require(len(rows) == len(expected), "extra daemon EVPN route")


def state(directory, mode="full"):
    local_tags = (20,) if mode == "local-withdrawn" else (10, 20)
    remote_tags = (20,) if mode == "remote-withdrawn" else (10, 20)
    daemon_rib(read(directory, "routes.json"), local_tags, remote_tags)
    srl_rib(read(directory, "srl-rib.json"), local_tags, remote_tags)
    imported(directory, local_tags, remote_tags)
    fdb((directory / "fdb.txt").read_text(), remote_tags)
    instances = read(directory, "instances.json")
    require(sorted(r["vni"] for r in instances) == [10010, 10020], "member inventory differs")
    for row in instances:
        require(row["service_interface"] == "vlan_aware_bundle"
                and row["ethernet_tag"] == row["vni"] - 10000 and row["readiness"] == "ready"
                and not any(r["count"] for r in row["remote_route_drop_counts"]), "member not ready or has drops")


def no_flap(directory):
    observations = sorted(directory.rglob("peer.json"))
    require(len(observations) == 15, "missing or extra session phases")
    transitions = set()
    for path in observations:
        peer = json.loads(path.read_text())
        require(peer["state"] == "Established" and peer["flap_count"] == 0
                and peer["notifications_received"] == peer["notifications_sent"] == 0,
                f"daemon session flapped in {path.parent.name}")
        srl = read(path.parent, "srl-peer.json")["network-instance"][0]["protocols"]["bgp"]["neighbor"][0]
        require(srl["session-state"] == "established", "SR Linux session is not established")
        transitions.add(srl["established-transitions"])
    require(len(transitions) == 1, "SR Linux session flapped")


def replay(directory):
    for phase, mode in (("initial", "full"), ("remote-withdrawn", "remote-withdrawn"),
                        ("remote-restored", "full"), ("local-withdrawn", "local-withdrawn"),
                        ("final", "full")):
        state(directory / phase, mode)
    for phase, tags in (("forwarding", (10, 20)), ("isolated", (20,)), ("restored", (10, 20))):
        for tag in tags:
            for destination in (1, 2):
                result = (directory / phase / f"ping-{tag}-to-{destination}.txt").read_text()
                require(f"PING 198.18.{tag}.{destination} " in result and
                        "3 packets transmitted, 3 received, 0% packet loss" in result,
                        f"{phase} tag {tag} to {destination} ping did not fully succeed")
                snapshot = directory / phase / f"{tag}-to-{destination}"
                for side in ("vtep", "client"):
                    for member in (10, 20):
                        require(read(snapshot, f"before-{side}-h{member}-neighbors.json") == [],
                                f"{phase} ping started with a cached or static neighbor")
                neighbors(snapshot, tag)
                state(snapshot, "remote-withdrawn" if phase == "isolated" else "full")
    initial_fdb = sorted((directory / "initial/fdb.txt").read_text().splitlines())
    require(initial_fdb == sorted((directory / "final/fdb.txt").read_text().splitlines()),
            "complete FDB inventory differs after restore")
    no_flap(directory)


def main():
    directory = Path(sys.argv[1])
    mode = sys.argv[2] if len(sys.argv) > 2 else "full"
    if mode == "replay":
        replay(directory)
    elif mode == "neighbors":
        neighbors(directory, int(sys.argv[3]))
    elif mode == "no-flap":
        no_flap(directory)
    elif mode in ("full", "local-withdrawn", "remote-withdrawn"):
        state(directory, mode)
    else:
        raise ValueError(f"unknown assertion {mode}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, IndexError, TypeError) as error:
        print(f"M119 assertion failed: {error}", file=sys.stderr)
        sys.exit(1)
