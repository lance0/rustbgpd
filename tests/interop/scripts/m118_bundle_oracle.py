#!/usr/bin/env python3
"""Fixed M118 decoded-wire, FDB and drop-snapshot assertions."""

import json
from pathlib import Path
import sys

LOCAL_MAC = "02:aa:bb:01:18:01"
REMOTE_MAC = "02:aa:bb:01:18:02"
NEGATIVE_MACS = [f"02:aa:bb:01:ee:{n:02x}" for n in (1, 2, 3)]
VTEP = "10.0.118.1"
PEER = "10.0.118.2"


def originated(rib, tags=(10, 20)):
    for tag in (10, 20):
        vni = 10000 + tag
        rd = {"type": 1, "admin": VTEP, "assigned": tag}
        mac_key = f"[type:macadv][rd:{VTEP}:{tag}][etag:{tag}][mac:{LOCAL_MAC}]"
        imet_key = f"[type:multicast][rd:{VTEP}:{tag}][etag:{tag}][ip:{VTEP}]"
        for key, route_type, value in (
            (mac_key, 2, {"rd": rd, "esi": "single-homed", "etag": tag,
                       "mac": LOCAL_MAC, "labels": [vni]}),
            (imet_key, 3, {"rd": rd, "etag": tag, "ip": VTEP}),
        ):
            if route_type == 2 and tag not in tags:
                if key in rib:
                    raise ValueError(f"withdrawn local tag {tag} still advertised")
                continue
            paths = rib.get(key, [])
            if len(paths) != 1 or paths[0]["nlri"] != {"type": route_type, "value": value}:
                raise ValueError(f"decoded NLRI differs for {key}")
            attrs = paths[0]["attrs"]
            mp_reach = [a for a in attrs if a["type"] == 14]
            if len(mp_reach) != 1 or (
                    mp_reach[0].get("afi"), mp_reach[0].get("safi"), mp_reach[0].get("nexthop")) != (25, 70, VTEP):
                raise ValueError(f"EVPN MP_REACH next hop differs for {key}")
            rts = [c["value"] for a in attrs if a["type"] == 16
                   for c in a["value"] if c["type"] in (0, 1, 2) and c["subtype"] == 2]
            if rts != ["65000:100"]:
                raise ValueError(f"bundle RT differs for {key}")
            encaps = [c["tunnel_type"] for a in attrs if a["type"] == 16
                      for c in a["value"] if c["type"] == 3 and c["subtype"] == 12]
            if encaps != [8]:
                raise ValueError(f"VXLAN encapsulation differs for {key}")
            if key == imet_key:
                pmsi = [a for a in attrs if a["type"] == 22]
                if len(pmsi) != 1 or any(pmsi[0].get(k) != v for k, v in {
                    "label": vni, "tunnel-type": 6, "tunnel-id": VTEP,
                    "is-leaf-info-required": False,
                }.items()):
                    raise ValueError(f"IMET member VNI/tunnel differs for tag {tag}")
    if sum(LOCAL_MAC in key for key in rib) != len(tags):
        raise ValueError("local MAC has the wrong number of per-member route keys")


def fdb(text, tags=(10, 20)):
    rows = [line.split() for line in text.lower().splitlines()]
    if any(row and row[0] in NEGATIVE_MACS for row in rows):
        raise ValueError("unsupported route installed an FDB row")
    remote_rows = [row for row in rows if row and row[0] == REMOTE_MAC]
    if len(remote_rows) != 2 * len(tags):
        raise ValueError("remote MAC has an unexpected FDB row inventory")
    for tag in (10, 20):
        dev = f"vxlan{10000 + tag}"
        selected = [r for r in remote_rows if "dev" in r and r[r.index("dev") + 1] == dev]
        if tag not in tags:
            if selected:
                raise ValueError(f"withdrawn tag {tag} still has FDB rows")
            continue
        master = [r for r in selected if "master" in r and "vlan" in r
                  and r[r.index("master") + 1] == "brbundle"
                  and r[r.index("vlan") + 1] == str(tag) and "extern_learn" in r]
        tunnel = [r for r in selected if "self" in r and "dst" in r
                  and r[r.index("dst") + 1] == PEER and "extern_learn" in r]
        if len(selected) != 2 or len(master) != 1 or len(tunnel) != 1:
            raise ValueError(f"tag {tag} lacks its exact VLAN master + VXLAN destination rows")


def retained(routes):
    expected = [
        {"route_type": 2, "rd": f"{PEER}:301", "ethernet_tag": "30",
         "label": 10010, "mac": NEGATIVE_MACS[0]},
        {"route_type": 2, "rd": f"{PEER}:302", "ethernet_tag": "10",
         "label": 10030, "mac": NEGATIVE_MACS[1]},
        {"route_type": 2, "rd": f"{PEER}:303", "ethernet_tag": "10",
         "label": 10010, "mac": NEGATIVE_MACS[2], "esi": "00:01:02:03:04:05:06:07:08:09"},
        {"route_type": 1, "rd": f"{PEER}:304", "ethernet_tag": "10",
         "label": 10010, "esi": "00:01:02:03:04:05:06:07:08:09"},
        {"route_type": 5, "rd": f"{PEER}:500", "ethernet_tag": "10",
         "label": 10500, "prefix": "203.0.118.0/24"},
    ]
    for wanted in expected:
        matches = [r for r in routes if r.get("peer") == PEER
                   and all(r.get(k) == v for k, v in wanted.items())]
        if len(matches) != 1:
            raise ValueError(f"unsupported input not observed intact in the RIB: {wanted}")


def drops(instances, vrfs, negative=True):
    members = {row["vni"]: row for row in instances}
    for tag in (10, 20):
        row = members[10000 + tag]
        if (row["service_interface"], row["ethernet_tag"], row["readiness"]) != (
                "vlan_aware_bundle", tag, "ready"):
            raise ValueError(f"bundle member {tag} status differs")
        expected = {"ethernet_tag_mismatch": 1, "vni_mismatch": 1,
                    "multihoming_unsupported": 2} if negative and tag == 10 else {}
        counts = {r["reason"]: r["count"] for r in row["remote_route_drop_counts"] if r["count"]}
        if counts != expected:
            raise ValueError(f"member {tag} drop snapshot differs: {counts}")
    control = [row for row in vrfs if row["name"] == "negative"]
    if len(control) != 1:
        raise ValueError("missing Type 5 control VRF")
    counts = {r["reason"]: r["count"] for r in control[0]["remote_prefix_drop_counts"] if r["count"]}
    expected = {"non_zero_ethernet_tag": 1} if negative else {}
    if control[0]["readiness"] != "ready" or counts != expected or control[0]["installed_routes_count"] != 0:
        raise ValueError(f"Type 5 negative was not isolated to its drop reason: {counts}")


def main():
    mode = sys.argv[1]
    if mode == "originated":
        if len(sys.argv) > 3 and sys.argv[3] != "withdrawn":
            raise ValueError("expected withdrawn local advertisement assertion")
        originated(json.loads(Path(sys.argv[2]).read_text()), (20,) if len(sys.argv) > 3 else (10, 20))
    elif mode == "fdb":
        if len(sys.argv) > 3 and sys.argv[3] != "withdrawn":
            raise ValueError("expected withdrawn FDB assertion")
        fdb(Path(sys.argv[2]).read_text(), (20,) if len(sys.argv) > 3 else (10, 20))
    elif mode == "drops":
        if len(sys.argv) > 4 and sys.argv[4] != "zero":
            raise ValueError("expected zero drop baseline assertion")
        drops(*(json.loads(Path(p).read_text()) for p in sys.argv[2:4]), negative=len(sys.argv) == 4)
    elif mode == "retained":
        retained(json.loads(Path(sys.argv[2]).read_text()))
    else:
        raise ValueError(f"unknown assertion {mode}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, IndexError, TypeError) as error:
        print(f"M118 assertion failed: {error}", file=sys.stderr)
        sys.exit(1)
