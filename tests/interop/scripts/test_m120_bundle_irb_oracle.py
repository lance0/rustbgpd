#!/usr/bin/env python3
"""Self-contained counterexamples for M120 daemon and kernel evidence."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import m120_bundle_irb_oracle as oracle

REMOTE_MAC = "02:00:00:01:20:02"
IRB_MACS = {10: "02:00:00:01:20:41", 20: "02:00:00:01:20:41"}
FIXTURE_RMAC_PREFIX = "fixture-router-mac:"
FIXTURE_NH_TYPE = "fixture-ifl-next-hop"


def vendor_snapshot():
    """Synthetic schema fixture; these strings are not vendor observations."""
    routes = []
    attributes = []
    for rust, vtep, mac, suffixes in (
        (True, "10.0.119.1", "02:00:00:01:20:01", (121, 124)),
        (False, "192.0.2.2", REMOTE_MAC, (120, 123)),
    ):
        prefixes = ["198.18.10.0/24", "198.18.20.0/24", *(f"198.19.{s}.0/24" for s in suffixes)]
        if not rust:
            prefixes.extend(f"198.19.{s}.2/32" for s in suffixes)
        for prefix in prefixes:
            index = len(attributes) + 1
            attributes.append({"index": index, "next-hop": vtep, "communities": {"ext-community": [
                "target:65000:50120", "bgp-tunnel-encap:VXLAN", FIXTURE_RMAC_PREFIX + mac]}})
            routes.append({"route-distinguisher": f"{vtep}:50120", "ethernet-tag-id": 0,
                           "ip-prefix-length": int(prefix.split("/")[1]), "ip-prefix": prefix,
                           "neighbor": "10.0.119.1" if rust else "0.0.0.0", "path-id": 0,
                           "esi": "00:00:00:00:00:00:00:00:00:00", "gateway-ip": "0.0.0.0",
                           "label": {"value": 50120, "value-type": "vni"}, "attr-id": index,
                           "valid-route": True, "best-route": True, "used-route": True,
                           "stale-route": False, "pending-delete": False,
                           "imported-network-instances": ["tenant"] if rust else []})
    l2_routes = {"mac-ip-route": [], "imet-route": []}
    for vtep, mac, rust in (("10.0.119.1", "02:AA:BB:01:19:01", True),
                            ("192.0.2.2", "02:AA:BB:01:19:02", False)):
        for tag, remote_rd in ((10, 100), (20, 101)):
            for kind in l2_routes:
                index = len(attributes) + 1
                attr = {"index": index, "next-hop": vtep, "communities": {
                    "ext-community": ["target:65000:100", "bgp-tunnel-encap:VXLAN"]}}
                row = {"route-distinguisher": f"{vtep}:{tag if rust else remote_rd}",
                       "ethernet-tag-id": tag, "neighbor": vtep if rust else "0.0.0.0",
                       "path-id": 0, "attr-id": index, "valid-route": True,
                       "best-route": True, "stale-route": False, "pending-delete": False}
                if kind == "mac-ip-route":
                    row.update({"mac-length": 48, "mac-address": mac, "ip-address": "0.0.0.0",
                                "esi": "00:00:00:00:00:00:00:00:00:00",
                                "label1": {"value": 10000 + tag, "value-type": "vni"}})
                else:
                    row["originating-router"] = vtep
                    attr["pmsi-tunnel"] = {"tunnel-type": "ingress-replication",
                                           "tunnel-endpoint": vtep,
                                           "label": {"value": 10000 + tag, "value-type": "vni"}}
                l2_routes[kind].append(row)
                attributes.append(attr)
                if not rust and kind == "mac-ip-route":
                    for ip in ("0.0.0.0", f"198.18.{tag}.253"):
                        irb = copy.deepcopy(row)
                        irb.update({"mac-address": IRB_MACS[tag].upper(), "ip-address": ip})
                        l2_routes[kind].append(irb)
    programmed = {"suppressed": False, "pending-operation-type": "none",
                  "last-successful-operation-type": "add", "last-failed-operation-type": "none"}
    group_programmed = {key: value for key, value in programmed.items() if key != "suppressed"}
    fib_routes = [{"ipv4-prefix": f"198.19.{s}.0/24", "active": True, "route-type": "bgp-evpn",
                   "route-owner": "bgp_evpn_mgr", "id": 0, "origin-network-instance": "tenant",
                   "next-hop-group": 11, "fib-programming": copy.deepcopy(programmed)}
                  for s in (121, 124)]
    fib_routes.extend({"ipv4-prefix": p, "active": True, "route-type": "local",
                       "route-owner": "net_inst_mgr", "id": 0, "origin-network-instance": "tenant",
                       "fib-programming": copy.deepcopy(programmed)}
                      for p in ("198.18.10.0/24", "198.18.20.0/24", "198.19.120.0/24", "198.19.123.0/24"))
    fib_routes.extend({"ipv4-prefix": p, "active": True, "route-type": "host",
                       "route-owner": "net_inst_mgr", "id": 0, "origin-network-instance": "tenant",
                       "fib-programming": copy.deepcopy(programmed)}
                      for p in ("198.19.120.2/32", "198.19.123.2/32"))
    return {
        "srl-rib.json": {"network-instance": [{"name": "default", "bgp-rib": {
            "afi-safi": [{"afi-safi-name": "evpn", "evpn": {"local-rib": {
                "ip-prefix-route": routes, **l2_routes}}}],
            "attr-sets": {"attr-set": attributes}}}]},
        "srl-tenant.json": {"network-instance": [{"name": "tenant", "interface": [
            {"name": f"irb0.{tag}", "oper-state": "up"} for tag in (10, 20)], "route-table": {
            "ipv4-unicast": {"route": fib_routes},
            "next-hop-group": [{"index": 11, "backup-active": False,
                                "fib-programming": copy.deepcopy(group_programmed),
                                "next-hop": [{"id": 0, "next-hop": 21, "resolved": "true",
                                              "resource-allocation-failed": False}]}],
            "next-hop": [{"index": 21, "type": FIXTURE_NH_TYPE, "resource-allocation-failed": False,
                          "ip-address": "10.0.119.1", "indirect": {
                              "resolved": True, "resolving-tunnel": {
                                  "next-hop-group": 31, "ip-prefix": "10.0.119.1/32",
                                  "tunnel-type": "vxlan", "tunnel-owner": "vxlan_mgr", "tunnel-id": 1}},
                          "vxlan-encapsulation": {
                              "vni": 50120, "interface": "vxlan1",
                              "destination-mac": "02:00:00:01:20:01"}}]}}]},
        "srl-default-fib.json": {"network-instance": [{"name": "default", "route-table": {
            "next-hop-group": [{"index": 31, "backup-active": False,
                                "fib-programming": copy.deepcopy(group_programmed),
                                "next-hop": [{"id": 0, "next-hop": 41, "resolved": "not-applicable",
                                              "resource-allocation-failed": False}]}],
            "next-hop": [{"index": 41, "type": "tunnel", "resource-allocation-failed": False,
                          "tunnel": {"ip-prefix": "10.0.119.1/32", "type": "vxlan",
                                     "owner": "vxlan_mgr", "tunnel-id": 1, "network-instance": "default"},
                          "vxlan-encapsulation": {"vni": 0, "destination-mac": "00:00:00:00:00:00"}}]}}]},
    }


def vendor_l2_imported_snapshot():
    snapshots = {}
    members = []
    for tag in (10, 20):
        snapshots[f"srl-bd{tag}.json"] = {"network-instance": [{"name": f"bd{tag}",
            "bridge-table": {"mac-table": {"mac": [
                {"address": "02:AA:BB:01:19:01", "type": "evpn", "destination-type": "vxlan",
                 "destination": f"vxlan-interface:vxlan1.{tag} vtep:10.0.119.1 vni:{10000 + tag}"},
                {"address": "02:AA:BB:01:19:02", "type": "static",
                 "destination-type": "sub-interface", "destination": f"ethernet-1/2.{tag}"},
                {"address": IRB_MACS[tag].upper(), "type": "irb-interface",
                 "destination-type": "irb-interface", "destination": "irb-interface", "is-protected": True},
            ]}}}]}
        members.append({"index": tag, "ingress": {"vni": 10000 + tag}, "oper-state": "up",
                        "bridge-table": {"multicast-destinations": {"destination": [
                            {"vtep": "10.0.119.1", "vni": 10000 + tag,
                             "multicast-forwarding": "BUM"}]}}})
    snapshots["srl-tunnels.json"] = {"tunnel-interface": [{"name": "vxlan1", "vxlan-interface": [
        {"index": 50120, "type": "routed", "oper-state": "up", "ingress": {"vni": 50120},
         "egress": {"inner-ethernet-header": {"used-source-mac": REMOTE_MAC}}},
        *members]}]}
    return snapshots


def snapshot():
    rows = []
    for local, vtep, mac, router_mac, suffixes in (
        (True, "10.0.119.1", "02:aa:bb:01:19:01", "02:00:00:01:20:01", (121, 124)),
        (False, "192.0.2.2", "02:aa:bb:01:19:02", "02:00:00:01:20:02", (120, 123)),
    ):
        peer = "0.0.0.0" if local else "10.0.119.2"
        for tag, remote_rd in ((10, 100), (20, 101)):
            for kind in (2, 3):
                rows.append({"route_type": kind, "rd": f"{vtep}:{tag if local else remote_rd}",
                             "ethernet_tag": str(tag), "next_hop": vtep, "peer": peer,
                             "mac": mac if kind == 2 else "", "ip": "" if kind == 2 else vtep,
                             "label": 10000 + tag if kind == 2 else 0, "label2": 0,
                             "esi": "00:00:00:00:00:00:00:00:00:00" if kind == 2 else "",
                             "tunnel_type": 8, "extended_communities": [842122827661412, 219550481834311688]})
                if not local and kind == 2:
                    for ip in ("", f"198.18.{tag}.253"):
                        irb = copy.deepcopy(rows[-1])
                        irb.update({"mac": IRB_MACS[tag], "ip": ip})
                        rows.append(irb)
        prefixes = ["198.18.10.0/24", "198.18.20.0/24", *(f"198.19.{s}.0/24" for s in suffixes)]
        if not local:
            prefixes.extend(f"198.19.{s}.2/32" for s in suffixes)
        for prefix in prefixes:
            rows.append({"route_type": 5, "rd": f"{vtep}:50120", "prefix": prefix,
                         "ethernet_tag": "0", "esi": "00:00:00:00:00:00:00:00:00:00",
                         "gateway": "0.0.0.0", "label": 50120, "label2": 0, "tunnel_type": 8,
                         "next_hop": vtep, "peer": peer, "mac": "", "ip": "",
                         "extended_communities": [int("0002fde80000c3c8", 16),
                                                  int("030c000000000008", 16),
                                                  int("0603" + router_mac.replace(":", ""), 16)]})
    kernel = [{"dst": p, "table": 50120, "gateway": "192.0.2.2", "dev": "l3vxlan50120",
               "protocol": "bgp", "flags": ["onlink"]}
              for p in ("198.19.120.0/24", "198.19.123.0/24", "198.19.120.2/32", "198.19.123.2/32")]
    kernel.extend({"dst": f"198.18.{tag}.0/24", "table": 50120, "dev": f"svi{tag}",
                   "protocol": "kernel", "scope": "link"} for tag in (10, 20))
    fdb = "\n".join(line for tag in (10, 20) for line in (
        f"02:aa:bb:01:19:02 dev vxlan{10000 + tag} vlan {tag} extern_learn master brbundle",
        f"02:aa:bb:01:19:02 dev vxlan{10000 + tag} dst 192.0.2.2 self extern_learn permanent",
        f"00:00:00:00:00:00 dev vxlan{10000 + tag} dst 192.0.2.2 self extern_learn permanent",
    )) + "\n02:00:00:01:20:02 dev l3vxlan50120 dst 192.0.2.2 self extern_learn permanent"
    observation = {
        "routes.json": rows, "kernel-routes.json": kernel, "fdb.txt": fdb,
        "effective-config.json": {
            "evpn_instances": [{"vni": 10000 + tag, "ethernet_tag": tag,
                                "service_interface": "vlan_aware_bundle", "ip_vrf": "tenant"}
                               for tag in (10, 20)],
            "evpn_ip_vrfs": [{"name": "tenant", "vni": 50120, "overlay_index_mode": "interface_less"}],
        },
        "runtime.json": {"generation": 42, "lifecycle": "active", "evpn_instances_count": 2,
                         "evpn_ip_vrfs_count": 1, "ethernet_segments_count": 0,
                         "ethernet_segment_member_vnis_count": 0},
        "peer.json": {"address": "10.0.119.2", "state": "Established", "flap_count": 0,
                      "notifications_received": 0, "notifications_sent": 0},
        "srl-peer.json": {"network-instance": [{"name": "default", "protocols": {"bgp": {
            "neighbor": [{"peer-address": "10.0.119.1", "session-state": "established",
                          "established-transitions": "1"}]}}}]},
        "kernel-neighbors.json": [{"dst": "192.0.2.2", "dev": "l3vxlan50120",
                                   "lladdr": "02:00:00:01:20:02", "state": ["PERMANENT"],
                                   "extern_learn": None, "protocol": "bgp"}],
        "instances.json": [{"vni": 10000 + tag, "bridge_vlan": tag, "ethernet_tag": tag,
                            "bridge": "brbundle", "service_interface": "vlan_aware_bundle",
                            "route_targets": ["65000:100"], "readiness": "ready",
                            "remote_route_drop_counts": []} for tag in (10, 20)],
        "ip-vrf.json": {"name": "tenant", "vni": 50120, "rd": "10.0.119.1:50120",
                        "route_targets": ["65000:50120"], "local_vtep_ip": "10.0.119.1",
                        "router_mac": "02:00:00:01:20:01", "vrf_device": "tenant",
                        "l3vxlan_device": "l3vxlan50120", "table_id": 50120,
                        "readiness": "ready", "not_ready_reasons": [], "originated_routes_count": 4,
                        "installed_routes_count": 4,
                        "remote_prefix_drop_counts": [{"reason": "self_originated", "count": 4}]},
    }
    observation.update(vendor_snapshot())
    observation.update(vendor_l2_imported_snapshot())
    return observation


def withdraw(observation):
    observation["routes.json"] = [r for r in observation["routes.json"]
                                  if r.get("prefix") not in ("198.19.120.0/24", "198.19.120.2/32")]
    observation["kernel-routes.json"] = [r for r in observation["kernel-routes.json"]
                                         if r["dst"] not in ("198.19.120.0/24", "198.19.120.2/32", "198.19.120.2")]
    observation["ip-vrf.json"]["installed_routes_count"] = 2
    vendor_routes = observation["srl-rib.json"]["network-instance"][0]["bgp-rib"]["afi-safi"][0]["evpn"]["local-rib"]["ip-prefix-route"]
    vendor_routes[:] = [r for r in vendor_routes if r["ip-prefix"] not in ("198.19.120.0/24", "198.19.120.2/32")]


def write(directory, observation):
    directory.mkdir(parents=True, exist_ok=True)
    for name, value in observation.items():
        (directory / name).write_text(value if name.endswith(".txt") else json.dumps(value))


def write_receipt(directory):
    for phase in ("startup", "initial", "remote-withdrawn", "restored", "rejected-reload", "unlinked", "relinked", "final"):
        observation = snapshot()
        if phase == "remote-withdrawn":
            withdraw(observation)
        elif phase == "unlinked":
            del observation["effective-config.json"]["evpn_instances"][0]["ip_vrf"]
            observation["runtime.json"]["generation"] = 43
        elif phase in ("relinked", "final"):
            observation["runtime.json"]["generation"] = 44
        write(directory / phase, observation)


class BundleIrbOracleTests(unittest.TestCase):
    def setUp(self):
        # Bind distinct fixture vocabulary so production rendering changes
        # cannot silently turn synthetic strings into vendor observations.
        for name, value in (("SRL_ROUTER_MAC_COMMUNITY_PREFIX", FIXTURE_RMAC_PREFIX),
                            ("SRL_IFL_NEXT_HOP_TYPE", FIXTURE_NH_TYPE)):
            binding = patch.object(oracle, name, value)
            binding.start()
            self.addCleanup(binding.stop)

    def test_remote_router_mac_comes_from_independent_vendor_state(self):
        good = snapshot()
        self.assertEqual(oracle.remote_router_mac(good["srl-tunnels.json"]), REMOTE_MAC)
        alternate = "02:11:22:33:44:55"
        good["srl-tunnels.json"]["tunnel-interface"][0]["vxlan-interface"][0]["egress"]["inner-ethernet-header"]["used-source-mac"] = alternate
        with self.assertRaises(ValueError):
            oracle.daemon_l3(good["routes.json"], oracle.remote_router_mac(good["srl-tunnels.json"]))
        with self.assertRaises(ValueError):
            oracle.kernel_neighbor(good["kernel-neighbors.json"], alternate)
        with self.assertRaises(ValueError):
            oracle.kernel_fdb(good["fdb.txt"], alternate)
        for row in good["routes.json"]:
            if row["route_type"] == 5 and row["peer"] == "10.0.119.2":
                row["extended_communities"][2] = int("0603021122334455", 16)
        good["kernel-neighbors.json"][0]["lladdr"] = alternate
        good["fdb.txt"] = good["fdb.txt"].replace(REMOTE_MAC, alternate)
        attributes = good["srl-rib.json"]["network-instance"][0]["bgp-rib"]["attr-sets"]["attr-set"]
        for attr in attributes:
            if attr["next-hop"] == "192.0.2.2" and "target:65000:50120" in attr["communities"]["ext-community"]:
                attr["communities"]["ext-community"][2] = FIXTURE_RMAC_PREFIX + alternate
        with tempfile.TemporaryDirectory() as temporary:
            write(Path(temporary), good)
            oracle.state(Path(temporary))

    def test_vendor_router_mac_must_be_valid_unicast_and_from_l3_member(self):
        for mac in (None, "00:00:00:00:00:00", "01:00:5e:00:00:01", "ff:ff:ff:ff:ff:ff", "02:00:00:01:20"):
            with self.subTest(mac=mac):
                vendor = snapshot()["srl-tunnels.json"]
                vendor["tunnel-interface"][0]["vxlan-interface"][0]["egress"]["inner-ethernet-header"]["used-source-mac"] = mac
                with self.assertRaises(ValueError):
                    oracle.remote_router_mac(vendor)
        vendor = snapshot()["srl-tunnels.json"]
        vendor["tunnel-interface"][0]["vxlan-interface"][0]["index"] = 10010
        with self.assertRaises(ValueError):
            oracle.remote_router_mac(vendor)

        for field, wrong in (("type", "bridged"), ("oper-state", "down"),
                             ("ingress", {"vni": 10010}), ("ingress", {})):
            with self.subTest(field=field, wrong=wrong):
                vendor = snapshot()["srl-tunnels.json"]
                vendor["tunnel-interface"][0]["vxlan-interface"][0][field] = wrong
                with self.assertRaises((ValueError, KeyError)):
                    oracle.remote_router_mac(vendor)
        for field in ("type", "oper-state", "ingress"):
            with self.subTest(missing=field):
                vendor = snapshot()["srl-tunnels.json"]
                del vendor["tunnel-interface"][0]["vxlan-interface"][0][field]
                with self.assertRaises(KeyError):
                    oracle.remote_router_mac(vendor)

    def test_full_withdrawn_and_final_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_receipt(directory)
            oracle.replay(directory)

    def test_vendor_l2_rib_requires_exact_inventory_and_member_identity(self):
        good = snapshot()["srl-rib.json"]
        oracle.vendor_l2_rib(good, IRB_MACS)
        self.assertEqual(good, snapshot()["srl-rib.json"])
        for kind in ("mac-ip-route", "imet-route"):
            for field, wrong in (("route-distinguisher", "10.0.119.1:20"),
                                 ("ethernet-tag-id", 20), ("attr-id", 1),
                                 ("best-route", False)):
                with self.subTest(kind=kind, field=field):
                    bad = copy.deepcopy(good)
                    routes = bad["network-instance"][0]["bgp-rib"]["afi-safi"][0]["evpn"]["local-rib"]
                    routes[kind][0][field] = wrong
                    with self.assertRaises(ValueError):
                        oracle.vendor_l2_rib(bad, IRB_MACS)
        for case in ("extra-kind", "missing-kind", "duplicate", "wrong-mac"):
            with self.subTest(case=case):
                bad = copy.deepcopy(good)
                routes = bad["network-instance"][0]["bgp-rib"]["afi-safi"][0]["evpn"]["local-rib"]
                if case == "extra-kind":
                    routes["ethernet-ad-route"] = []
                elif case == "missing-kind":
                    del routes["imet-route"]
                elif case == "duplicate":
                    routes["mac-ip-route"].append(copy.deepcopy(routes["mac-ip-route"][0]))
                else:
                    routes["mac-ip-route"][0]["mac-address"] = "02:AA:BB:01:19:FF"
                with self.assertRaises(ValueError):
                    oracle.vendor_l2_rib(bad, IRB_MACS)

    def test_vendor_l2_attributes_must_match_the_referenced_path(self):
        for field, wrong in (("next-hop", "192.0.2.99"),
                             ("communities", {"ext-community": ["target:65000:50120", "bgp-tunnel-encap:VXLAN"]}),
                             ("pmsi-tunnel", {"tunnel-type": "ingress-replication",
                                              "tunnel-endpoint": "10.0.119.1",
                                              "label": {"value": 10020, "value-type": "vni"}})):
            with self.subTest(field=field):
                bad = snapshot()["srl-rib.json"]
                rib = bad["network-instance"][0]["bgp-rib"]
                row = rib["afi-safi"][0]["evpn"]["local-rib"]["imet-route"][0]
                attrs = rib["attr-sets"]["attr-set"]
                redirected = copy.deepcopy(next(a for a in attrs if a["index"] == row["attr-id"]))
                redirected.update({"index": 99, field: wrong})
                attrs.append(redirected)
                row["attr-id"] = 99
                with self.assertRaises(ValueError):
                    oracle.vendor_l2_rib(bad, IRB_MACS)

    def test_vendor_l2_imported_mac_requires_programmed_member_destination(self):
        for field, wrong in (("address", "02:AA:BB:01:19:FF"), ("type", "static"),
                             ("type", "evpn-static"), ("not-programmed-reason", "failed"),
                             ("destination", "vxlan-interface:vxlan1.20 vtep:10.0.119.1 vni:10020")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                bad = snapshot()
                row = bad["srl-bd10.json"]["network-instance"][0]["bridge-table"]["mac-table"]["mac"][0]
                row[field] = wrong
                write(Path(temporary), bad)
                with self.assertRaises(ValueError):
                    oracle.vendor_l2_imported(Path(temporary))

    def test_vendor_l2_flood_and_tunnel_inventory_cannot_cross_members(self):
        for case in ("cross-vni", "wrong-vtep", "failed", "duplicate", "missing", "extra-member"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                bad = snapshot()
                members = bad["srl-tunnels.json"]["tunnel-interface"][0]["vxlan-interface"]
                destinations = members[1]["bridge-table"]["multicast-destinations"]["destination"]
                if case == "cross-vni":
                    destinations[0]["vni"] = 10020
                elif case == "wrong-vtep":
                    destinations[0]["vtep"] = "192.0.2.99"
                elif case == "failed":
                    destinations[0]["not-programmed-reason"] = "failed"
                elif case == "duplicate":
                    destinations.append(copy.deepcopy(destinations[0]))
                elif case == "missing":
                    destinations.clear()
                else:
                    members.append({"index": 30})
                write(Path(temporary), bad)
                with self.assertRaises(ValueError):
                    oracle.vendor_l2_imported(Path(temporary))

    def test_effective_config_rejects_wrong_mode_and_wrong_unlinked_member(self):
        for mode in ("gateway_ip", "esi"):
            with self.subTest(mode=mode):
                config = snapshot()["effective-config.json"]
                config["evpn_ip_vrfs"][0]["overlay_index_mode"] = mode
                with self.assertRaises(ValueError):
                    oracle.effective_config(config)
        config = snapshot()["effective-config.json"]
        del config["evpn_instances"][1]["ip_vrf"]
        with self.assertRaises(ValueError):
            oracle.effective_config(config, unlinked=True)
        config = snapshot()["effective-config.json"]
        del config["evpn_instances"][0]["ip_vrf"]
        oracle.effective_config(config, unlinked=True)
        with self.assertRaises(ValueError):
            oracle.effective_config(config)
        config["evpn_instances"][0]["ip_vrf"] = "wrong-tenant"
        with self.assertRaises(ValueError):
            oracle.effective_config(config, unlinked=True)

    def test_replay_checks_rejected_unlink_and_relink_generations(self):
        for phase, wrong in (("rejected-reload", 43), ("unlinked", 42), ("relinked", 43), ("final", 42)):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                write_receipt(directory)
                path = directory / phase / "runtime.json"
                row = json.loads(path.read_text())
                row["generation"] = wrong
                path.write_text(json.dumps(row))
                with self.assertRaises(ValueError):
                    oracle.replay(directory)

    def test_runtime_requires_active_single_homed_members(self):
        for field, wrong in (("lifecycle", "degraded"), ("ethernet_segments_count", 1),
                             ("ethernet_segment_member_vnis_count", 1)):
            with self.subTest(field=field):
                row = snapshot()["runtime.json"]
                row[field] = wrong
                with self.assertRaises(ValueError):
                    oracle.runtime(row)

    def test_replay_rejects_daemon_flap_notifications_and_vendor_reestablishment(self):
        for field, wrong in (("state", "Active"), ("flap_count", 1), ("notifications_received", 1),
                             ("notifications_sent", 1), ("established-transitions", "2")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                write_receipt(directory)
                name = "srl-peer.json" if field == "established-transitions" else "peer.json"
                path = directory / "restored" / name
                observation = json.loads(path.read_text())
                row = (observation["network-instance"][0]["protocols"]["bgp"]["neighbor"][0]
                       if name == "srl-peer.json" else observation)
                row[field] = wrong
                path.write_text(json.dumps(observation))
                with self.assertRaises(ValueError):
                    oracle.replay(directory)

    def test_complete_final_rib_comparison_detects_other_attribute_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_receipt(directory)
            path = directory / "final" / "routes.json"
            rows = json.loads(path.read_text())
            rows[0]["as_path"] = [64512]
            path.write_text(json.dumps(rows))
            with self.assertRaisesRegex(ValueError, "complete EVPN RIB"):
                oracle.replay(directory)

    def test_unknown_extra_type2_is_not_ignored(self):
        observation = snapshot()
        extra = copy.deepcopy(observation["routes.json"][0])
        extra["mac"] = "02:aa:bb:01:19:99"
        observation["routes.json"].append(extra)
        with self.assertRaises(ValueError):
            oracle.daemon_l2(observation["routes.json"], observation["instances.json"], IRB_MACS)

    def test_irb_type2_inventory_is_exact_and_bound_to_independent_bridge_identity(self):
        for side in ("daemon", "vendor"):
            for case in ("missing", "duplicate", "unknown", "wrong-ip", "wrong-tag", "wrong-identity"):
                with self.subTest(side=side, case=case):
                    observation = snapshot()
                    identities = dict(IRB_MACS)
                    if side == "daemon":
                        rows = observation["routes.json"]
                        mac_key, ip_key, tag_key = "mac", "ip", "ethernet_tag"
                    else:
                        rows = observation["srl-rib.json"]["network-instance"][0]["bgp-rib"]["afi-safi"][0]["evpn"]["local-rib"]["mac-ip-route"]
                        mac_key, ip_key, tag_key = "mac-address", "ip-address", "ethernet-tag-id"
                    row = next(r for r in rows if r.get(mac_key, "").lower() == IRB_MACS[10])
                    if case == "missing":
                        rows.remove(row)
                    elif case == "duplicate":
                        rows.append(copy.deepcopy(row))
                    elif case == "unknown":
                        row[mac_key] = "02:00:00:01:20:99"
                    elif case == "wrong-ip":
                        row[ip_key] = "198.18.10.252"
                    elif case == "wrong-tag":
                        row[tag_key] = "20" if side == "daemon" else 20
                    else:
                        identities[10] = "02:00:00:01:20:99"
                    with self.assertRaises(ValueError):
                        if side == "daemon":
                            oracle.daemon_l2(rows, observation["instances.json"], identities)
                        else:
                            oracle.vendor_l2_rib(observation["srl-rib.json"], identities)

    def test_vendor_irb_identity_requires_unique_programmed_irb_row(self):
        for case in ("valid", "missing", "duplicate", "wrong-type", "multicast", "malformed", "not-programmed",
                     "unprotected", "wrong-destination", "missing-interface", "down-interface", "duplicate-interface"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                observation = snapshot()
                rows = observation["srl-bd10.json"]["network-instance"][0]["bridge-table"]["mac-table"]["mac"]
                row = rows[-1]
                if case == "missing":
                    rows.remove(row)
                elif case == "duplicate":
                    rows.append(copy.deepcopy(row))
                elif case == "wrong-type":
                    row["type"] = "static"
                elif case == "multicast":
                    row["address"] = "01:00:5E:00:00:01"
                elif case == "malformed":
                    row["address"] = "not-a-mac"
                elif case == "not-programmed":
                    row["not-programmed-reason"] = "failed"
                elif case == "unprotected":
                    row["is-protected"] = False
                elif case == "wrong-destination":
                    row["destination"] = "ethernet-1/2.10"
                elif case.endswith("interface"):
                    interfaces = observation["srl-tenant.json"]["network-instance"][0]["interface"]
                    if case == "missing-interface":
                        interfaces.pop(0)
                    elif case == "down-interface":
                        interfaces[0]["oper-state"] = "down"
                    else:
                        interfaces.append(copy.deepcopy(interfaces[0]))
                write(Path(temporary), observation)
                if case == "valid":
                    self.assertEqual(oracle.vendor_irb_macs(Path(temporary)), IRB_MACS)
                else:
                    with self.assertRaises(ValueError):
                        oracle.vendor_irb_macs(Path(temporary))

    def test_each_type5_path_requires_exact_fields_and_communities(self):
        good = snapshot()["routes.json"]
        changes = (("ethernet_tag", "10"), ("esi", "00:01:02:03:04:05:06:07:08:09"),
                   ("gateway", "198.18.10.2"), ("label", 10010), ("label2", 50120),
                   ("tunnel_type", 10), ("next_hop", "192.0.2.99"), ("peer", "192.0.2.99"),
                   ("rd", "65000:100"), ("prefix", "198.19.122.0/24"))
        for index, row in enumerate(good):
            if row["route_type"] != 5:
                continue
            for field, wrong in changes:
                with self.subTest(index=index, field=field):
                    bad = copy.deepcopy(good)
                    bad[index][field] = wrong
                    with self.assertRaises(ValueError):
                        oracle.daemon_l3(bad, REMOTE_MAC)
            for community in range(3):
                with self.subTest(index=index, community=community):
                    bad = copy.deepcopy(good)
                    # Other paths retain correct values; global presence is insufficient.
                    bad[index]["extended_communities"][community] ^= 1
                    with self.assertRaises(ValueError):
                        oracle.daemon_l3(bad, REMOTE_MAC)

    def test_duplicate_extra_and_missing_type5_fail(self):
        good = snapshot()["routes.json"]
        for case in ("missing", "duplicate", "extra", "extra-host", "duplicate-community"):
            with self.subTest(case=case):
                bad = copy.deepcopy(good)
                row = next(r for r in bad if r["route_type"] == 5)
                if case == "missing":
                    bad.remove(row)
                elif case == "duplicate-community":
                    row["extended_communities"].append(row["extended_communities"][0])
                else:
                    extra = copy.deepcopy(row)
                    if case == "extra":
                        extra["prefix"] = "198.19.122.0/24"
                    elif case == "extra-host":
                        extra["prefix"] = "198.19.120.3/32"
                    bad.append(extra)
                with self.assertRaises(ValueError):
                    oracle.daemon_l3(bad, REMOTE_MAC)

    def test_kernel_route_identity_and_connected_survival(self):
        good = snapshot()["kernel-routes.json"]
        for field, wrong in (("table", 254), ("dev", "vxlan10010"), ("gateway", "192.0.2.99"),
                             ("protocol", "static"), ("flags", []), ("type", "blackhole"),
                             ("nexthops", [{"gateway": "192.0.2.99", "dev": "l3vxlan50120"}])):
            with self.subTest(field=field):
                bad = copy.deepcopy(good)
                bad[0][field] = wrong
                with self.assertRaises(ValueError):
                    oracle.kernel_routes(bad)
        for index in (4, 5):
            bad = copy.deepcopy(good)
            del bad[index]
            with self.subTest(connected=index), self.assertRaises(ValueError):
                oracle.kernel_routes(bad)

    def test_kernel_rejects_foreign_host_and_equal_prefix_probe_routes(self):
        for prefix in ("198.19.120.2/32", "198.19.120.2", "198.19.120.0/24",
                       "198.19.123.2/32", "198.19.123.2", "198.19.123.0/24"):
            with self.subTest(prefix=prefix):
                rows = snapshot()["kernel-routes.json"]
                rows.append({"dst": prefix, "table": 50120, "protocol": "static",
                             "gateway": "198.18.10.253", "dev": "svi10"})
                with self.assertRaisesRegex(ValueError, "tenant competing route covers probe"):
                    oracle.kernel_routes(rows)

    def test_owned_host_routes_accept_canonical_table_and_host_renderings(self):
        for table in (50120, "50120"):
            for bare in (False, True):
                with self.subTest(table=table, bare=bare):
                    rows = snapshot()["kernel-routes.json"]
                    for row in rows:
                        row["table"] = table
                        if bare and row["dst"].endswith("/32"):
                            row["dst"] = row["dst"].removesuffix("/32")
                    oracle.kernel_routes(rows)
        for table in (50120.0, "050120", "50120.0", True, None):
            with self.subTest(table=table):
                rows = snapshot()["kernel-routes.json"]
                rows[0]["table"] = table
                with self.assertRaises(ValueError):
                    oracle.kernel_routes(rows)

    def test_unknown_bgp_host_route_is_not_accepted_as_an_export(self):
        for prefix in ("198.19.120.3/32", "198.19.123.3/32"):
            with self.subTest(prefix=prefix):
                rows = snapshot()["kernel-routes.json"]
                extra = copy.deepcopy(rows[0])
                extra["dst"] = prefix
                rows.append(extra)
                with self.assertRaises(ValueError):
                    oracle.kernel_routes(rows)

    def test_export_counts_and_withdrawal_include_owned_host_routes(self):
        observation = snapshot()
        self.assertEqual(sum(r["route_type"] == 5 for r in observation["routes.json"]), 10)
        oracle.ip_vrf(observation["ip-vrf.json"])
        withdraw(observation)
        self.assertEqual(sum(r["route_type"] == 5 for r in observation["routes.json"]), 8)
        oracle.ip_vrf(observation["ip-vrf.json"], "remote-withdrawn")
        for side in ("daemon", "vendor", "kernel"):
            with self.subTest(side=side):
                good = snapshot()
                bad = snapshot()
                withdraw(bad)
                if side == "daemon":
                    stale = next(r for r in good["routes.json"] if r.get("prefix") == "198.19.120.2/32")
                    bad["routes.json"].append(stale)
                    with self.assertRaises(ValueError):
                        oracle.daemon_l3(bad["routes.json"], REMOTE_MAC, "remote-withdrawn")
                elif side == "vendor":
                    routes = good["srl-rib.json"]["network-instance"][0]["bgp-rib"]["afi-safi"][0]["evpn"]["local-rib"]["ip-prefix-route"]
                    stale = next(r for r in routes if r["ip-prefix"] == "198.19.120.2/32")
                    bad["srl-rib.json"]["network-instance"][0]["bgp-rib"]["afi-safi"][0]["evpn"]["local-rib"]["ip-prefix-route"].append(stale)
                    with self.assertRaises(ValueError):
                        oracle.vendor_l3_rib(bad["srl-rib.json"], REMOTE_MAC, "remote-withdrawn")
                else:
                    stale = next(r for r in good["kernel-routes.json"] if r["dst"] == "198.19.120.2/32")
                    bad["kernel-routes.json"].append(stale)
                    with self.assertRaises(ValueError):
                        oracle.kernel_routes(bad["kernel-routes.json"], "remote-withdrawn")

    def test_replay_rejects_transient_foreign_linux_host_route(self):
        for phase, prefix in (("restored", "198.19.120.2/32"),
                              ("relinked", "198.19.123.2")):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                write_receipt(directory)
                path = directory / phase / "kernel-routes.json"
                rows = json.loads(path.read_text())
                rows.append({"dst": prefix, "table": 50120, "protocol": "static",
                             "gateway": "198.18.10.253", "dev": "svi10"})
                path.write_text(json.dumps(rows))
                with self.assertRaisesRegex(ValueError, "tenant competing route covers probe"):
                    oracle.replay(directory)

    def test_kernel_allows_local_bare_hosts_unrelated_routes_and_default(self):
        rows = snapshot()["kernel-routes.json"]
        rows.extend([
            {"dst": "198.18.10.254", "table": 50120, "protocol": "kernel",
             "dev": "svi10", "type": "local", "scope": "host"},
            {"dst": "203.0.113.7/32", "table": 50120, "protocol": "static",
             "gateway": "198.18.10.253", "dev": "svi10"},
            {"dst": "default", "table": 50120, "protocol": "static",
             "gateway": "198.18.10.253", "dev": "svi10"},
        ])
        oracle.kernel_routes(rows)

    def test_kernel_requires_valid_ipv4_destination_shapes(self):
        for prefix in (None, 1234, "198.19.120.2/24",
                       "198.19.120.0/255.255.255.0", "2001:db8::/64"):
            with self.subTest(prefix=prefix):
                rows = snapshot()["kernel-routes.json"]
                rows.append({"dst": prefix, "table": 50120, "protocol": "static",
                             "gateway": "198.18.10.253", "dev": "svi10"})
                with self.assertRaises(ValueError):
                    oracle.kernel_routes(rows)

    def test_withdrawal_requires_absence_everywhere_and_survivor(self):
        good = snapshot()
        with self.assertRaises(ValueError):
            oracle.daemon_l3(good["routes.json"], REMOTE_MAC, "remote-withdrawn")
        withdraw(good)
        oracle.daemon_l3(good["routes.json"], REMOTE_MAC, "remote-withdrawn")
        oracle.kernel_routes(good["kernel-routes.json"], "remote-withdrawn")
        bad = copy.deepcopy(good["kernel-routes.json"])
        bad.append({"dst": "198.19.120.0/24", "table": 254, "protocol": "static", "dev": "eth1"})
        with self.assertRaises(ValueError):
            oracle.kernel_routes(bad, "remote-withdrawn")
        good["routes.json"] = [r for r in good["routes.json"] if r.get("prefix") != "198.19.123.0/24"]
        with self.assertRaises(ValueError):
            oracle.daemon_l3(good["routes.json"], REMOTE_MAC, "remote-withdrawn")

    def test_neighbor_requires_exact_device_mac_and_ownership(self):
        good = snapshot()["kernel-neighbors.json"]
        for field, wrong in (("dst", "192.0.2.99"), ("dev", "vxlan10010"),
                             ("lladdr", "02:00:00:01:20:01"), ("state", ["REACHABLE"]),
                             ("protocol", "static"), ("extern_learn", False)):
            with self.subTest(field=field):
                bad = copy.deepcopy(good)
                bad[0][field] = wrong
                with self.assertRaises(ValueError):
                    oracle.kernel_neighbor(bad, REMOTE_MAC)
        del good[0]["extern_learn"]
        with self.assertRaises(ValueError):
            oracle.kernel_neighbor(good, REMOTE_MAC)

    def test_fdb_requires_l3_and_both_l2_members(self):
        good = snapshot()["fdb.txt"]
        for bad in (good.replace("02:00:00:01:20:02", "02:00:00:01:20:99"),
                    good.replace("dst 192.0.2.2", "dst 192.0.2.99"),
                    good.replace("vlan 10", "vlan 20"),
                    good.replace("extern_learn", "static"),
                    "\n".join(line for line in good.splitlines() if "vxlan10010 " not in line),
                    good + "\n00:00:00:00:00:00 dev l3vxlan50120 dst 192.0.2.2 self permanent"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                oracle.kernel_fdb(bad, REMOTE_MAC)

    def test_state_rejects_unrelated_extra_managed_l2_mac(self):
        for tag in (10, 20):
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as temporary:
                observation = snapshot()
                observation["fdb.txt"] += (
                    f"\n02:de:ad:01:20:99 dev vxlan{10000 + tag} "
                    "dst 192.0.2.2 self extern_learn permanent")
                write(Path(temporary), observation)
                with self.assertRaisesRegex(ValueError, "unexpected managed FDB row"):
                    oracle.state(Path(temporary))

    def test_replay_rejects_transient_unrelated_managed_l2_mac(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_receipt(directory)
            path = directory / "unlinked" / "fdb.txt"
            path.write_text(path.read_text() +
                            "\n02:de:ad:01:20:99 dev vxlan10020 "
                            "dst 192.0.2.2 self extern_learn permanent")
            self.assertEqual((directory / "initial" / "fdb.txt").read_text(),
                             (directory / "final" / "fdb.txt").read_text())
            with self.assertRaisesRegex(ValueError, "unexpected managed FDB row"):
                oracle.replay(directory)

    def test_fdb_allows_unmanaged_learned_and_local_rows(self):
        text = snapshot()["fdb.txt"] + (
            "\n02:de:ad:01:20:99 dev vxlan10010 master brbundle"
            "\n02:aa:bb:01:19:01 dev access20 vlan 20 master brbundle permanent")
        oracle.kernel_fdb(text, REMOTE_MAC)

    def test_member_identity_and_ip_vrf_status_cannot_substitute_for_proof(self):
        good = snapshot()
        good["instances.json"][0]["ethernet_tag"] = 20
        with self.assertRaises(ValueError):
            oracle.daemon_l2(good["routes.json"], good["instances.json"], IRB_MACS)
        for field, wrong in (("readiness", "not-ready"), ("table_id", 254),
                             ("router_mac", "02:00:00:01:20:02"), ("installed_routes_count", 0)):
            with self.subTest(field=field):
                bad = snapshot()["ip-vrf.json"]
                bad[field] = wrong
                with self.assertRaises(ValueError):
                    oracle.ip_vrf(bad)

    def test_vendor_live_renderings_must_be_explicitly_bound(self):
        observation = vendor_snapshot()
        with patch.object(oracle, "SRL_ROUTER_MAC_COMMUNITY_PREFIX", None):
            with self.assertRaisesRegex(ValueError, "bind the Router MAC"):
                oracle.vendor_l3_rib(observation["srl-rib.json"], REMOTE_MAC)
        with patch.object(oracle, "SRL_IFL_NEXT_HOP_TYPE", None):
            with self.assertRaisesRegex(ValueError, "bind the pinned"):
                oracle.vendor_l3_fib(observation["srl-tenant.json"], observation["srl-default-fib.json"])

    def test_vendor_type5_nlri_and_import_are_bound_to_each_route(self):
        changes = (("ethernet-tag-id", 10), ("ip-prefix-length", 32),
                   ("gateway-ip", "198.18.10.253"), ("esi", "00:01:02:03:04:05:06:07:08:09"),
                   ("label", {"value": 10010, "value-type": "vni"}),
                   ("label", {"value": 50120, "value-type": "mpls-label"}),
                   ("neighbor", "10.0.119.99"), ("path-id", 1), ("valid-route", False),
                   ("best-route", False), ("stale-route", True), ("pending-delete", True),
                   ("imported-network-instances", ["wrong-tenant"]),
                   ("used-route", False), ("fib-disabled", True))
        for field, value in changes:
            with self.subTest(field=field, value=value):
                observation = vendor_snapshot()["srl-rib.json"]
                row = observation["network-instance"][0]["bgp-rib"]["afi-safi"][0]["evpn"]["local-rib"]["ip-prefix-route"][2]
                row[field] = value
                with self.assertRaises(ValueError):
                    oracle.vendor_l3_rib(observation, REMOTE_MAC)

    def test_vendor_type5_uses_referenced_attributes_not_nearby_good_values(self):
        for field, wrong in (("next-hop", "10.0.119.99"),
                             ("rt", "target:65000:100"),
                             ("encap", "bgp-tunnel-encap:MPLS"),
                             ("rmac", FIXTURE_RMAC_PREFIX + "02:00:00:01:20:99")):
            with self.subTest(field=field):
                observation = vendor_snapshot()["srl-rib.json"]
                rib = observation["network-instance"][0]["bgp-rib"]
                # Keep the original correct attr-set in the same document,
                # but point this route at a different, incorrect attr-set.
                bad = copy.deepcopy(rib["attr-sets"]["attr-set"][2])
                bad["index"] = 999
                if field == "next-hop":
                    bad[field] = wrong
                else:
                    bad["communities"]["ext-community"][("rt", "encap", "rmac").index(field)] = wrong
                rib["attr-sets"]["attr-set"].append(bad)
                rib["afi-safi"][0]["evpn"]["local-rib"]["ip-prefix-route"][2]["attr-id"] = 999
                with self.assertRaises(ValueError):
                    oracle.vendor_l3_rib(observation, REMOTE_MAC)

    def test_vendor_type5_inventory_rejects_missing_duplicate_and_stale_withdrawal(self):
        for case in ("missing", "duplicate", "extra", "extra-host", "duplicate-attr-id"):
            with self.subTest(case=case):
                observation = vendor_snapshot()["srl-rib.json"]
                rib = observation["network-instance"][0]["bgp-rib"]
                rows = rib["afi-safi"][0]["evpn"]["local-rib"]["ip-prefix-route"]
                if case == "missing":
                    rows.pop()
                elif case == "duplicate-attr-id":
                    rib["attr-sets"]["attr-set"].append(copy.deepcopy(rib["attr-sets"]["attr-set"][0]))
                else:
                    extra = copy.deepcopy(rows[0])
                    if case == "extra":
                        extra["ip-prefix"] = "198.19.122.0/24"
                    elif case == "extra-host":
                        extra.update({"ip-prefix": "198.19.120.3/32", "ip-prefix-length": 32})
                    rows.append(extra)
                with self.assertRaises(ValueError):
                    oracle.vendor_l3_rib(observation, REMOTE_MAC)
        with self.assertRaises(ValueError):
            oracle.vendor_l3_rib(vendor_snapshot()["srl-rib.json"], REMOTE_MAC, "remote-withdrawn")

    def test_vendor_fib_uses_route_nhg_and_member_nh_references(self):
        for level in ("group", "hop"):
            with self.subTest(level=level):
                observation = vendor_snapshot()
                table = observation["srl-tenant.json"]["network-instance"][0]["route-table"]
                if level == "group":
                    bad = copy.deepcopy(table["next-hop-group"][0])
                    bad["index"] = 99
                    bad["next-hop"][0]["resolved"] = "false"
                    table["next-hop-group"].append(bad)
                    table["ipv4-unicast"]["route"][0]["next-hop-group"] = 99
                else:
                    bad = copy.deepcopy(table["next-hop"][0])
                    bad["index"] = 99
                    bad["vxlan-encapsulation"]["vni"] = 10010
                    table["next-hop"].append(bad)
                    table["next-hop-group"][0]["next-hop"][0]["next-hop"] = 99
                with self.assertRaises(ValueError):
                    oracle.vendor_l3_fib(observation["srl-tenant.json"], observation["srl-default-fib.json"])

    def test_vendor_fib_honors_explicit_cross_network_instance_reference(self):
        observation = vendor_snapshot()
        tenant = observation["srl-tenant.json"]["network-instance"][0]["route-table"]
        default = observation["srl-default-fib.json"]["network-instance"][0]["route-table"]
        default["next-hop-group"].extend(tenant.pop("next-hop-group"))
        default["next-hop"].extend(tenant.pop("next-hop"))
        for row in tenant["ipv4-unicast"]["route"][:2]:
            row["next-hop-group-network-instance"] = "default"
        oracle.vendor_l3_fib(observation["srl-tenant.json"], observation["srl-default-fib.json"])
        tenant["ipv4-unicast"]["route"][0]["next-hop-group-network-instance"] = "uncaptured"
        with self.assertRaises(ValueError):
            oracle.vendor_l3_fib(observation["srl-tenant.json"], observation["srl-default-fib.json"])

    def test_vendor_indirect_resolver_must_reach_the_exact_programmed_terminal(self):
        changes = (
            ("indirect", "resolved", False), ("indirect", "resolved", "true"),
            ("resolver", "next-hop-group", 999), ("resolver", "ip-prefix", "10.0.119.99/32"),
            ("resolver", "tunnel-type", "mpls"), ("resolver", "tunnel-owner", "static_mgr"),
            ("resolver", "tunnel-id", 0), ("resolver", "tunnel-id", True),
            ("group", "backup-active", True), ("programming", "suppressed", True),
            ("programming", "pending-operation-type", "add"),
            ("member", "next-hop", 999), ("member", "resolved", "false"),
            ("member", "resource-allocation-failed", True),
            ("terminal", "type", "direct"), ("terminal", "resource-allocation-failed", True),
            ("tunnel", "ip-prefix", "10.0.119.99/32"), ("tunnel", "tunnel-id", 2),
            ("tunnel", "tunnel-id", True),
            ("tunnel", "network-instance", "tenant"),
            ("vxlan", "vni", 50120), ("vxlan", "destination-mac", REMOTE_MAC),
        )
        for level, field, wrong in changes:
            with self.subTest(level=level, field=field, wrong=wrong):
                observation = vendor_snapshot()
                tenant = observation["srl-tenant.json"]["network-instance"][0]["route-table"]
                default = observation["srl-default-fib.json"]["network-instance"][0]["route-table"]
                indirect = tenant["next-hop"][0]["indirect"]
                group, terminal = default["next-hop-group"][0], default["next-hop"][0]
                target = {"indirect": indirect, "resolver": indirect["resolving-tunnel"],
                          "group": group, "programming": group["fib-programming"],
                          "member": group["next-hop"][0], "terminal": terminal,
                          "tunnel": terminal["tunnel"], "vxlan": terminal["vxlan-encapsulation"]}[level]
                target[field] = wrong
                with self.assertRaises(ValueError):
                    oracle.vendor_l3_fib(observation["srl-tenant.json"], observation["srl-default-fib.json"])

    def test_vendor_resolver_rejects_missing_links_and_malformed_schema(self):
        for case in ("missing-indirect", "missing-resolver", "missing-group", "missing-terminal",
                     "malformed-resolver", "malformed-group", "malformed-terminal"):
            with self.subTest(case=case):
                observation = vendor_snapshot()
                tenant = observation["srl-tenant.json"]["network-instance"][0]["route-table"]
                default = observation["srl-default-fib.json"]["network-instance"][0]["route-table"]
                hop = tenant["next-hop"][0]
                if case == "missing-indirect":
                    del hop["indirect"]
                elif case == "missing-resolver":
                    del hop["indirect"]["resolving-tunnel"]
                elif case == "missing-group":
                    default["next-hop-group"].clear()
                elif case == "missing-terminal":
                    default["next-hop"].clear()
                elif case == "malformed-resolver":
                    hop["indirect"]["resolving-tunnel"] = None
                elif case == "malformed-group":
                    default["next-hop-group"][0]["next-hop"] = None
                else:
                    default["next-hop"][0]["tunnel"] = []
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    oracle.vendor_l3_fib(observation["srl-tenant.json"], observation["srl-default-fib.json"])

    def test_vendor_optional_flags_preserve_required_route_programming(self):
        observation = vendor_snapshot()
        table = observation["srl-tenant.json"]["network-instance"][0]["route-table"]
        table["next-hop-group"][0]["fib-programming"]["suppressed"] = False
        rib = observation["srl-rib.json"]["network-instance"][0]["bgp-rib"]
        row = rib["afi-safi"][0]["evpn"]["local-rib"]["ip-prefix-route"][2]
        row["fib-disabled"] = False
        oracle.vendor_l3_rib(observation["srl-rib.json"], REMOTE_MAC)
        oracle.vendor_l3_fib(observation["srl-tenant.json"], observation["srl-default-fib.json"])
        del table["ipv4-unicast"]["route"][0]["fib-programming"]["suppressed"]
        with self.assertRaises((ValueError, KeyError)):
            oracle.vendor_l3_fib(observation["srl-tenant.json"], observation["srl-default-fib.json"])

    def test_vendor_fib_rejects_active_competitors_for_reverse_probes(self):
        for prefix in ("198.19.121.1/32", "198.19.124.1/32",
                       "198.19.121.0/24", "198.19.124.0/24"):
            with self.subTest(prefix=prefix):
                observation = vendor_snapshot()
                table = observation["srl-tenant.json"]["network-instance"][0]["route-table"]
                competitor = copy.deepcopy(table["ipv4-unicast"]["route"][0])
                competitor.update({"ipv4-prefix": prefix, "route-type": "static",
                                   "route-owner": "static_mgr"})
                table["ipv4-unicast"]["route"].append(competitor)
                with self.assertRaisesRegex(ValueError, "competing route covers reverse probe"):
                    oracle.vendor_l3_fib(observation["srl-tenant.json"], observation["srl-default-fib.json"])

    def test_vendor_fib_allows_unrelated_local_less_specific_and_inactive_routes(self):
        observation = vendor_snapshot()
        routes = observation["srl-tenant.json"]["network-instance"][0]["route-table"]["ipv4-unicast"]["route"]
        for prefix, kind, active in (("203.0.113.7/32", "static", True),
                                     ("198.18.10.253/32", "local", True),
                                     ("198.19.122.2/32", "local", True),
                                     ("198.19.0.0/16", "static", True),
                                     ("0.0.0.0/0", "static", True),
                                     ("198.19.121.1/32", "static", False)):
            routes.append({"ipv4-prefix": prefix, "route-type": kind, "active": active})
        oracle.vendor_l3_fib(observation["srl-tenant.json"], observation["srl-default-fib.json"])

    def test_vendor_fib_requires_canonical_ipv4_prefixes(self):
        for prefix in (None, 1234, "198.19.121.1", "198.19.121.1/24",
                       "198.19.121.0/255.255.255.0", "2001:db8::/64"):
            with self.subTest(prefix=prefix):
                observation = vendor_snapshot()
                routes = observation["srl-tenant.json"]["network-instance"][0]["route-table"]["ipv4-unicast"]["route"]
                routes.append({"ipv4-prefix": prefix, "route-type": "static", "active": True})
                with self.assertRaises(ValueError):
                    oracle.vendor_l3_fib(observation["srl-tenant.json"], observation["srl-default-fib.json"])

    def test_vendor_fib_requires_completed_programming_and_available_next_hop(self):
        for level, field, value in (
            ("route", "active", False), ("route", "route-owner", "static_mgr"),
            ("route", "origin-network-instance", "wrong-tenant"),
            ("route-programming", "suppressed", True),
            ("route-programming", "pending-operation-type", "add"),
            ("group-programming", "last-successful-operation-type", "delete"),
            ("group-programming", "suppressed", True),
            ("group", "backup-active", True), ("member", "resolved", "false"),
            ("member", "resolved", "not-applicable"),
            ("member", "resource-allocation-failed", True),
            ("hop", "resource-allocation-failed", True), ("hop", "type", "discard"),
            ("hop", "ip-address", "10.0.119.99"), ("vxlan", "vni", 10010),
            ("vxlan", "interface", "vxlan1.10"), ("vxlan", "destination-mac", REMOTE_MAC),
        ):
            with self.subTest(level=level, field=field):
                observation = vendor_snapshot()
                table = observation["srl-tenant.json"]["network-instance"][0]["route-table"]
                route = table["ipv4-unicast"]["route"][0]
                group = table["next-hop-group"][0]
                hop = table["next-hop"][0]
                target = {"route": route, "route-programming": route["fib-programming"],
                          "group": group, "group-programming": group["fib-programming"],
                          "member": group["next-hop"][0], "hop": hop,
                          "vxlan": hop["vxlan-encapsulation"]}[level]
                target[field] = value
                with self.assertRaises(ValueError):
                    oracle.vendor_l3_fib(observation["srl-tenant.json"], observation["srl-default-fib.json"])

    def test_vendor_export_withdrawal_preserves_the_local_endpoint(self):
        observation = snapshot()
        withdraw(observation)
        oracle.vendor_l3_rib(observation["srl-rib.json"], REMOTE_MAC, "remote-withdrawn")
        oracle.vendor_l3_fib(observation["srl-tenant.json"], observation["srl-default-fib.json"])
        for prefix in ("198.19.120.0/24", "198.19.120.2/32", "198.19.123.2/32"):
            with self.subTest(prefix=prefix):
                bad = copy.deepcopy(observation)
                table = bad["srl-tenant.json"]["network-instance"][0]["route-table"]
                table["ipv4-unicast"]["route"] = [r for r in table["ipv4-unicast"]["route"]
                                                 if r["ipv4-prefix"] != prefix]
                with self.assertRaisesRegex(ValueError, "connected prefix " + prefix):
                    oracle.vendor_l3_fib(bad["srl-tenant.json"], bad["srl-default-fib.json"])


if __name__ == "__main__":
    unittest.main()
