#!/usr/bin/env python3
"""Counterexamples for the M119 SR Linux and kernel evidence oracle."""

import copy
import json
from pathlib import Path
import tempfile
import shutil
import unittest

import m119_bundle_oracle as oracle


def rib_snapshot():
    """Minimal SR Linux 25.10.1 local-rib and shared attribute-set schema."""
    routes = {"mac-ip-route": [], "imet-route": []}
    attributes = []
    for vtep, mac, local in (("10.0.119.1", "02:AA:BB:01:19:01", True),
                             ("192.0.2.2", "02:AA:BB:01:19:02", False)):
        for tag, remote_rd in ((10, 100), (20, 101)):
            for kind in routes:
                index = str(len(attributes) + 1)
                attr = {"index": index, "next-hop": vtep, "communities": {
                    "ext-community": ["target:65000:100", "bgp-tunnel-encap:VXLAN"]}}
                row = {"route-distinguisher": f"{vtep}:{tag if local else remote_rd}",
                       "ethernet-tag-id": tag, "neighbor": vtep if local else "0.0.0.0",
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
                routes[kind].append(row)
                attributes.append(attr)
    return {"network-instance": [{"name": "default", "bgp-rib": {
        "afi-safi": [{"afi-safi-name": "evpn", "evpn": {"local-rib": routes}}],
        "attr-sets": {"attr-set": attributes}}}]}


def fdb_snapshot(tags=(10, 20)):
    return "\n".join(line for tag in tags for line in (
        f"02:aa:bb:01:19:02 dev vxlan{10000 + tag} vlan {tag} extern_learn master brbundle",
        f"02:aa:bb:01:19:02 dev vxlan{10000 + tag} dst 192.0.2.2 self extern_learn permanent",
        f"00:00:00:00:00:00 dev vxlan{10000 + tag} dst 192.0.2.2 self extern_learn permanent",
    ))


def imported_snapshots():
    """Minimal programmed MAC and BUM destination views, including a local MAC."""
    snapshots = {}
    members = []
    for tag in (10, 20):
        snapshots[f"srl-bd{tag}.json"] = {"network-instance": [{"name": f"bd{tag}",
            "bridge-table": {"mac-table": {"mac": [
                {"address": "02:AA:BB:01:19:01", "type": "evpn", "destination-type": "vxlan",
                 "destination": f"vxlan-interface:vxlan1.{tag} vtep:10.0.119.1 vni:{10000 + tag}"},
                {"address": "02:AA:BB:01:19:02", "type": "static",
                 "destination-type": "sub-interface", "destination": f"ethernet-1/2.{tag}"},
            ]}}}]}
        members.append({"index": tag, "ingress": {"vni": 10000 + tag}, "oper-state": "up",
                        "bridge-table": {"multicast-destinations": {"destination": [
                            {"vtep": "10.0.119.1", "vni": 10000 + tag,
                             "multicast-forwarding": "BUM"}]}}})
    snapshots["srl-tunnels.json"] = {"tunnel-interface": [{"name": "vxlan1", "vxlan-interface": members}]}
    return snapshots


class BundleOracleTests(unittest.TestCase):
    def check_imported(self, snapshots, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            for name, observation in snapshots.items():
                (Path(directory) / name).write_text(json.dumps(observation))
            oracle.imported(Path(directory), **kwargs)

    def test_valid_rib_fdb_and_vendor_import(self):
        oracle.srl_rib(rib_snapshot())
        oracle.fdb(fdb_snapshot())
        self.check_imported(imported_snapshots())

    def test_attributes_must_belong_to_the_same_path(self):
        for field, wrong in (
            ("next-hop", "192.0.2.99"),
            ("communities", {"ext-community": ["target:65000:200", "bgp-tunnel-encap:VXLAN"]}),
            ("communities", {"ext-community": ["target:65000:100", "bgp-tunnel-encap:MPLS"]}),
            ("pmsi-tunnel", {"tunnel-type": "ingress-replication", "tunnel-endpoint": "10.0.119.1",
                             "label": {"value": 10020, "value-type": "vni"}}),
        ):
            with self.subTest(field=field, wrong=wrong):
                observation = rib_snapshot()
                rib = observation["network-instance"][0]["bgp-rib"]
                row = rib["afi-safi"][0]["evpn"]["local-rib"]["imet-route"][0]
                attrs = rib["attr-sets"]["attr-set"]
                redirected = copy.deepcopy(next(a for a in attrs if a["index"] == row["attr-id"]))
                redirected.update({"index": "99", field: wrong})
                attrs.append(redirected)
                row["attr-id"] = "99"
                # Correct attributes remain in the observation, but this path no longer uses them.
                with self.assertRaises(ValueError):
                    oracle.srl_rib(observation)

    def test_swapping_member_imet_attribute_ids_fails(self):
        observation = rib_snapshot()
        rows = observation["network-instance"][0]["bgp-rib"]["afi-safi"][0]["evpn"]["local-rib"]["imet-route"]
        rows[0]["attr-id"], rows[1]["attr-id"] = rows[1]["attr-id"], rows[0]["attr-id"]
        with self.assertRaises(ValueError):
            oracle.srl_rib(observation)

    def test_extra_missing_and_duplicate_routes_fail(self):
        for kind in ("mac-ip-route", "imet-route"):
            for case in ("extra", "missing", "duplicate"):
                with self.subTest(kind=kind, case=case):
                    observation = rib_snapshot()
                    rows = observation["network-instance"][0]["bgp-rib"]["afi-safi"][0]["evpn"]["local-rib"][kind]
                    if case == "missing":
                        rows.pop()
                    else:
                        extra = copy.deepcopy(rows[0])
                        if case == "extra":
                            extra["route-distinguisher"] = "10.0.119.1:30"
                            extra["ethernet-tag-id"] = 30
                        rows.append(extra)
                    with self.assertRaises(ValueError):
                        oracle.srl_rib(observation)

    def test_wrong_nlri_and_stale_or_unselected_paths_fail(self):
        for kind in ("mac-ip-route", "imet-route"):
            changes = [("ethernet-tag-id", 30), ("stale-route", True), ("pending-delete", True),
                       ("valid-route", False), ("best-route", False), ("path-id", 1)]
            if kind == "mac-ip-route":
                changes += [("mac-address", "02:AA:BB:01:19:FF"),
                            ("label1", {"value": 10030, "value-type": "vni"}),
                            ("esi", "00:01:02:03:04:05:06:07:08:09")]
            else:
                changes += [("originating-router", "192.0.2.99")]
            for index in range(4):
                for field, wrong in changes:
                    with self.subTest(kind=kind, index=index, field=field):
                        observation = rib_snapshot()
                        row = observation["network-instance"][0]["bgp-rib"]["afi-safi"][0]["evpn"]["local-rib"][kind][index]
                        row[field] = wrong
                        with self.assertRaises(ValueError):
                            oracle.srl_rib(observation)

    def test_rib_local_withdraw_keeps_imets_and_remote_routes(self):
        observation = rib_snapshot()
        routes = observation["network-instance"][0]["bgp-rib"]["afi-safi"][0]["evpn"]["local-rib"]
        with self.assertRaises(ValueError):
            oracle.srl_rib(observation, local_tags=(20,))
        routes["mac-ip-route"].pop(0)
        oracle.srl_rib(observation, local_tags=(20,))
        routes["imet-route"].pop(0)
        with self.assertRaises(ValueError):
            oracle.srl_rib(observation, local_tags=(20,))

    def test_fdb_wrong_vlan_destination_or_static_flood_fails(self):
        good = fdb_snapshot()
        static_flood = good.replace(
            "00:00:00:00:00:00 dev vxlan10010 dst 192.0.2.2 self extern_learn permanent",
            "00:00:00:00:00:00 dev vxlan10010 dst 192.0.2.2 self permanent")
        for bad in (good.replace("vlan 10", "vlan 20"), good.replace("192.0.2.2", "192.0.2.99"),
                    good.replace("master brbundle", "master wrongbridge"), static_flood,
                    good + "\n00:00:00:00:00:00 dev vxlan10010 dst 192.0.2.99 self permanent"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                oracle.fdb(bad)

    def test_fdb_scoped_withdraw_preserves_other_member(self):
        oracle.fdb(fdb_snapshot((20,)), (20,))
        with self.assertRaises(ValueError):
            oracle.fdb(fdb_snapshot(), (20,))
        with self.assertRaises(ValueError):
            oracle.fdb(fdb_snapshot((20,)))

    def test_vendor_mac_requires_programmed_matching_destination(self):
        for field, wrong in (("address", "02:AA:BB:01:19:FF"), ("type", "static"),
                             ("type", "evpn-static"), ("destination-type", "sub-interface"),
                             ("not-programmed-reason", "no-destination"),
                             ("destination", "vxlan-interface:vxlan1.20 vtep:10.0.119.1 vni:10010"),
                             ("destination", "vxlan-interface:vxlan1.10 vtep:192.0.2.99 vni:10010"),
                             ("destination", "vxlan-interface:vxlan1.10 vtep:10.0.119.1 vni:10020")):
            with self.subTest(field=field, wrong=wrong):
                snapshots = imported_snapshots()
                snapshots["srl-bd10.json"]["network-instance"][0]["bridge-table"]["mac-table"]["mac"][0][field] = wrong
                with self.assertRaises(ValueError):
                    self.check_imported(snapshots)

    def test_vendor_flood_requires_programmed_matching_bum_destination(self):
        for field, wrong in (("vtep", "192.0.2.99"), ("vni", 10020),
                             ("multicast-forwarding", "unknown-unicast"),
                             ("not-programmed-reason", "no-destination")):
            with self.subTest(field=field):
                snapshots = imported_snapshots()
                member = snapshots["srl-tunnels.json"]["tunnel-interface"][0]["vxlan-interface"][0]
                member["bridge-table"]["multicast-destinations"]["destination"][0][field] = wrong
                with self.assertRaises(ValueError):
                    self.check_imported(snapshots)

    def test_vendor_local_withdraw_keeps_flood_and_other_member(self):
        snapshots = imported_snapshots()
        with self.assertRaises(ValueError):
            self.check_imported(snapshots, local_tags=(20,))
        snapshots["srl-bd10.json"]["network-instance"][0]["bridge-table"]["mac-table"]["mac"].pop(0)
        self.check_imported(snapshots, local_tags=(20,))
        snapshots["srl-tunnels.json"]["tunnel-interface"][0]["vxlan-interface"][0]["bridge-table"]["multicast-destinations"]["destination"] = []
        with self.assertRaises(ValueError):
            self.check_imported(snapshots, local_tags=(20,))


class ReceiptReplayTests(unittest.TestCase):
    receipt = Path(__file__).resolve().parents[3] / "docs/artifacts/interop/m119-evpn-bundle-vtep-20261010T124729Z"

    def test_committed_receipt(self):
        oracle.replay(self.receipt)

    def test_incomplete_or_cached_forwarding_and_flaps_fail(self):
        for case in ("missing-direction", "packet-loss", "cached-before", "static-after", "flap", "extra-fdb"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "receipt"
                shutil.copytree(self.receipt, directory)
                ping = directory / "forwarding/ping-10-to-2.txt"
                if case == "missing-direction":
                    ping.unlink()
                elif case == "packet-loss":
                    ping.write_text(ping.read_text().replace("3 received, 0% packet loss", "1 received, 66% packet loss"))
                elif case == "cached-before":
                    path = directory / "forwarding/10-to-2/before-vtep-h10-neighbors.json"
                    path.write_text('[{"dst": "198.18.10.2", "state": ["REACHABLE"]}]')
                elif case == "static-after":
                    path = directory / "forwarding/10-to-2/vtep-h10-neighbors.json"
                    rows = json.loads(path.read_text())
                    rows[0]["state"] = ["PERMANENT"]
                    path.write_text(json.dumps(rows))
                elif case == "flap":
                    path = directory / "final/peer.json"
                    peer = json.loads(path.read_text())
                    peer["flap_count"] = 1
                    path.write_text(json.dumps(peer))
                else:
                    path = directory / "final/fdb.txt"
                    path.write_text(path.read_text() + "02:aa:bb:00:99:99 dev access20 vlan 20 master brbundle static\n")
                with self.assertRaises((ValueError, FileNotFoundError)):
                    oracle.replay(directory)


if __name__ == "__main__":
    unittest.main()
