#!/usr/bin/env python3
"""Exercise the exact M118 oracle against valid and plausibly broken observations."""

import copy
from pathlib import Path
import tomllib
import unittest

import m118_bundle_oracle as oracle


def peer_rib():
    rib = {}
    for tag in (10, 20):
        rd = {"type": 1, "admin": oracle.VTEP, "assigned": tag}
        attrs = [{"type": 16, "value": [{"type": 0, "subtype": 2, "value": "65000:100"},
                                         {"type": 3, "subtype": 12, "tunnel_type": 8}]},
                 {"type": 14, "afi": 25, "safi": 70, "nexthop": oracle.VTEP}]
        mac_key = f"[type:macadv][rd:{oracle.VTEP}:{tag}][etag:{tag}][mac:{oracle.LOCAL_MAC}]"
        imet_key = f"[type:multicast][rd:{oracle.VTEP}:{tag}][etag:{tag}][ip:{oracle.VTEP}]"
        rib[mac_key] = [{"nlri": {"type": 2, "value": {
            "rd": rd, "esi": "single-homed", "etag": tag,
            "mac": oracle.LOCAL_MAC, "labels": [10000 + tag],
        }}, "attrs": copy.deepcopy(attrs)}]
        rib[imet_key] = [{"nlri": {"type": 3, "value": {
            "rd": rd, "etag": tag, "ip": oracle.VTEP,
        }}, "attrs": [*copy.deepcopy(attrs), {
            "type": 22, "label": 10000 + tag, "tunnel-type": 6,
            "tunnel-id": oracle.VTEP, "is-leaf-info-required": False,
        }]}]
    return rib


def fdb_rows(tags=(10, 20)):
    return "\n".join(line for tag in tags for line in (
        f"{oracle.REMOTE_MAC} dev vxlan{10000 + tag} vlan {tag} master brbundle extern_learn",
        f"{oracle.REMOTE_MAC} dev vxlan{10000 + tag} dst {oracle.PEER} self extern_learn",
    ))


def drop_snapshot():
    members = [{"vni": 10000 + tag, "ethernet_tag": tag, "readiness": "ready",
                "service_interface": "vlan_aware_bundle", "remote_route_drop_counts": []}
               for tag in (10, 20)]
    members[0]["remote_route_drop_counts"] = [
        {"reason": reason, "count": count} for reason, count in (
            ("ethernet_tag_mismatch", 1), ("vni_mismatch", 1), ("multihoming_unsupported", 2))]
    vrfs = [{"name": "negative", "readiness": "ready", "installed_routes_count": 0,
             "remote_prefix_drop_counts": [{"reason": "non_zero_ethernet_tag", "count": 1}]}]
    return members, vrfs


class BundleOracleTests(unittest.TestCase):
    def test_valid_decoded_peer_fields(self):
        oracle.originated(peer_rib())

    def test_each_load_bearing_decoded_field_must_match(self):
        good = peer_rib()
        for key, paths in good.items():
            broken = copy.deepcopy(good)
            broken[key][0]["nlri"]["type"] = 5
            with self.subTest(key=key, field="route_type"), self.assertRaises(ValueError):
                oracle.originated(broken)
            value = paths[0]["nlri"]["value"]
            for field in value:
                with self.subTest(key=key, field=field):
                    broken = copy.deepcopy(good)
                    del broken[key][0]["nlri"]["value"][field]
                    with self.assertRaises(ValueError):
                        oracle.originated(broken)
        key = next(k for k in good if "multicast" in k)
        for field in ("label", "tunnel-type", "tunnel-id", "is-leaf-info-required"):
            with self.subTest(pmsi=field):
                broken = copy.deepcopy(good)
                del next(a for a in broken[key][0]["attrs"] if a["type"] == 22)[field]
                with self.assertRaises(ValueError):
                    oracle.originated(broken)

    def test_each_decoded_path_requires_one_evpn_vtep_next_hop(self):
        good = peer_rib()
        for key in good:
            for case in ("missing", "wrong", "duplicate", "wrong_afi", "wrong_safi"):
                with self.subTest(key=key, case=case):
                    broken = copy.deepcopy(good)
                    attrs = broken[key][0]["attrs"]
                    mp_reach = next(a for a in attrs if a["type"] == 14)
                    if case == "missing":
                        attrs.remove(mp_reach)
                    elif case == "duplicate":
                        attrs.append(copy.deepcopy(mp_reach))
                    else:
                        field = {"wrong": "nexthop", "wrong_afi": "afi", "wrong_safi": "safi"}[case]
                        mp_reach[field] = "10.0.118.3" if field == "nexthop" else 1
                    with self.assertRaises(ValueError):
                        oracle.originated(broken)

    def test_each_decoded_path_requires_only_vxlan_encapsulation(self):
        good = peer_rib()
        for key in good:
            for case in ("missing", "nvgre", "mpls", "additional"):
                with self.subTest(key=key, case=case):
                    broken = copy.deepcopy(good)
                    communities = broken[key][0]["attrs"][0]["value"]
                    encap = next(c for c in communities if c["type"] == 3)
                    if case == "missing":
                        communities.remove(encap)
                    elif case == "additional":
                        communities.append({"type": 3, "subtype": 12, "tunnel_type": 10})
                    else:
                        encap["tunnel_type"] = 9 if case == "nvgre" else 10
                    with self.assertRaises(ValueError):
                        oracle.originated(broken)

    def test_missing_collapsed_or_extra_mac_and_wrong_rt_fail(self):
        good = peer_rib()
        key = next(k for k in good if "macadv" in k)
        for case in ("missing", "extra", "wrong_rt", "foreign_rt1", "foreign_rt2", "extra_path"):
            with self.subTest(case=case):
                broken = copy.deepcopy(good)
                if case == "missing":
                    del broken[key]
                elif case == "extra":
                    broken[f"[etag:30][mac:{oracle.LOCAL_MAC}]"] = broken[key]
                elif case == "wrong_rt":
                    broken[key][0]["attrs"][0]["value"][0]["value"] = "65000:200"
                elif case in ("foreign_rt1", "foreign_rt2"):
                    broken[key][0]["attrs"][0]["value"].append({
                        "type": int(case[-1]), "subtype": 2,
                        "value": "10.0.118.3:200" if case == "foreign_rt1" else "4200000000:200",
                    })
                else:
                    broken[key].append(copy.deepcopy(broken[key][0]))
                with self.assertRaises(ValueError):
                    oracle.originated(broken)

    def test_extra_vtep_imet_with_other_tag_or_rd_fails(self):
        good = peer_rib()
        key = next(k for k in good if "multicast" in k and "[etag:10]" in k)
        for case, extra in (
            ("other_tag", f"[type:multicast][rd:{oracle.VTEP}:10][etag:30][ip:{oracle.VTEP}]"),
            ("other_rd", f"[type:multicast][rd:{oracle.VTEP}:99][etag:10][ip:{oracle.VTEP}]"),
        ):
            with self.subTest(case=case):
                broken = copy.deepcopy(good)
                broken[extra] = copy.deepcopy(good[key])
                with self.assertRaises(ValueError):
                    oracle.originated(broken)

    def test_peer_injected_routes_are_not_vtep_originated(self):
        rib = peer_rib()
        rib[f"[type:macadv][rd:{oracle.PEER}:10][etag:10][mac:{oracle.REMOTE_MAC}]"] = [
            {"nlri": {"type": 2}, "attrs": [{"type": 14, "afi": 25, "safi": 70, "nexthop": oracle.PEER}]}]
        oracle.originated(rib)

    def test_local_withdraw_preserves_other_mac_and_both_imets(self):
        rib = peer_rib()
        key = next(k for k in rib if "macadv" in k and "[etag:10]" in k)
        with self.assertRaises(ValueError):
            oracle.originated(rib, (20,))
        del rib[key]
        oracle.originated(rib, (20,))
        del rib[next(k for k in rib if "multicast" in k and "[etag:10]" in k)]
        with self.assertRaises(ValueError):
            oracle.originated(rib, (20,))

    def test_both_fdb_members_and_scoped_withdraw(self):
        oracle.fdb(fdb_rows())
        oracle.fdb(fdb_rows((20,)), (20,))
        with self.assertRaises(ValueError):
            oracle.fdb(fdb_rows(), (20,))
        with self.assertRaises(ValueError):
            oracle.fdb(fdb_rows((20,)) + f"\n{oracle.REMOTE_MAC} dev access10 vlan 10 master brbundle extern_learn", (20,))

    def test_missing_wrong_vlan_wrong_destination_and_unsupported_fdb_fail(self):
        good = fdb_rows()
        for broken in (
            fdb_rows((10,)), good.replace("vlan 10", "vlan 20"),
            good.replace(oracle.PEER, "10.0.118.3"), good.replace("extern_learn", "static"),
            good.replace("master brbundle", "master wrongbridge"),
            good + f"\n{oracle.NEGATIVE_MACS[0]} dev vxlan10010 master brbundle",
            good + f"\n{oracle.REMOTE_MAC} dev vxlan10010 vlan 20 master brbundle extern_learn",
            good + f"\n{oracle.REMOTE_MAC} dev vxlan10030 vlan 30 master brbundle extern_learn",
        ):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                oracle.fdb(broken)

    def test_unsupported_inputs_must_be_observed_in_one_exact_rib_row(self):
        routes = [
            {"route_type": 2, "rd": f"{oracle.PEER}:301", "ethernet_tag": "30",
             "label": 10010, "mac": oracle.NEGATIVE_MACS[0]},
            {"route_type": 2, "rd": f"{oracle.PEER}:302", "ethernet_tag": "10",
             "label": 10030, "mac": oracle.NEGATIVE_MACS[1]},
            {"route_type": 2, "rd": f"{oracle.PEER}:303", "ethernet_tag": "10",
             "label": 10010, "mac": oracle.NEGATIVE_MACS[2], "esi": "00:01:02:03:04:05:06:07:08:09"},
            {"route_type": 1, "rd": f"{oracle.PEER}:304", "ethernet_tag": "10",
             "label": 10010, "esi": "00:01:02:03:04:05:06:07:08:09"},
            {"route_type": 5, "rd": f"{oracle.PEER}:500", "ethernet_tag": "10",
             "label": 10500, "prefix": "203.0.118.0/24"},
        ]
        for row in routes:
            row["peer"] = oracle.PEER
        oracle.retained(routes)
        for index, row in enumerate(routes):
            for field in row:
                with self.subTest(index=index, field=field):
                    broken = copy.deepcopy(routes)
                    del broken[index][field]
                    with self.assertRaises(ValueError):
                        oracle.retained(broken)

    def test_exact_drop_snapshot_and_no_installed_type5(self):
        oracle.drops(*drop_snapshot())
        for case in ("missing", "wrong_member", "extra_reason", "not_ready", "type5_installed"):
            with self.subTest(case=case):
                members, vrfs = drop_snapshot()
                if case == "missing":
                    members[0]["remote_route_drop_counts"].pop()
                elif case == "wrong_member":
                    members[1]["remote_route_drop_counts"] = members[0]["remote_route_drop_counts"]
                elif case == "extra_reason":
                    vrfs[0]["remote_prefix_drop_counts"].append({"reason": "other", "count": 1})
                elif case == "not_ready":
                    members[0]["readiness"] = "not-ready"
                else:
                    vrfs[0]["installed_routes_count"] = 1
                with self.assertRaises(ValueError):
                    oracle.drops(members, vrfs)

    def test_zero_baseline_cannot_include_preexisting_drops(self):
        members, vrfs = drop_snapshot()
        with self.assertRaises(ValueError):
            oracle.drops(members, vrfs, negative=False)
        for row in members:
            row["remote_route_drop_counts"] = []
        vrfs[0]["remote_prefix_drop_counts"] = []
        oracle.drops(members, vrfs, negative=False)

    def test_fixture_is_two_members_with_a_separate_type5_control(self):
        config = tomllib.loads((Path(__file__).parent.parent / "configs/rustbgpd-m118-bundle-vtep.toml").read_text())
        members = config["evpn_instances"]
        self.assertEqual([(m["vni"], m["ethernet_tag"], m["bridge_vlan"]) for m in members],
                         [(10010, 10, 10), (10020, 20, 20)])
        self.assertEqual([m["route_targets"] for m in members], [["65000:100"], ["65000:100"]])
        self.assertTrue(all(m["service_interface"] == "vlan_aware_bundle" and "ip_vrf" not in m for m in members))
        self.assertEqual(config["evpn_ip_vrfs"][0]["route_targets"], ["65000:500"])


if __name__ == "__main__":
    unittest.main()
