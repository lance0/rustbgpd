#!/usr/bin/env python3
"""Negative controls for the VPN FlowSpec peer and raw-wire assertions."""

import copy
import struct
import unittest

from qualify_vpn_flowspec_gobgp import (
    check_gobgp, check_wire, expected_gobgp, expected_nlri, rule, split_nlri, wire_observations,
)


def observed(desired, family=(2, 134)):
    nlri = expected_gobgp(desired)
    return {"fixture": [{"nlri": nlri, "neighbor-ip": "192.0.2.1", "attrs": [
        {"type": 14, "afi": family[0], "safi": family[1], "value": [{"NLRI": nlri, "ID": 0}]},
        {"type": 16, "value": [{"type": 128, "subtype": 6, "as": 0, "rate": 0},
                                {"type": 0, "subtype": 2, "value": "44407:777"}]}]}]}


class VpnFlowSpecOracleTests(unittest.TestCase):
    def test_exact_rd_rt_family_and_flow_label(self):
        desired = rule(14, 40, components=[{"type": 1, "prefix": "2001:db8::/32"},
                                          {"type": 13, "value": "=74565"}])
        value = observed(desired)
        check_gobgp(value, [desired], 14, "192.0.2.1")
        mutations = [
            lambda row: row["nlri"]["rd"].update(assigned=41),
            lambda row: row["attrs"][0].update(afi=1),
            lambda row: row["attrs"][0].update(safi=133),
            lambda row: row["attrs"][1]["value"][1].update(value="44407:778"),
            lambda row: row["nlri"]["value"].pop(),
            lambda row: row.update(**{"neighbor-ip": "192.0.2.2"}),
        ]
        for mutation in mutations:
            broken = copy.deepcopy(value)
            mutation(broken["fixture"][0])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                check_gobgp(broken, [desired], 14, "192.0.2.1")

    def test_two_scopes_are_not_a_count_only_pass(self):
        desired = [rule(14, 40), rule(14, 41)]
        value = observed(desired[0])
        value["other"] = observed(desired[1])["fixture"]
        check_gobgp(value, desired, 14, "192.0.2.1")
        value["other"] = copy.deepcopy(value["fixture"])
        with self.assertRaises(ValueError):
            check_gobgp(value, desired, 14, "192.0.2.1")

    def test_rfc8956_nonzero_offset_vector(self):
        desired = rule(14, 901, components=[{"type": 2, "prefix": "::1234:5678:9a00:0/104", "offset": 64},
                                           {"type": 3, "value": "=6"}])
        self.assertEqual(expected_nlri(desired).hex(), "0000ad7700000385026840123456789a038106")
        desired["components"][0]["offset"] = 65
        self.assertEqual(expected_nlri(desired).hex(), "0000ad77000003850268412468acf134038106")

    def test_rd_inclusive_239_240_lengths_and_truncation(self):
        for length in (239, 240):
            values = [1] + list(range(1000, 1076)) if length == 239 else list(range(1000, 1077))
            desired = rule(14, length, components=[{"type": 5, "value": ",".join(f"={v}" for v in values)}])
            data = expected_nlri(desired)
            self.assertEqual(len(data), length)
            prefix = bytes([length]) if length == 239 else bytes.fromhex("f0f0")
            self.assertEqual(split_nlri(prefix + data), [(len(prefix), data)])
            with self.assertRaises(ValueError):
                split_nlri(prefix + data[:-1])
        with self.assertRaises(ValueError):
            split_nlri(bytes.fromhex("f00100"))

    def test_raw_update_keeps_family_rd_rt_and_action_together(self):
        nlri = expected_nlri(rule(14, 40))
        reach = struct.pack("!HBBB", 2, 134, 0, 0) + bytes([len(nlri)]) + nlri
        communities = bytes.fromhex("0002ad77000003098006000000000000")
        attrs = bytes([128, 14, len(reach)]) + reach + bytes([192, 16, len(communities)]) + communities
        body = bytes(2) + len(attrs).to_bytes(2, "big") + attrs
        packet = b"\xff" * 16 + struct.pack("!HB", 19 + len(body), 2) + body
        observed = wire_observations([f"0\t192.0.2.1\t192.0.2.2\t100\t{packet.hex()}"])
        self.assertEqual(observed["routes"], [{"source": "192.0.2.1", "destination": "192.0.2.2",
                         "family": [2, 134], "announce": True, "length_octets": 1, "nlri": nlri.hex(),
                         "communities": ["0002ad7700000309", "8006000000000000"]}])
        with self.assertRaises(ValueError):
            wire_observations([f"0\t192.0.2.1\t192.0.2.2\t100\t{packet[:-1].hex()}"])

    def test_wire_requires_opt_in_and_detects_vpn_leak_and_wrong_replacement(self):
        all_families = [(1, 133), (2, 133), (1, 134), (2, 134)]
        opens = [{"source": src, "destination": dst, "families": families}
                 for src, dst, families in [("d", "p", all_families), ("p", "d", all_families),
                                            ("d", "g", all_families[:2]), ("g", "d", all_families)]]
        initial = [rule(13, 40), rule(14, 40)]
        replacement = rule(14, 40, rt="44407:778")
        rows = []
        for afi, desired in zip((1, 2), initial):
            row = {"source": "d", "destination": "p", "family": [afi, 134], "announce": True,
                   "nlri": expected_nlri(desired).hex(), "communities": ["0002ad7700000309", "8006000000000000"]}
            rows.append(row)
            if afi == 2:
                rows.append(dict(row, communities=["0002ad770000030a", "8006000000000000"]))
            rows.append(dict(row, announce=False, communities=[]))
        observed = {"opens": opens, "routes": rows}
        check_wire(observed, "d", "p", "g", initial, replacement)
        mutations = [
            lambda value: value["opens"][2].update(families=all_families),
            lambda value: value["routes"].append(dict(rows[0], destination="g")),
            lambda value: value["routes"][3].update(communities=["0002ad7700000309", "8006000000000000"]),
            lambda value: value["routes"].pop(),
        ]
        for mutation in mutations:
            broken = copy.deepcopy(observed)
            mutation(broken)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                check_wire(broken, "d", "p", "g", initial, replacement)


if __name__ == "__main__":
    unittest.main()
