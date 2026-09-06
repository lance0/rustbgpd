#!/usr/bin/env python3
"""Offline controls for typed M111 evidence; all inputs here are synthetic."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import m111_typed_visibility as oracle


def fixture():
    wire = {"schema": "m111-wire/1", "families": {}}
    allocated, files = {}, {}
    for family, api_family in oracle.FAMILIES.items():
        v4 = family == "vpnv4"
        function, behavior = (1, 19) if v4 else (2, 18)
        label = function << 4
        sid = f"2001:db8:111:1:{function}::"
        raw = "0500220001001e0020010db80111000100000000000000000000"
        raw += f"{behavior:02x}00010006281810001040"
        nlri = "700001030000fde90000006fc6336f" if v4 else "980002030000fde90000006f20010db801111000"
        evidence = {"prefix": "198.51.111.0/24" if v4 else "2001:db8:111:1000::/64",
                    "rd": "65001:111", "nlri_hex": nlri,
                    "next_hop_hex": "000000000000000020010db8011100100000000000000002",
                    "prefix_sid_hex": raw, "advertised_sid": "2001:db8:111:1::",
                    "service_sid": sid, "endpoint_behavior": behavior,
                    "structure": [40, 24, 16, 0, 16, 64], "transposed_function": function}
        wire["families"][family] = evidence
        allocated[sid] = {"sid": sid, "behavior": "End.DT4" if v4 else "End.DT6",
                          "locator": "srv6-proof", "context": {"vrfName": "vrf111", "table": 111},
                          "clients": [{"protocol": "bgp"}]}
        row = {"afi_safi": api_family, "route_distinguisher": "65001:111",
               "route_distinguisher_bytes": "0000fde90000006f", "prefix": evidence["prefix"],
               "labels": [label], "next_hop": "2001:db8:111:10::2",
               "peer_address": "2001:db8:111:10::2", "prefix_sid": {
                   "raw_value": raw, "flags": 192, "services": [{"tlv_type": 5, "sids": [{
                       "sid_value": "2001:db8:111:1::", "endpoint_behavior": behavior,
                       "flags": 0, "structures": [dict(zip(oracle.STRUCTURE_FIELDS, [40, 24, 16, 0, 16, 64], strict=True))],
                   }]}]}}
        files[f"baseline-{family}-rr.json"] = [row]
        files[f"{family}-count-1-rr.json"] = copy.deepcopy([row])
        files[f"{family}-count-0-rr.json"] = []
    return {"wire.json": wire, "frr-sids.json": allocated, **files}


class TypedVisibilityTests(unittest.TestCase):
    def check(self, files):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, value in files.items():
                (directory / name).write_text(json.dumps(value), encoding="utf-8")
            return oracle.verify(directory)

    def test_typed_dual_family_and_survivor(self):
        result = self.check(fixture())
        self.assertEqual(result["families"]["vpnv4"]["service_sid"], "2001:db8:111:1:1::")
        self.assertEqual(result["families"]["vpnv6"]["service_sid"], "2001:db8:111:1:2::")
        self.assertTrue(result["vpnv4_survives_vpnv6_withdrawal"])

    def test_wrong_route_identity_and_labels(self):
        for field, value in (("afi_safi", "l3vpn_ipv6_unicast"), ("labels", [1]),
                             ("peer_address", "2001:db8::1"), ("next_hop", "2001:db8::2"),
                             ("route_distinguisher", "65001:112"), ("prefix", "198.51.112.0/24"),
                             ("route_distinguisher_bytes", "0000fde900000070"), ("stale", True),
                             ("llgr_stale", True), ("path_id", 1)):
            with self.subTest(field=field):
                files = fixture()
                files["baseline-vpnv4-rr.json"][0][field] = value
                with self.assertRaises(ValueError):
                    self.check(files)

    def test_missing_or_wrong_typed_service(self):
        for mutation in ("missing", "raw", "flags", "error", "type", "sid", "behavior",
                         "sid_flags", "structure", "extra_service"):
            with self.subTest(mutation=mutation):
                files = fixture()
                row = files["baseline-vpnv4-rr.json"][0]
                view = row["prefix_sid"]
                sid = view["services"][0]["sids"][0]
                if mutation == "missing": del row["prefix_sid"]
                elif mutation == "raw": view["raw_value"] = "00"
                elif mutation == "flags": view["flags"] = 224
                elif mutation == "error": view["decode_error"] = "bad framing"
                elif mutation == "type": view["services"][0]["tlv_type"] = 6
                elif mutation == "sid": sid["sid_value"] = "2001:db8:111:1:1::"
                elif mutation == "behavior": sid["endpoint_behavior"] = 18
                elif mutation == "sid_flags": sid["flags"] = 1
                elif mutation == "structure": sid["structures"][0]["transposition_offset"] = 48
                elif mutation == "extra_service": view["services"].append(copy.deepcopy(view["services"][0]))
                with self.assertRaises(ValueError):
                    self.check(files)

    def test_missing_baseline_or_survivor_and_duplicate_route(self):
        for name in ("baseline-vpnv4-rr.json", "baseline-vpnv6-rr.json", "vpnv4-count-1-rr.json"):
            with self.subTest(name=name):
                files = fixture()
                del files[name]
                with self.assertRaises(OSError): self.check(files)
                files = fixture()
                files[name] *= 2
                with self.assertRaises(ValueError): self.check(files)
                files[name] = []
                with self.assertRaises(ValueError): self.check(files)

    def test_wrong_allocation_or_reconstructed_sid(self):
        for mutation in ("missing", "behavior", "locator", "vrf", "table", "client", "wire_sid"):
            with self.subTest(mutation=mutation):
                files = fixture()
                allocation = files["frr-sids.json"]["2001:db8:111:1:1::"]
                if mutation == "missing": files["frr-sids.json"] = {}
                elif mutation == "behavior": allocation["behavior"] = "End.DT6"
                elif mutation == "locator": allocation["locator"] = "other"
                elif mutation == "vrf": allocation["context"]["vrfName"] = "other"
                elif mutation == "table": allocation["context"]["table"] = 112
                elif mutation == "client": allocation["clients"] = []
                elif mutation == "wire_sid": files["wire.json"]["families"]["vpnv4"]["service_sid"] = "2001:db8:111:1:2::"
                with self.assertRaises(ValueError): self.check(files)

    def test_withdrawn_typed_route_remains(self):
        for family in oracle.FAMILIES:
            with self.subTest(family=family):
                files = fixture()
                files[f"{family}-count-0-rr.json"] = files[f"baseline-{family}-rr.json"]
                with self.assertRaises(ValueError): self.check(files)


if __name__ == "__main__":
    unittest.main()
