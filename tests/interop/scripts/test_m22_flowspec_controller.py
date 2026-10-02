#!/usr/bin/env python3
"""Negative controls for the controller lab's content comparisons."""

import copy
import json
import struct
import unittest

import m22_flowspec_controller as controller


def observed(request):
    row = copy.deepcopy(request)
    row["peerAddress"] = "0.0.0.0"
    bits = struct.unpack("!I", struct.pack("!f", row["actions"][0]["trafficRate"]["rate"]))[0]
    row["extendedCommunities"] = [str(0x8006000000000000 | bits)]
    return row


class ControllerOracleTests(unittest.TestCase):
    def test_exact_dual_afi_rows(self):
        for family in controller.FAMILIES:
            request = controller.rule(family, 1)
            controller.assert_routes([observed(request)], [request], {})

    def test_equal_count_is_insufficient(self):
        request = controller.rule("IPV4", 1)
        for mutation in (
            lambda row: row["components"][0].update(prefix="198.18.2.0/24"),
            lambda row: row["components"][2].update(value="=443"),
            lambda row: row["actions"][0]["trafficRate"].update(rate=0),
            lambda row: row.update(communities=[controller.REWRITE]),
            lambda row: row.update(peerAddress="10.0.1.2"),
            lambda row: row.update(extendedCommunities=["0"]),
        ):
            row = observed(request)
            mutation(row)
            with self.subTest(row=row), self.assertRaises(AssertionError):
                controller.assert_routes([row], [request], {})

    def test_duplicate_rows_do_not_hide_missing_rule(self):
        requests = [controller.rule("IPV6", n) for n in (1, 2)]
        with self.assertRaises(AssertionError):
            controller.assert_routes([observed(requests[0])] * 2, requests, {})

    def test_frr_rejects_count_only_and_invalid_paths(self):
        for document in (
            {"totalRoutes": 1},
            {"totalRoutes": 1, "routes": {"rule": [{"valid": False}]}},
            {"totalRoutes": 1, "routes": {"rule": [{"valid": True}, {"valid": True}]}},
        ):
            with self.subTest(document=document), self.assertRaises((AssertionError, KeyError)):
                controller.frr_routes(document)

    def test_frr_content_and_complete_detail_sequence(self):
        request = controller.rule("IPV6", 1)
        prefix = request["components"][0]["prefix"]
        fields = {"to": prefix + "/off 0", "proto": "= 6 ", "dstp": "= 80 "}
        details = controller.frr_details(json.dumps([
            fields, {"ecomlist": "65001:100 FS:rate 1000.000000"}, {"time": "00:00:01"}
        ]))
        fixture = {"frr": {"totalRoutes": 1, "routes": {"nlri": [dict(fields, valid=True, bestpath=True)]}},
                   "frr_details": details}
        controller.assert_frr(fixture, [request])
        for field, value in (("proto", "= 17 "), ("dstp", "= 443 "),
                             ("ecomlist", "65001:100 FS:rate 2000.000000"),
                             ("ecomlist", "FS:rate 1000.000000")):
            broken = copy.deepcopy(fixture)
            broken["frr_details"][prefix][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(AssertionError):
                controller.assert_frr(broken, [request])
        with self.assertRaises((AssertionError, json.JSONDecodeError)):
            controller.frr_details(json.dumps([fields, {"ecomlist": "x"}]) + "bad trailing data")


if __name__ == "__main__":
    unittest.main()
