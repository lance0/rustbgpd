"""Exercise the capability-section rules of the v1 stable-surface checker."""

import contextlib
import copy
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check-v1-stable-surface.py"
SPEC = importlib.util.spec_from_file_location("check_v1_stable_surface", SCRIPT)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class CapabilitySectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = checker.load_json(checker.INVENTORY_PATH)
        cls.legs = checker.evidence_index.load_legs(checker.ROOT)

    def rejected(self, inventory, expected):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            checker.check_capabilities(inventory, self.legs)
        self.assertIn(expected, stderr.getvalue())

    def row(self, row_id):
        inventory = copy.deepcopy(self.inventory)
        rows = inventory["capabilities"]["rows"]
        return inventory, next(row for row in rows if row["id"] == row_id)

    def test_live_inventory_passes(self):
        checker.check_capabilities(self.inventory, self.legs)

    def test_row_cannot_write_a_compatibility_label(self):
        inventory, row = self.row("flowspec-controller")
        row["classification"] = "stable"
        self.rejected(inventory, "compatibility is read from the inventory")

    def test_stable_is_not_a_behavior_claim(self):
        inventory, row = self.row("flowspec-controller")
        row["evidence"][0]["claims"].append("stable")
        self.rejected(inventory, "stability is never a claim")

    def test_projection_cannot_exceed_the_leg_declaration(self):
        inventory, row = self.row("bmp-base-export")
        row["evidence"][0]["claims"].append("selected")
        self.rejected(inventory, "projects claim 'selected' that leg m24-bmp-frr does not declare")

    def test_dangling_and_duplicate_references_fail(self):
        cases = [
            (lambda row: row.update(roles=["flowspec"]), "unknown role 'flowspec'"),
            (lambda row: row.update(surfaces=["InjectionService.AddFlowSpecs"]), "not inventoried"),
            (lambda row: row.update(evidence=[{"leg": "m22", "claims": ["stored"]}]),
             "with no driver header"),
            (lambda row: row.update(evidence=row["evidence"] * 2), "repeats evidence leg"),
            (lambda row: row.update(evidence=[]), "needs evidence"),
            (lambda row: row.update(excludes=[]), "must state what it does not cover"),
            (lambda row: row.update(id="FlowSpec"), "must be a lowercase slug"),
            (lambda row: row.update(id="bmp-base-export"), "duplicate capability id"),
        ]
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                inventory, row = self.row("flowspec-controller")
                mutate(row)
                self.rejected(inventory, expected)

    def test_malformed_evidence_values_fail_closed(self):
        cases = [
            ({"leg": ["m14-rr-frr"], "claims": ["stored"]}, "leg must be a string"),
            ({"leg": {"id": "m14-rr-frr"}, "claims": ["stored"]}, "leg must be a string"),
            ({"leg": "m14-rr-frr", "claims": [["stored"]]}, "distinct strings"),
            ({"leg": "m14-rr-frr", "claims": [{"key": "stored"}]}, "distinct strings"),
            ({"leg": "m14-rr-frr", "claims": [1]}, "distinct strings"),
            ({"leg": "m14-rr-frr", "claims": "stored"}, "distinct strings"),
        ]
        for item, expected in cases:
            with self.subTest(item=item):
                inventory, row = self.row("unicast-route-reflection")
                row["evidence"] = [item]
                self.rejected(inventory, expected)

    def test_section_shape(self):
        inventory = copy.deepcopy(self.inventory)
        inventory["capabilities"]["stable"] = []
        self.rejected(inventory, "exactly 'purpose' and 'rows'")
        del inventory["capabilities"]
        self.rejected(inventory, "exactly 'purpose' and 'rows'")

    def test_inventory_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "inventory.json"
            path.write_text(json.dumps({"a": 1})[:-1] + ', "a": 2}')
            stderr = io.StringIO()
            original = checker.ROOT
            checker.ROOT = Path(temp)
            try:
                with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
                    checker.load_json(path)
            finally:
                checker.ROOT = original
            self.assertIn("duplicate keys ['a']", stderr.getvalue())


class EvpnReflectorRoleTests(unittest.TestCase):
    """The scoped EVPN reflector set pins Types 1-5 fields, not Type 6/SRv6 views."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = checker.load_json(checker.INVENTORY_PATH)
        proto = checker.strip_proto_comments((checker.ROOT / "proto/rustbgpd.proto").read_text())
        cls.services = checker.parse_services(proto)
        cls.definitions = checker.parse_proto_definitions(proto)
        metrics_path = checker.ROOT / cls.inventory["metrics"]["source"]
        cls.metric_source = checker.strip_rust_comments(metrics_path.read_text())

    def evpn_entry(self, inventory):
        return next(
            entry
            for entry in inventory["grpc"]["scoped_rr_only_method_sets"]
            if "ListReceivedEvpnRoutes" in entry["methods"]
        )

    def check(self, inventory=None, definitions=None):
        # Isolate the EVPN set: the stable EventService graph also reaches
        # EvpnRouteEntry through the alpha BgpEvent.evpn payload.
        inventory = copy.deepcopy(inventory or self.inventory)
        inventory["grpc"]["stable_method_sets"] = []
        inventory["grpc"]["scoped_rr_only_method_sets"] = [self.evpn_entry(inventory)]
        checker.check_method_sets(inventory, self.services, definitions or self.definitions)

    def test_live_method_sets_pass(self):
        checker.check_method_sets(self.inventory, self.services, self.definitions)

    def rejected(self, action, expected):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            action()
        self.assertIn(expected, stderr.getvalue())

    def edited(self, message, old, new):
        definitions = dict(self.definitions)
        self.assertIn(old, definitions[message])
        definitions[message] = definitions[message].replace(old, new)
        return definitions

    def test_live_inventory_passes(self):
        self.check()
        checker.check_metrics(self.inventory, self.metric_source)

    def test_deferred_unpaged_loc_rib_rpc_cannot_join_the_role(self):
        inventory = copy.deepcopy(self.inventory)
        self.evpn_entry(inventory)["methods"].append("ListEvpnRoutes")
        self.rejected(
            lambda: self.check(inventory),
            "method ListEvpnRoutes takes ListEvpnRequest, not the profiled request",
        )

    def test_promoted_field_change_fails(self):
        for old, new in (("string rd = 2;", ""), ("string mac = 5;", "bytes mac = 5;")):
            with self.subTest(old=old):
                definitions = self.edited("EvpnRouteEntry", old, new)
                self.rejected(
                    lambda: self.check(definitions=definitions),
                    "stable protobuf message graph changed for RibService",
                )

    def test_change_confined_to_excluded_fields_passes(self):
        definitions = self.edited("EvpnRouteEntry", "EvpnSmetView smet = 18;", "bytes smet = 19;")
        definitions["EvpnSmetView"] += " "
        definitions["PrefixSidView"] = definitions["PrefixSidView"].replace(
            "bytes raw_value = 1;", "string raw_value = 1;"
        )
        self.check(definitions=definitions)

    def test_excluded_field_must_exist_and_stay_explicitly_unstable(self):
        definitions = self.edited("EvpnRouteEntry", "EvpnSmetView smet = 18;", "")
        self.rejected(
            lambda: self.check(definitions=definitions),
            "excluded protobuf field 'EvpnRouteEntry.smet' disappeared",
        )
        inventory = copy.deepcopy(self.inventory)
        inventory["grpc"]["explicitly_unstable_message_fields"].remove("EvpnRouteEntry.smet")
        self.rejected(lambda: self.check(inventory), "not explicitly unstable")

    def test_profiled_request_field_must_exist(self):
        definitions = self.edited(
            "ListPeerEvpnRoutesRequest", "route_type_filter = 2", "route_types = 2"
        )
        self.rejected(
            lambda: self.check(definitions=definitions),
            "stable request field 'ListPeerEvpnRoutesRequest.route_type_filter' disappeared",
        )

    def test_metric_floor_detects_name_type_and_label_drift(self):
        cases = [
            (self.metric_source.replace('"bgp_rib_prefixes"', '"bgp_rib_paths"'), None,
             "pinned metric bgp_rib_prefixes disappeared"),
            (self.metric_source.replace(
                'IntGaugeVec::new(\n            Opts::new(\n                "bgp_gr_stale_routes"',
                'IntCounterVec::new(\n            Opts::new(\n                "bgp_gr_stale_routes"'),
             None, "pinned metric bgp_gr_stale_routes changed type"),
            (self.metric_source, ["peer"], "pinned metric bgp_rib_prefixes changed labels"),
        ]
        for source, labels, expected in cases:
            with self.subTest(expected=expected):
                self.assertNotEqual((source, labels), (self.metric_source, None))
                inventory = copy.deepcopy(self.inventory)
                if labels is not None:
                    series = inventory["metrics"]["scoped_rr_only_series"]
                    next(s for s in series if s["name"] == "bgp_rib_prefixes")["labels"] = labels
                self.rejected(lambda: checker.check_metrics(inventory, source), expected)


if __name__ == "__main__":
    unittest.main()
