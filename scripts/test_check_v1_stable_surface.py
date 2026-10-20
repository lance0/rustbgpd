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
        cls.emission_sources = checker.production_rust_sources(checker.ROOT)

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
        checker.check_metrics(self.inventory, self.metric_source, self.emission_sources)

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
                    lambda definitions=definitions: self.check(definitions=definitions),
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

    def test_narrowed_set_cannot_lose_its_request_profile(self):
        cases = [
            (lambda entry: entry.pop("stable_request_values"), "stable request profile"),
            (
                lambda entry: entry.update(
                    stable_request_value=entry.pop("stable_request_values")
                ),
                "unknown keys ['stable_request_value']",
            ),
            (
                lambda entry: entry.update(
                    stable_request_values={
                        "ListPeerEvpnRoutesRequest.route_type_filter": [0, 1, 2, 3, 4, 5, 6]
                    }
                ),
                "stable request profile",
            ),
        ]
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                inventory = copy.deepcopy(self.inventory)
                mutate(self.evpn_entry(inventory))
                self.rejected(
                    lambda inventory=inventory: checker.check_method_sets(
                        inventory, self.services, self.definitions
                    ),
                    expected,
                )

    def test_best_set_cannot_lose_or_widen_its_request_profile(self):
        for profile in [None, {}, {"ListBestEvpnRoutesRequest.route_type_filter": [0, 1, 2, 3, 4, 5, 6]}]:
            with self.subTest(profile=profile):
                inventory = copy.deepcopy(self.inventory)
                entry = next(
                    entry for entry in inventory["grpc"]["scoped_rr_only_method_sets"]
                    if "ListBestEvpnRoutes" in entry["methods"]
                )
                if profile is None:
                    entry.pop("stable_request_values")
                else:
                    entry["stable_request_values"] = profile
                self.rejected(
                    lambda inventory=inventory: checker.check_method_sets(inventory, self.services, self.definitions),
                    "stable request profile",
                )

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
                self.rejected(
                    lambda inventory=inventory, source=source: checker.check_metrics(
                        inventory, source, self.emission_sources
                    ),
                    expected,
                )

    def emitted_by(self, path, old, new):
        sources = dict(self.emission_sources)
        self.assertEqual(sources[path].count(old), 1, old)
        sources[path] = sources[path].replace(old, new)
        return sources

    def test_pinned_label_value_must_be_emitted(self):
        # A misspelled inventory value has no emitting call site.
        inventory = copy.deepcopy(self.inventory)
        series = inventory["metrics"]["scoped_rr_only_series"]
        next(s for s in series if s["name"] == "bgp_rib_loc_prefixes")["label_values"] = {
            "family": ["evpnn"]
        }
        self.rejected(
            lambda: checker.check_metrics(inventory, self.metric_source, self.emission_sources),
            "pinned metric bgp_rib_loc_prefixes label family values ['evpnn']",
        )

    def test_changed_emission_fails_while_inventory_stays(self):
        cases = [
            (
                "crates/rib/src/manager/distribution/evpn.rs",
                '.set_loc_rib_prefixes("l2vpn_evpn"',
                '.set_loc_rib_prefixes("evpn"',
                "pinned metric bgp_rib_loc_prefixes label family values ['l2vpn_evpn']",
            ),
            (
                "crates/rib/src/manager/helpers.rs",
                "rustbgpd_wire::family_label(afi, safi)",
                "None::<&str>",
                "pinned metric bgp_route_refresh_stale_entries label family values ['l2vpn_evpn']",
            ),
        ]
        for path, old, new, expected in cases:
            with self.subTest(expected=expected):
                sources = self.emitted_by(path, old, new)
                self.rejected(
                    lambda sources=sources: checker.check_metrics(
                        self.inventory, self.metric_source, sources
                    ),
                    expected,
                )

    # Test-gated Rust is not production emission evidence for a pinned value.
    HELPER ='fn helper(m: &Metrics) {\n    m.set_loc_rib_prefixes("l2vpn_evpn", 1);\n}\n'
    MISSING = "pinned metric bgp_rib_loc_prefixes label family values ['l2vpn_evpn']"

    def without_live_loc_emitter(self):
        return self.emitted_by(
            "crates/rib/src/manager/distribution/evpn.rs",
            '.set_loc_rib_prefixes("l2vpn_evpn"',
            '.set_loc_rib_prefixes("evpn"',
        )

    def check_with(self, extra):
        sources = {**self.without_live_loc_emitter(), **extra}
        checker.check_metrics(self.inventory, self.metric_source, sources)

    def fixture_sources(self, declaration):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "crates/fixture/src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text(f"{declaration}\nmod live;\n")
            (source / "test_support.rs").write_text(self.HELPER)
            (source / "live.rs").write_text("")
            return checker.production_rust_sources(Path(temp))

    def test_value_emitted_only_in_a_test_gated_module_file_fails(self):
        sources = self.fixture_sources("#[cfg(test)]\nmod test_support;")
        self.assertNotIn("crates/fixture/src/test_support.rs", sources)
        self.assertIn("crates/fixture/src/live.rs", sources)
        self.rejected(lambda: self.check_with(sources), self.MISSING)

    def test_value_emitted_only_in_a_compound_test_gate_fails(self):
        for gate in ('all(test, target_os = "linux")', "any(test, feature = \"x\")", "test"):
            with self.subTest(gate=gate):
                text = checker.strip_cfg_test_items(f"#[cfg({gate})]\n{self.HELPER}")
                self.rejected(
                    lambda text=text: self.check_with({"fixture.rs": text}), self.MISSING
                )

    def test_production_emitter_still_counts(self):
        self.check_with(self.fixture_sources("mod test_support;"))
        for prefix in ("", "#[cfg(not(test))]\n", '#[cfg(feature = "test-utils")]\n'):
            with self.subTest(prefix=prefix):
                text = checker.strip_cfg_test_items(prefix + self.HELPER)
                self.check_with({"fixture.rs": text})


class MetricFloorTests(unittest.TestCase):
    """The RS/RR floor is checked like the EVPN set; diagnostic patterns stay disjoint."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = checker.load_json(checker.INVENTORY_PATH)
        metrics_path = checker.ROOT / cls.inventory["metrics"]["source"]
        cls.metric_source = checker.strip_rust_comments(metrics_path.read_text())
        cls.emission_sources = checker.production_rust_sources(checker.ROOT)

    def rejected(self, action, expected):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            action()
        self.assertIn(expected, stderr.getvalue())

    def check(self, inventory, sources=None):
        checker.check_metrics(inventory, self.metric_source, sources or self.emission_sources)

    def test_floor_pins_unicast_families_through_the_pair_helper(self):
        series = self.inventory["metrics"]["stable_series"]
        rib = next(entry for entry in series if entry["name"] == "bgp_rib_prefixes")
        self.assertEqual(rib["label_values"], {"family": ["ipv4_unicast", "ipv6_unicast"]})
        # The only unicast emitter is the constant the pair helpers loop over.
        path = "crates/rib/src/manager/helpers.rs"
        old = 'UNICAST_FAMILIES: [&str; 2] = ["ipv4_unicast", "ipv6_unicast"]'
        sources = dict(self.emission_sources)
        self.assertEqual(sources[path].count(old), 1)
        sources[path] = sources[path].replace(old, 'UNICAST_FAMILIES: [&str; 2] = ["ipv4", "ipv6"]')
        self.rejected(
            lambda: self.check(self.inventory, sources),
            # The first floor gauge fed by that constant fails.
            "pinned metric bgp_rib_adj_out_prefixes label family values ['ipv4_unicast', 'ipv6_unicast']",
        )

    def replaced(self, text, old, new, count=1):
        self.assertEqual(text.count(old), count, old)
        return text.replace(old, new)

    def test_max_prefix_and_session_state_values_are_traced(self):
        series = {entry["name"]: entry for entry in self.inventory["metrics"]["stable_series"]}
        self.assertEqual(
            series["bgp_max_prefix_usage"]["label_values"]["stage"], ["accepted", "received"]
        )
        self.assertIn("rtc", series["bgp_max_prefix_blocked_total"]["label_values"]["family"])
        self.assertIn(
            "open_sent", series["bgp_peer_session_state"]["label_values"]["state"]
        )
        # Each edit is seeded at one emission path; the first series it feeds fails.
        metric_cases = [
            # The pass-through helper swaps two labels.
            ("    [peer, family, stage]", "    [peer, stage, family]", 1,
             "pinned metric bgp_max_prefix_blocked_total label family values"),
            # The helper no longer returns an array the checker can map.
            ("    [peer, family, stage]", "    labels_of(peer, family, stage)", 1,
             "pinned metric bgp_max_prefix_blocked_total label family values"),
            # A `let`-bound call to an unknown helper is no evidence.
            ("let labels = max_prefix_label_values(peer, family, stage);",
             "let labels = other_labels(peer, family, stage);", 2,
             "pinned metric bgp_max_prefix_headroom label family values"),
            # A later `let` shadows the helper-bound labels with a literal stage.
            ("let labels = max_prefix_label_values(peer, family, stage);",
             "let labels = max_prefix_label_values(peer, family, stage);\n"
             '        let labels = [labels[0], labels[1], "pre_policy"];', 2,
             "pinned metric bgp_max_prefix_headroom label family values"),
            # The helper shadows a parameter before returning it: the whole site is no evidence.
            ("    [peer, family, stage]", '    let stage = "pre_policy";\n    [peer, family, stage]', 1,
             "pinned metric bgp_max_prefix_blocked_total label family values"),
            ("    [peer, family, stage]", "    let family = stage;\n    [peer, family, stage]", 1,
             "pinned metric bgp_max_prefix_blocked_total label family values"),
            # The setter rebinds a helper argument: direct call, then `let`-bound array.
            ("pub fn record_max_prefix_blocked(&self, peer: &str, family: &str, stage: &str) {\n",
             "pub fn record_max_prefix_blocked(&self, peer: &str, family: &str, stage: &str) {\n"
             '        let stage = "pre_policy";\n', 1,
             "pinned metric bgp_max_prefix_blocked_total label stage values ['accepted', 'received']"),
            ("let labels = max_prefix_label_values(peer, family, stage);\n        let usage =",
             'let stage = "pre_policy";\n'
             "        let labels = max_prefix_label_values(peer, family, stage);\n        let usage =", 1,
             "pinned metric bgp_max_prefix_headroom label stage values ['accepted', 'received']"),
            # The loop variable is shadowed before the emission.
            ("for state in SESSION_STATES {\n            if state != current {",
             'for state in SESSION_STATES {\n            let state = "renamed";\n'
             "            if state != current {", 1,
             "pinned metric bgp_peer_session_state label state values ['active'"),
            # An earlier `return` in the helper bypasses the tail array.
            ("    [peer, family, stage]",
             '    if stage == "received" {\n        return [peer, family, "pre_policy"];\n    }\n'
             "    [peer, family, stage]", 1,
             "pinned metric bgp_max_prefix_blocked_total label family values"),
            # A renamed state in the constant the one-hot loop iterates.
            ('"open_sent",', '"opensent",', 1,
             "pinned metric bgp_peer_session_state label state values ['open_sent']"),
            # A loop the checker cannot resolve to a constant is no evidence.
            ("for state in SESSION_STATES {", "for state in SESSION_STATES.iter().copied() {", 2,
             "pinned metric bgp_peer_session_state label state values ['active'"),
        ]
        for old, new, count, expected in metric_cases:
            with self.subTest(old=old, new=new):
                source = self.replaced(self.metric_source, old, new, count)
                self.rejected(
                    lambda source=source: checker.check_metrics(
                        self.inventory, source, self.emission_sources
                    ),
                    expected,
                )
        # Renamed values in the label methods callers pass to the helper.
        session = "crates/transport/src/session/mod.rs"
        emission_cases = [
            (session, 'Self::Ipv4Received | Self::Ipv6Received => "received"',
             'Self::Ipv4Received | Self::Ipv6Received => "pre_policy"',
             "pinned metric bgp_max_prefix_blocked_total label stage values ['received']"),
            # Reached only through the `Self::Family(family) => family.label()` arm.
            ("crates/transport/src/config.rs", 'Self::Rtc => "rtc"', 'Self::Rtc => "rt_constrain"',
             "pinned metric bgp_max_prefix_blocked_total label family values ['rtc']"),
            # The match is discarded; the method returns another literal.
            (session, '            _ => "accepted",\n        }\n',
             '            _ => "accepted",\n        };\n        "pre_policy"\n',
             "pinned metric bgp_max_prefix_blocked_total label stage values ['accepted', 'received']"),
            # A second same-named label method in the crate makes `scope.stage()` ambiguous.
            (session, "impl MaxPrefixScope {",
             "fn stage(self) -> &'static str { \"other\" }\nimpl MaxPrefixScope {",
             "pinned metric bgp_max_prefix_blocked_total label stage values ['accepted', 'received']"),
        ]
        for path, old, new, expected in emission_cases:
            with self.subTest(path=path, new=new):
                sources = dict(self.emission_sources)
                sources[path] = self.replaced(sources[path], old, new)
                self.rejected(lambda sources=sources: self.check(self.inventory, sources), expected)

    def test_floor_series_drift_fails(self):
        inventory = copy.deepcopy(self.inventory)
        series = inventory["metrics"]["stable_series"]
        next(s for s in series if s["name"] == "bgp_max_prefix_usage")["labels"] = ["family", "peer"]
        self.rejected(lambda: self.check(inventory), "pinned metric bgp_max_prefix_usage changed labels")
        inventory = copy.deepcopy(self.inventory)
        del inventory["metrics"]["stable_series"]
        self.rejected(lambda: self.check(inventory), "metrics must be an object with exactly")

    def test_diagnostic_patterns_must_match_and_stay_disjoint(self):
        cases = [
            (["bgp_nonexistent_*"], "pattern 'bgp_nonexistent_*' matches no registered metric"),
            (["bgp_rib_*"], "pattern 'bgp_rib_*' matches pinned series ['bgp_rib_adj_out_prefixes'"),
            (["bgp_runtime_*", "bgp_rib_actor_*"], "metrics.diagnostic_series must be sorted"),
        ]
        for patterns, expected in cases:
            with self.subTest(patterns=patterns):
                inventory = copy.deepcopy(self.inventory)
                inventory["metrics"]["diagnostic_series"] = patterns
                self.rejected(lambda inventory=inventory: self.check(inventory), expected)


class PassThroughEmissionTests(unittest.TestCase):
    """A label value counts when a wrapper passes a constant through to the setter.

    Callers and constants resolve by module path: a same-named function or
    constant in another module is no evidence.
    """

    METRIC = (
        'let gauge = IntGaugeVec::new(Opts::new("bgp_x", "help"), &["peer", "family"]).unwrap();\n'
        "pub fn set_x(&self, peer: &str, family: &str, value: i64) {\n"
        "    self.0.gauge.with_label_values(&[peer, family]).set(value);\n"
        "}\n"
    )
    WRAPPER = (
        'pub const PAIR: [&str; 2] = ["fam_a", "fam_b"];\n'
        'pub const OTHER: [&str; 1] = ["fam_c"];\n'
        "pub fn publish(metrics: &M, peer: &str, families: [&str; 2], counts: [usize; 2]) {\n"
        "    for (family, count) in families.into_iter().zip(counts) {\n"
        "        metrics.set_x(peer, family, count);\n"
        "    }\n"
        "}\n"
    )
    # Same names, no metric: neither the function nor its constants emit bgp_x.
    UNRELATED = (
        'pub const PAIR: [&str; 2] = ["old_a", "old_b"];\n'
        "pub fn publish(metrics: &M, peer: &str, families: [&str; 2], counts: [usize; 2]) {}\n"
    )

    def emitted(self, caller, **extra):
        sources = {
            "crates/fixture/src/wrapper.rs": self.WRAPPER,
            "crates/fixture/src/unrelated.rs": self.UNRELATED,
            "crates/fixture/src/caller.rs": caller,
            **extra,
        }
        return checker.emitted_label_values(
            self.METRIC, sources, "bgp_x", "family", ["peer", "family"]
        )

    def test_constant_passed_through_a_loop_parameter_counts(self):
        for caller in (
            'fn caller(m: &M) { crate::wrapper::publish(m, "p", crate::wrapper::PAIR, [1, 2]); }',
            'use crate::wrapper::{publish, PAIR};\n'
            'fn caller(m: &M) { publish(m, "p", PAIR, [1, 2]); }',
            'use crate::wrapper;\n'
            'fn caller(m: &M) { wrapper::publish(m, "p", wrapper::PAIR, [1, 2]); }',
        ):
            with self.subTest(caller=caller):
                self.assertEqual(self.emitted(caller), {"fam_a", "fam_b"})

    def test_unpassed_constant_and_same_named_method_do_not_count(self):
        # OTHER is defined but never passed; `.publish(` is some other method.
        self.assertEqual(
            self.emitted(
                'fn caller(m: &M, x: &X) { x.publish(m, "p", crate::wrapper::OTHER, [1, 2]); }'
            ),
            set(),
        )

    def test_same_named_function_in_another_module_is_no_evidence(self):
        # Only crate::wrapper::publish reaches the metric.
        for caller in (
            'fn caller(m: &M) { crate::unrelated::publish(m, "p", crate::unrelated::PAIR, [1, 2]); }',
            'use crate::unrelated::{publish, PAIR};\n'
            'fn caller(m: &M) { publish(m, "p", PAIR, [1, 2]); }',
        ):
            with self.subTest(caller=caller):
                self.assertEqual(self.emitted(caller), set())

    def test_constant_resolves_to_the_referenced_module_only(self):
        # The live call passes crate::wrapper::PAIR; the unused same-named
        # crate::unrelated::PAIR keeps the old labels and must not count.
        caller = 'fn caller(m: &M) { crate::wrapper::publish(m, "p", crate::wrapper::PAIR, [1, 2]); }'
        self.assertEqual(self.emitted(caller), {"fam_a", "fam_b"})
        renamed = self.WRAPPER.replace('["fam_a", "fam_b"]', '["new_a", "new_b"]')
        emitted = self.emitted(caller, **{"crates/fixture/src/wrapper.rs": renamed})
        self.assertEqual(emitted, {"new_a", "new_b"})

    def test_ambiguous_or_unresolvable_constant_is_no_evidence(self):
        caller = 'fn caller(m: &M) { crate::wrapper::publish(m, "p", PAIR, [1, 2]); }'
        # Bare PAIR is neither declared in the caller nor imported.
        self.assertEqual(self.emitted(caller), set())
        twice = self.WRAPPER + 'pub const PAIR: [&str; 1] = ["fam_z"];\n'
        qualified = caller.replace(", PAIR,", ", crate::wrapper::PAIR,")
        self.assertEqual(
            self.emitted(qualified, **{"crates/fixture/src/wrapper.rs": twice}), set()
        )


class RoleFamilyTests(unittest.TestCase):
    """Role families must use the configuration labels the daemon accepts."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = checker.load_json(checker.INVENTORY_PATH)
        cls.canonical = checker.canonical_family_labels()

    def rejected(self, roles, expected):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            checker.check_role_families(roles, self.canonical)
        self.assertIn(expected, stderr.getvalue())

    def test_canonical_labels_come_from_the_wire_table(self):
        self.assertLessEqual(
            {"ipv4_unicast", "linkstate", "l3vpn_ipv4_unicast", "rtc"}, self.canonical
        )
        self.assertNotIn("vpnv4_unicast", self.canonical)

    def test_live_roles_pass(self):
        checker.check_role_families(self.inventory["roles"], self.canonical)

    def test_legacy_and_malformed_families_fail(self):
        cases = [
            (["vpnv4_unicast", "vpnv6_unicast"], "non-canonical families ['vpnv4_unicast'"),
            (["bgp_ls"], "non-canonical families ['bgp_ls']"),
            (["ipv4_unicast", "ipv4_unicast"], "repeats a family"),
            ([], "must list its families"),
            ([["ipv4_unicast"]], "must list its families"),
        ]
        for families, expected in cases:
            with self.subTest(families=families):
                roles = copy.deepcopy(self.inventory["roles"])
                next(r for r in roles if r["id"] == "route-reflector-l3vpn")["families"] = families
                self.rejected(roles, expected)


class NestedExperimentalJsonFieldTests(unittest.TestCase):
    """Nested JSON shapes may mark keys experimental, but never also pin them."""

    @classmethod
    def setUpClass(cls):
        cls.inventory = checker.load_json(checker.INVENTORY_PATH)

    def neighbor_detail(self):
        contract = next(
            contract
            for contract in copy.deepcopy(self.inventory["cli"]["test_pinned_json_contracts"])
            if contract["id"] == "neighbor-detail-v1"
        )
        nested = next(
            shape for shape in contract["nested_json_contracts"]
            if shape["path"] == "selection_deferral[]"
        )
        return contract, nested

    def rejected(self, contract, expected):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            checker.check_json_contract(contract, "neighbor-detail-v1", require_id_literal=False)
        self.assertIn(expected, stderr.getvalue())

    def test_live_contract_passes(self):
        contract, _ = self.neighbor_detail()
        checker.check_json_contract(contract, "neighbor-detail-v1", require_id_literal=False)

    def test_nested_field_cannot_be_both_pinned_and_experimental(self):
        contract, nested = self.neighbor_detail()
        nested["optional_json_types"]["waiter_session_id"] = "number"
        self.rejected(contract, "both contract-pinned and explicitly experimental")

    def test_nested_experimental_field_must_exist(self):
        contract, nested = self.neighbor_detail()
        nested["explicitly_experimental_json_fields"].append("zz_missing_field")
        self.rejected(contract, "'zz_missing_field' disappeared")



class CliExitCodeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = checker.load_json(checker.INVENTORY_PATH)

    def contract(self):
        inventory = copy.deepcopy(self.inventory)
        return inventory, inventory["cli"]["exit_code_contract"]

    def rejected(self, inventory, expected):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            checker.check_cli_exit_codes(inventory)
        self.assertIn(expected, stderr.getvalue())

    def test_live_contract_passes(self):
        checker.check_cli_exit_codes(self.inventory)

    def test_usage_code_must_match_the_cli(self):
        inventory, contract = self.contract()
        contract["usage_error"] = 2
        self.rejected(inventory, "is not the CLI's USAGE_EXIT_CODE")

    def test_detailed_code_cannot_reuse_the_usage_code(self):
        inventory, contract = self.contract()
        contract["command_exit_codes"]["doctor"] = [0, 1, 2, 64]
        self.rejected(inventory, "reuses the usage-error code 64")

    def test_pinned_codes_must_match_the_help(self):
        inventory, contract = self.contract()
        contract["command_exit_codes"]["config plan"] = [0, 1, 2]
        self.rejected(inventory, "EXIT_CODES_HELP documents [0, 1, 2, 3]")

    def test_pinned_command_must_be_stable_and_exercised(self):
        inventory, contract = self.contract()
        contract["command_exit_codes"] = dict(
            sorted({**contract["command_exit_codes"], "config import": [0, 1, 2, 3]}.items())
        )
        self.rejected(inventory, "reference unpinned CLI paths: ['config import']")
        inventory, contract = self.contract()
        inventory["cli"]["stable_command_paths"].append("config rollback")
        inventory["cli"]["stable_command_paths"].sort()
        contract["command_exit_codes"] = dict(
            sorted({**contract["command_exit_codes"], "config rollback": [0, 1, 3]}.items())
        )
        self.rejected(inventory, "does not exercise a usage error on 'config rollback'")

    def test_help_text_decoding(self):
        source = 'const X: &str = "Exit codes:\\n  \\\n    64 usage\\n  \\\n    doctor  0 a / 2 b";'
        self.assertEqual(
            checker.rust_str_const(source, "X"), "Exit codes:\n  64 usage\n  doctor  0 a / 2 b"
        )

if __name__ == "__main__":
    unittest.main()
