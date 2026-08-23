#!/usr/bin/env python3
import copy
import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path


PATH = Path(__file__).with_name("check-metric-consumers.py")
SPEC = importlib.util.spec_from_file_location("metric_consumer_check", PATH)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class MetricConsumerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = CHECK.candidate_emitter_sources()
        cls.lock_text = CHECK.CARGO_LOCK.read_text(encoding="utf-8")
        cls.inventory = CHECK.workspace_metric_inventory(cls.sources, cls.lock_text)
        cls.dashboard = json.loads(CHECK.DASHBOARD.read_text(encoding="utf-8"))
        dashboard_raw = CHECK.DASHBOARD_CHECK.dashboard_metric_references(cls.dashboard)
        cls.dashboard_refs = {
            normalized
            for name in dashboard_raw
            if (normalized := CHECK.normalize_metric(name, cls.inventory)) is not None
        }
        cls.rule_refs = set(
            CHECK.rule_metric_references(
                CHECK.ALERT_RULES.read_text(encoding="utf-8"), cls.inventory
            )
        )
        cls.documents = CHECK.PUBLIC_DOCS_CHECK.discover_documents()
        cls.doc_refs = set(
            CHECK.public_document_references(cls.documents, cls.inventory)
        )

    @staticmethod
    def before_tests(source, addition):
        marker = "\n#[cfg(test)]\nmod tests {"
        if marker not in source:
            return f"{source}\n{addition}"
        return source.replace(marker, f"\n{addition}{marker}", 1)

    def test_live_inventory_and_consumer_counts_are_exact(self):
        self.assertEqual(set(self.sources), set(CHECK.EMITTER_FILES))
        self.assertEqual(len(self.inventory), 189)
        self.assertEqual(
            len(CHECK.DASHBOARD_CHECK.rust_metric_inventory(self.sources[CHECK.TELEMETRY])),
            178,
        )
        self.assertEqual(
            len(CHECK.settlement_metric_inventory(self.sources[CHECK.SETTLEMENT])), 4
        )
        self.assertEqual(len(CHECK.PROCESS_FAMILIES), 7)
        self.assertEqual(len(self.dashboard_refs), 93)
        self.assertEqual(len(self.rule_refs), 39)
        self.assertEqual(len(self.doc_refs), 176)
        consumers = self.dashboard_refs | self.rule_refs | self.doc_refs
        self.assertEqual(len(consumers), 183)
        self.assertEqual(set(self.inventory) - consumers, set(CHECK.ALLOWLIST))
        self.assertEqual(
            set(CHECK.ALLOWLIST), CHECK.PROCESS_FAMILIES - {"process_start_time_seconds"}
        )
        CHECK.validate_coverage(self.inventory, consumers)

    def test_live_main_reports_the_exact_roster(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(CHECK.main(), 0)
        self.assertIn("189 emitted families", stdout.getvalue())
        self.assertIn("183 consumed, 6 justified raw diagnostics", stdout.getvalue())

    def test_comments_literals_and_test_modules_are_not_definitions(self):
        source = r'''
let ready = IntGauge::new("bgp_ready", "help").unwrap();
// let commented = IntGauge::new("bgp_commented", "help").unwrap();
let note = r#"let quoted = IntGauge::new("bgp_quoted", "help");"#;
#[cfg(test)]
mod tests {
    let test_only = IntGauge::new("bgp_test_only", "help").unwrap();
}
'''
        definitions = CHECK.static_metric_definitions(source)
        self.assertEqual(definitions, {"ready": ("bgp_ready", "ordinary")})

    def test_dynamic_metric_name_is_rejected(self):
        sources = dict(self.sources)
        sources[CHECK.TELEMETRY] = self.before_tests(
            sources[CHECK.TELEMETRY],
            '''fn dynamic_metric_name() {
    let dynamic = IntGauge::new(format!("bgp_dynamic_{}", "name"), "help").unwrap();
    drop(dynamic);
}
''',
        )
        with self.assertRaisesRegex(ValueError, "inventory is not fully static"):
            CHECK.workspace_metric_inventory(sources, self.lock_text)

    def test_unclassified_emitter_file_is_rejected(self):
        sources = dict(self.sources)
        sources["src/new_metric_emitter.rs"] = '''
let surprise = IntGauge::new("bgp_surprise", "help").unwrap();
registry.register(Box::new(surprise.clone())).unwrap();
'''
        with self.assertRaisesRegex(ValueError, "emitter source roster changed"):
            CHECK.workspace_metric_inventory(sources, self.lock_text)

    def test_unregistered_static_definition_is_rejected(self):
        sources = dict(self.sources)
        sources[CHECK.TELEMETRY] = self.before_tests(
            sources[CHECK.TELEMETRY],
            '''fn orphan_metric_definition() {
    let orphan = IntGauge::new("bgp_orphan", "help").unwrap();
    drop(orphan);
}
''',
        )
        with self.assertRaisesRegex(ValueError, "unregistered=.*bgp_orphan"):
            CHECK.workspace_metric_inventory(sources, self.lock_text)

    def test_alias_backed_direct_registration_is_rejected(self):
        sources = dict(self.sources)
        sources[CHECK.TELEMETRY] = self.before_tests(
            sources[CHECK.TELEMETRY],
            '''type HiddenCounter = IntCounter;
fn alias_metric(registry: &Registry) {
    let hidden = HiddenCounter::new("bgp_hidden", "help").unwrap();
    registry.register(Box::new(hidden.clone())).unwrap();
}
''',
        )
        with self.assertRaisesRegex(
            ValueError, "registered variable hidden has no parsed literal"
        ):
            CHECK.workspace_metric_inventory(sources, self.lock_text)

    def test_custom_collector_roster_and_wiring_are_pinned(self):
        sources = dict(self.sources)
        sources[CHECK.SETTLEMENT] = sources[CHECK.SETTLEMENT].replace(
            "impl Collector for RuntimeConfigSettlementCollector",
            "impl Collector for RenamedSettlementCollector",
            1,
        )
        with self.assertRaisesRegex(ValueError, "custom metric collector roster changed"):
            CHECK.workspace_metric_inventory(sources, self.lock_text)

        unwired = self.sources[CHECK.SETTLEMENT].replace(
            "families.extend(self.fail_stops.collect());",
            "self.fail_stops.reset();",
            1,
        )
        with self.assertRaisesRegex(ValueError, "not collected.*fail_stops"):
            CHECK.settlement_metric_inventory(unwired)

    def test_custom_collector_unparsed_fields_are_rejected(self):
        alias_backed = self.sources[CHECK.SETTLEMENT].replace(
            "let fail_stops = CounterVec::new(",
            "let fail_stops = HiddenCounterVec::new(",
            1,
        )
        with self.assertRaisesRegex(ValueError, "fail_stops.*literal metric definition"):
            CHECK.settlement_metric_inventory(alias_backed)

        unknown_collected = self.sources[CHECK.SETTLEMENT].replace(
            "families.extend(self.fail_stops.collect());",
            "families.extend(self.fail_stops.collect());\n"
            "        families.extend(self.hidden.collect());",
            1,
        )
        with self.assertRaisesRegex(ValueError, "hidden.*no unique constructor mapping"):
            CHECK.settlement_metric_inventory(unknown_collected)

    def test_custom_collector_direct_metric_family_emission_is_rejected(self):
        direct_proto = self.sources[CHECK.SETTLEMENT].replace(
            "families.extend(self.fail_stops.collect());\n        families",
            '''families.extend(self.fail_stops.collect());
        let mut hidden = MetricFamily::new();
        hidden.set_name("bgp_runtime_config_settlement_hidden_total".into());
        families.push(hidden);
        families''',
            1,
        )
        with self.assertRaisesRegex(ValueError, "constructs MetricFamily values directly"):
            CHECK.settlement_metric_inventory(direct_proto)

    def test_process_dependency_drift_is_rejected(self):
        drifted = self.lock_text.replace(
            'name = "prometheus"\nversion = "0.14.0"',
            'name = "prometheus"\nversion = "0.15.0"',
            1,
        )
        with self.assertRaisesRegex(ValueError, "dependency version changed"):
            CHECK.workspace_metric_inventory(self.sources, drifted)

    def test_rule_parser_handles_scalar_folded_and_ignores_non_expressions(self):
        inventory = {
            "bgp_ready": "ordinary",
            "bgp_latency_seconds": "histogram",
            "bgp_annotation_only": "ordinary",
            "bgp_comment_only": "ordinary",
            "bgp_label_only": "ordinary",
        }
        rules = '''
groups:
  - name: test
    rules:
      - alert: Ready
        expr: bgp_ready == 1
        annotations:
          summary: bgp_annotation_only
      - alert: Latency
        expr: >-
          rate(bgp_latency_seconds_count{state="bgp_label_only"}[5m]) > 0
          # bgp_comment_only
'''
        references = CHECK.rule_metric_references(rules, inventory)
        self.assertEqual(set(references), {"bgp_ready", "bgp_latency_seconds"})

    def test_unregistered_rule_metric_is_rejected(self):
        rules = (
            "groups:\n  - rules:\n      - alert: Typo\n"
            "        expr: bgp_typo == 1\n"
        )
        with self.assertRaisesRegex(ValueError, "unregistered.*bgp_typo"):
            CHECK.rule_metric_references(rules, {"bgp_ready": "ordinary"})

    def test_quoted_rule_metric_typo_is_decoded_and_rejected(self):
        rules = '''
groups:
  - rules:
      - alert: Ready
        expr: bgp_ready == 1
      - alert: Typo
        expr: "bgp_typo == 1"
'''
        with self.assertRaisesRegex(ValueError, "unregistered.*bgp_typo"):
            CHECK.rule_metric_references(rules, {"bgp_ready": "ordinary"})

    def test_plain_rule_continuation_is_parsed(self):
        rules = '''
groups:
  - rules:
      - alert: Continued
        expr: bgp_ready
          or bgp_typo
'''
        with self.assertRaisesRegex(ValueError, "unregistered.*bgp_typo"):
            CHECK.rule_metric_references(rules, {"bgp_ready": "ordinary"})

    def test_yaml_rule_references_and_unsupported_block_headers_are_rejected(self):
        cases = (
            "        expr: &shared bgp_ready\n",
            "        expr: *shared\n",
            "        expr: >2-\n          bgp_ready\n",
            "        expr: |+2\n          bgp_ready\n",
        )
        for expression in cases:
            rules = "groups:\n  - rules:\n      - alert: Invalid\n" + expression
            with self.subTest(expression=expression), self.assertRaisesRegex(
                ValueError, "unsupported YAML expr"
            ):
                CHECK.rule_metric_references(rules, {"bgp_ready": "ordinary"})

    def test_yaml_rule_tags_are_rejected_before_quoted_payload_masking(self):
        cases = (
            '        expr: !!str "bgp_typo == 1"\n',
            '        expr: !<tag:yaml.org,2002:str> "bgp_typo == 1"\n',
        )
        valid = "groups:\n  - rules:\n      - alert: Ready\n        expr: bgp_ready\n"
        for expression in cases:
            rules = valid + "      - alert: Tagged\n" + expression
            with self.subTest(expression=expression), self.assertRaisesRegex(
                ValueError, "unsupported YAML expr tag"
            ):
                CHECK.rule_metric_references(rules, {"bgp_ready": "ordinary"})

    def test_yaml_rule_actual_empty_scalars_are_rejected(self):
        cases = (
            "        expr: # comment\n",
            '        expr: ""\n',
            "        expr: ''\n",
            "        expr: >-\n          # comment only\n",
        )
        valid = "groups:\n  - rules:\n      - alert: Ready\n        expr: bgp_ready\n"
        for expression in cases:
            rules = valid + "      - alert: Empty\n" + expression
            with self.subTest(expression=expression), self.assertRaisesRegex(
                ValueError, "empty YAML expr scalar"
            ):
                CHECK.rule_metric_references(rules, {"bgp_ready": "ordinary"})

    def test_inline_rule_comments_outside_quotes_are_ignored(self):
        inventory = {
            "bgp_ready": "ordinary",
            "bgp_comment_only": "ordinary",
            "bgp_label_value": "ordinary",
        }
        rules = '''
groups:
  - rules:
      - alert: Ready
        expr: bgp_ready{note="# bgp_label_value"} # bgp_comment_only
'''
        references = CHECK.rule_metric_references(rules, inventory)
        self.assertEqual(set(references), {"bgp_ready"})

    def test_document_tokens_are_exact_and_histogram_kind_aware(self):
        inventory = {
            "bgp_ready": "ordinary",
            "bgp_latency_seconds": "histogram",
            "bgp_non_markdown": "ordinary",
        }
        documents = {
            "docs/metrics.md": (
                "`bgp_ready`, `bgp_latency_seconds_bucket`, and bgp_ready_suffix"
            ),
            "docs/data.json": "bgp_non_markdown",
        }
        references = CHECK.public_document_references(documents, inventory)
        self.assertEqual(set(references), {"bgp_ready", "bgp_latency_seconds"})
        self.assertIsNone(CHECK.normalize_metric("bgp_ready_count", inventory))

    def test_metric_near_miss_in_document_code_or_table_is_rejected(self):
        inventory = {"bgp_ready": "ordinary"}
        CHECK.public_document_references(
            {"docs/metrics.md": "Plain prose may say bgp_raedy; use `bgp_ready`."},
            inventory,
        )
        for text in (
            "Use `bgp_raedy`.",
            "| Metric |\n| --- |\n| bgp_raedy |",
            "```promql\nbgp_raedy == 1\n```",
        ):
            with self.subTest(text=text), self.assertRaisesRegex(
                ValueError, "near-miss.*bgp_raedy.*bgp_ready"
            ):
                CHECK.public_document_references({"docs/metrics.md": text}, inventory)

    def test_dashboard_only_and_docs_only_consumer_removals_fail(self):
        dashboard = copy.deepcopy(self.dashboard)
        for panel in CHECK.DASHBOARD_CHECK.all_panels(dashboard["panels"]):
            for target in panel.get("targets", []):
                expression = target.get("expr", "")
                target["expr"] = expression.replace(
                    "bgp_orr_spf_runs_total", "bgp_orr_topology_nodes"
                )
        dashboard_raw = CHECK.DASHBOARD_CHECK.dashboard_metric_references(dashboard)
        dashboard_refs = {
            normalized
            for name in dashboard_raw
            if (normalized := CHECK.normalize_metric(name, self.inventory)) is not None
        }
        with self.assertRaisesRegex(ValueError, "bgp_orr_spf_runs_total"):
            CHECK.validate_coverage(
                self.inventory, dashboard_refs | self.rule_refs | self.doc_refs
            )

        documents = {
            relative: text.replace(
                "bgp_event_outbox_cursor_gap_total",
                "bgp_event_outbox_cursor_gap_removed_total",
            )
            for relative, text in self.documents.items()
        }
        doc_refs = set(CHECK.public_document_references(documents, self.inventory))
        with self.assertRaisesRegex(ValueError, "bgp_event_outbox_cursor_gap_total"):
            CHECK.validate_coverage(
                self.inventory, self.dashboard_refs | self.rule_refs | doc_refs
            )

    def test_allowlist_missing_unknown_empty_and_stale_entries_fail(self):
        inventory = {"bgp_ready": "ordinary", "process_raw": "ordinary"}
        CHECK.validate_coverage(
            inventory, {"bgp_ready"}, {"process_raw": "raw diagnostic"}
        )
        cases = (
            ({}, "lack shipped consumers"),
            ({"unknown": "raw"}, "not emitted"),
            ({"process_raw": ""}, "without reasons"),
            ({"bgp_ready": "raw", "process_raw": "raw"}, "now have shipped consumers"),
        )
        for allowlist, message in cases:
            with self.subTest(allowlist=allowlist), self.assertRaisesRegex(
                ValueError, message
            ):
                CHECK.validate_coverage(inventory, {"bgp_ready"}, allowlist)


if __name__ == "__main__":
    unittest.main()
