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
        cls.public_doc_refs = CHECK.public_document_references(
            cls.documents, cls.inventory
        )
        cls.doc_refs = CHECK.normative_document_references(cls.public_doc_refs)

    @staticmethod
    def before_tests(source, addition):
        marker = "\n#[cfg(test)]\nmod tests {"
        if marker not in source:
            return f"{source}\n{addition}"
        return source.replace(marker, f"\n{addition}{marker}", 1)

    def test_live_inventory_and_consumer_counts_are_exact(self):
        self.assertEqual(set(self.sources), set(CHECK.EMITTER_FILES))
        self.assertEqual(len(self.inventory), 208)
        self.assertEqual(
            len(CHECK.DASHBOARD_CHECK.rust_metric_inventory(self.sources[CHECK.TELEMETRY])),
            195,
        )
        self.assertEqual(
            len(CHECK.settlement_metric_inventory(self.sources[CHECK.SETTLEMENT])), 4
        )
        self.assertEqual(len(CHECK.PROCESS_FAMILIES), 7)
        self.assertEqual(len(self.dashboard_refs), 98)
        self.assertEqual(len(self.rule_refs), 44)
        self.assertEqual(len(self.public_doc_refs), 197)
        self.assertEqual(len(self.doc_refs), 197)
        consumers = self.dashboard_refs | self.rule_refs | self.doc_refs
        self.assertEqual(len(consumers), 202)
        self.assertEqual(set(self.inventory) - consumers, set(CHECK.ALLOWLIST))
        self.assertEqual(
            set(CHECK.ALLOWLIST), CHECK.PROCESS_FAMILIES - {"process_start_time_seconds"}
        )
        CHECK.validate_coverage(self.inventory, consumers)

    def test_live_main_reports_the_exact_roster(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(CHECK.main(), 0)
        self.assertIn("208 emitted families", stdout.getvalue())
        self.assertIn("197 normative-doc families", stdout.getvalue())
        self.assertIn("202 consumed, 6 justified raw diagnostics", stdout.getvalue())

    def test_blackhole_metric_inventory_has_one_operations_row_per_family(self):
        prefix = "bgp_blackhole_discard_"
        expected = {
            "bgp_blackhole_discard_installed_total",
            "bgp_blackhole_discard_withdrawn_total",
            "bgp_blackhole_discard_adopted_total",
            "bgp_blackhole_discard_reaped_total",
            "bgp_blackhole_discard_rejected_total",
            "bgp_blackhole_discard_kernel_failures_total",
            "bgp_blackhole_discard_active",
        }
        registered = {name for name in self.inventory if name.startswith(prefix)}
        self.assertEqual(registered, expected)

        operations = (CHECK.ROOT / "docs/OPERATIONS.md").read_text(encoding="utf-8")
        start = "### RFC 7999 BLACKHOLE discards"
        end = "### General Unicast FIB"
        self.assertEqual(operations.count(start), 1)
        self.assertEqual(operations.count(end), 1)
        section = operations.split(start, 1)[1].split(end, 1)[0]
        for metric in sorted(registered):
            with self.subTest(metric=metric):
                self.assertEqual(section.count(metric), 1)

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

    def test_session_notification_depth_collector_shape_is_fail_closed(self):
        telemetry = self.sources[CHECK.TELEMETRY]
        emitted, variables = CHECK.session_notification_depth_inventory(telemetry)
        self.assertEqual(
            emitted,
            {
                "bgp_session_notification_outstanding": "ordinary",
                "bgp_session_notification_outstanding_high_watermark": "ordinary",
            },
        )
        self.assertEqual(variables, {"current_gauge", "high_watermark_gauge"})

        duplicate_collect = telemetry.replace(
            "families.extend(high_watermark_gauge.collect());",
            "families.extend(current_gauge.collect());",
            1,
        )
        with self.assertRaisesRegex(ValueError, "assemble each local gauge exactly once"):
            CHECK.session_notification_depth_inventory(duplicate_collect)

        discarded = telemetry.replace(
            "let mut families = current_gauge.collect();",
            "let _ = current_gauge.collect();\n        let mut families = Vec::new();",
            1,
        )
        with self.assertRaisesRegex(ValueError, "assemble each local gauge exactly once"):
            CHECK.session_notification_depth_inventory(discarded)

        renamed = telemetry.replace(
            '"bgp_session_notification_outstanding_high_watermark",',
            '"bgp_session_notification_outstanding_peak",',
            1,
        )
        with self.assertRaisesRegex(ValueError, "exactly two uniquely named local gauges"):
            CHECK.session_notification_depth_inventory(renamed)

        third = telemetry.replace(
            "let mut families = current_gauge.collect();",
            '''let extra_gauge = IntGauge::new(
            "bgp_session_notification_extra", "help"
        ).expect("valid metric definition");
        let mut families = current_gauge.collect();''',
            1,
        )
        with self.assertRaisesRegex(ValueError, "exactly two uniquely named local gauges"):
            CHECK.session_notification_depth_inventory(third)

    def test_session_notification_depth_registration_is_pinned(self):
        sources = dict(self.sources)
        sources[CHECK.TELEMETRY] = sources[CHECK.TELEMETRY].replace(
            "SessionNotificationDepthCollector::new(",
            "RenamedSessionNotificationDepthCollector::new(",
            1,
        )
        with self.assertRaisesRegex(ValueError, "special collector registrations changed"):
            CHECK.workspace_metric_inventory(sources, self.lock_text)

    def test_event_outbox_queue_depth_collector_shape_is_fail_closed(self):
        telemetry = self.sources[CHECK.TELEMETRY]
        emitted, variables = CHECK.event_outbox_queue_depth_inventory(telemetry)
        self.assertEqual(emitted, {"bgp_event_outbox_queue_depth": "ordinary"})
        self.assertEqual(len(variables), 1)
        variable = next(iter(variables))

        replacement = f"{variable}_renamed"
        renamed_declaration = telemetry.replace(
            f"let {variable} = IntGaugeVec::new(",
            f"let {replacement} = IntGaugeVec::new(",
            1,
        )
        with self.assertRaisesRegex(ValueError, "populate its local gauge vector"):
            CHECK.event_outbox_queue_depth_inventory(renamed_declaration)

        renamed_variable = renamed_declaration.replace(
            f"{variable}\n                .with_label_values",
            f"{replacement}\n                .with_label_values",
            1,
        ).replace(
            f"{variable}.collect()",
            f"{replacement}.collect()",
            1,
        )
        renamed_emitted, renamed_variables = CHECK.event_outbox_queue_depth_inventory(
            renamed_variable
        )
        self.assertEqual(renamed_emitted, emitted)
        self.assertEqual(renamed_variables, {replacement})
        sources = dict(self.sources)
        sources[CHECK.TELEMETRY] = renamed_variable
        self.assertEqual(CHECK.workspace_metric_inventory(sources, self.lock_text), self.inventory)

        renamed = telemetry.replace(
            '"bgp_event_outbox_queue_depth",',
            '"bgp_event_outbox_pending_depth",',
            1,
        )
        with self.assertRaisesRegex(ValueError, "exactly one uniquely named local gauge"):
            CHECK.event_outbox_queue_depth_inventory(renamed)

        relabeled = telemetry.replace(
            '''&["category"],
        )
        .expect("valid metric definition");
        for (index, category) in EVENT_OUTBOX_QUEUE_DEPTH_CATEGORIES''',
            '''&["reason"],
        )
        .expect("valid metric definition");
        for (index, category) in EVENT_OUTBOX_QUEUE_DEPTH_CATEGORIES''',
            1,
        )
        with self.assertRaisesRegex(ValueError, "with the category label"):
            CHECK.event_outbox_queue_depth_inventory(relabeled)

        discarded = telemetry.replace(
            f"{variable}.collect()",
            "Vec::new()",
            1,
        )
        with self.assertRaisesRegex(ValueError, "return its local gauge vector exactly once"):
            CHECK.event_outbox_queue_depth_inventory(discarded)

        unmapped_return = telemetry.replace(
            "return Vec::new();",
            "return self.hidden.collect();",
            1,
        )
        with self.assertRaisesRegex(ValueError, "returns families outside"):
            CHECK.event_outbox_queue_depth_inventory(unmapped_return)

    def test_event_outbox_queue_depth_roster_and_registration_are_pinned(self):
        sources = dict(self.sources)
        sources[CHECK.TELEMETRY] = sources[CHECK.TELEMETRY].replace(
            "impl Collector for EventOutboxQueueDepthCollector",
            "impl Collector for RenamedEventOutboxQueueDepthCollector",
            1,
        )
        with self.assertRaisesRegex(ValueError, "custom metric collector roster changed"):
            CHECK.workspace_metric_inventory(sources, self.lock_text)

        sources = dict(self.sources)
        sources[CHECK.TELEMETRY] = sources[CHECK.TELEMETRY].replace(
            "EventOutboxQueueDepthCollector::new(",
            "RenamedEventOutboxQueueDepthCollector::new(",
            1,
        )
        with self.assertRaisesRegex(ValueError, "special collector registrations changed"):
            CHECK.workspace_metric_inventory(sources, self.lock_text)

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

    def test_historical_documents_still_enforce_metric_name_checks(self):
        with self.assertRaisesRegex(ValueError, "near-miss.*bgp_raedy.*bgp_ready"):
            CHECK.public_document_references(
                {"docs/soaks/receipt.md": "Observed `bgp_raedy`."},
                {"bgp_ready": "ordinary"},
            )

    def test_document_evidence_classification_is_pinned(self):
        self.assertNotIn("CHANGELOG.md", self.documents)
        self.assertNotIn("ROADMAP.md", self.documents)
        self.assertEqual(
            CHECK.HISTORICAL_DOCUMENTS,
            frozenset(
                {
                    "docs/OPERATIONAL_PROOF.md",
                    "docs/RECEIPTS.md",
                    "docs/evpn-alpha-soak.md",
                    "docs/milestones.md",
                    "docs/upstream-findings.md",
                }
            ),
        )
        self.assertEqual(
            CHECK.HISTORICAL_DOCUMENT_PREFIXES,
            ("docs/adr/", "docs/artifacts/", "docs/perf/", "docs/soaks/"),
        )
        cases = {
            "docs/OPERATIONS.md": "normative",
            "docs/CONFIGURATION.md": "normative",
            "docs/milestones.md": "historical",
            "docs/adr/9999-example.md": "historical",
            "docs/artifacts/soak/receipt.md": "historical",
            "docs/perf/artifacts/receipt.md": "historical",
            "docs/soaks/receipt.md": "historical",
        }
        for relative, expected in cases.items():
            with self.subTest(relative=relative):
                self.assertEqual(CHECK.document_evidence_class(relative), expected)

    def test_only_normative_document_references_certify_consumers(self):
        inventory = {
            "bgp_runbook_metric": "ordinary",
            "bgp_historical_metric": "ordinary",
        }
        references = CHECK.public_document_references(
            {
                "docs/OPERATIONS.md": "Watch `bgp_runbook_metric`.",
                "docs/milestones.md": "Shipped `bgp_historical_metric`.",
                "docs/adr/9999-example.md": "Chose `bgp_historical_metric`.",
                "docs/soaks/example.md": "Observed `bgp_historical_metric`.",
            },
            inventory,
        )
        normative = CHECK.normative_document_references(references)

        self.assertEqual(normative, {"bgp_runbook_metric"})
        CHECK.validate_coverage({"bgp_runbook_metric": "ordinary"}, normative, {})
        with self.assertRaisesRegex(ValueError, "bgp_historical_metric"):
            CHECK.validate_coverage(inventory, normative, {})

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

        documents = dict(self.documents)
        for relative, text in documents.items():
            if CHECK.document_evidence_class(relative) == "normative":
                documents[relative] = text.replace(
                    "bgp_event_outbox_cursor_gap_total",
                    "bgp_event_outbox_cursor_gap_removed_total",
                )
        public_doc_refs = CHECK.public_document_references(documents, self.inventory)
        self.assertIn("bgp_event_outbox_cursor_gap_total", public_doc_refs)
        doc_refs = CHECK.normative_document_references(public_doc_refs)
        with self.assertRaisesRegex(ValueError, "bgp_event_outbox_cursor_gap_total"):
            CHECK.validate_coverage(
                self.inventory, self.dashboard_refs | self.rule_refs | doc_refs
            )

    def test_evpn_nhg_recovery_metrics_require_normative_runbook_evidence(self):
        recovery_metrics = (
            "evpn_fdb_nhg_drift_members_repaired_total",
            "evpn_fdb_nhg_drift_groups_replaced_total",
            "evpn_fdb_nhg_orphans_cleaned_total",
            "evpn_fdb_nhg_drift_disabled_total",
        )
        for metric in recovery_metrics:
            with self.subTest(metric=metric):
                documents = {}
                for relative, text in self.documents.items():
                    if CHECK.document_evidence_class(relative) == "normative":
                        text = "\n".join(
                            line for line in text.splitlines() if metric not in line
                        )
                    documents[relative] = text

                public_doc_refs = CHECK.public_document_references(
                    documents, self.inventory
                )
                self.assertIn(metric, public_doc_refs)
                doc_refs = CHECK.normative_document_references(public_doc_refs)
                self.assertNotIn(metric, doc_refs)
                with self.assertRaisesRegex(ValueError, metric):
                    CHECK.validate_coverage(
                        self.inventory,
                        self.dashboard_refs | self.rule_refs | doc_refs,
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
