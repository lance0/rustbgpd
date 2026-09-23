#!/usr/bin/env python3
import copy
import importlib.util
import io
import json
import re
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
        cls.rust = CHECK.production_rust_sources()
        cls.vocabularies = CHECK.closed_label_vocabularies(cls.rust, cls.inventory)
        cls.label_consumers = CHECK.label_value_consumers()
        cls.lenient = frozenset({"examples/prometheus/rustbgpd-alerts_test.yml"})

    @staticmethod
    def before_tests(source, addition):
        marker = "\n#[cfg(test)]\nmod tests {"
        if marker not in source:
            return f"{source}\n{addition}"
        return source.replace(marker, f"\n{addition}{marker}", 1)

    def test_live_inventory_and_consumer_counts_are_exact(self):
        self.assertEqual(set(self.sources), set(CHECK.EMITTER_FILES))
        self.assertEqual(len(self.inventory), 219)
        self.assertEqual(
            len(CHECK.DASHBOARD_CHECK.rust_metric_inventory(self.sources[CHECK.TELEMETRY])),
            205,
        )
        self.assertEqual(
            len(CHECK.settlement_metric_inventory(self.sources[CHECK.SETTLEMENT])), 4
        )
        self.assertEqual(len(CHECK.PROCESS_FAMILIES), 7)
        self.assertEqual(len(self.dashboard_refs), 98)
        self.assertEqual(len(self.rule_refs), 46)
        self.assertEqual(len(self.public_doc_refs), 208)
        self.assertEqual(len(self.doc_refs), 208)
        consumers = self.dashboard_refs | self.rule_refs | self.doc_refs
        self.assertEqual(len(consumers), 213)
        self.assertEqual(set(self.inventory) - consumers, set(CHECK.ALLOWLIST))
        self.assertEqual(
            set(CHECK.ALLOWLIST), CHECK.PROCESS_FAMILIES - {"process_start_time_seconds"}
        )
        CHECK.validate_coverage(self.inventory, consumers)

    def test_live_main_reports_the_exact_roster(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(CHECK.main(), 0)
        self.assertIn("219 emitted families", stdout.getvalue())
        self.assertIn("208 normative-doc families", stdout.getvalue())
        self.assertIn("213 consumed, 6 justified raw diagnostics", stdout.getvalue())

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

        operations = (CHECK.ROOT / "docs/reference/operations.md").read_text(encoding="utf-8")
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

    def test_tls_expiry_collector_shape_and_registration_are_fail_closed(self):
        source = self.sources[CHECK.CREDENTIALS]
        emitted = CHECK.tls_expiry_metric_inventory(source)
        self.assertEqual(emitted, {"bgp_grpc_tls_certificate_not_after_seconds": "ordinary"})
        mutations = [
            (source.replace('"bgp_grpc_tls_certificate_not_after_seconds"', '"bgp_other_seconds"'),
             "uniquely named local gauge"),
            (source.replace('&["kind"],', '&["identity"],'), "with the kind label"),
            (source.replace("gauges.collect()", "Vec::new()", 1), "return its local gauge vector"),
            (source.replace("return Vec::new();", "return self.hidden.collect();", 1),
             "returns families outside"),
            (source.replace("TlsExpiryCollector::new(", "UnknownCollector::new(", 1),
             "special collector registrations changed"),
        ]
        for mutated, diagnostic in mutations:
            with self.subTest(diagnostic=diagnostic):
                self.assertNotEqual(mutated, source)
                with self.assertRaisesRegex(ValueError, diagnostic):
                    CHECK.tls_expiry_metric_inventory(mutated)

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
        self.assertNotIn("docs/project/roadmap.md", self.documents)
        self.assertNotIn("docs/project/roadmap-history.md", self.documents)
        self.assertNotIn("docs/project/changelog/older-releases.md", self.documents)
        self.assertEqual(
            CHECK.HISTORICAL_DOCUMENTS,
            frozenset(
                {
                    "docs/operational-proof.md",
                    "docs/receipts.md",
                    "docs/how-to/evpn-alpha-soak.md",
                    "docs/project/evpn-enablement.md",
                    "docs/project/milestones.md",
                    "docs/project/upstream-findings.md",
                }
            ),
        )
        self.assertEqual(
            CHECK.HISTORICAL_DOCUMENT_PREFIXES,
            ("docs/adr/", "docs/artifacts/", "docs/perf/", "docs/soaks/"),
        )
        cases = {
            "docs/reference/operations.md": "normative",
            "docs/reference/configuration.md": "normative",
            "docs/project/milestones.md": "historical",
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
                "docs/reference/operations.md": "Watch `bgp_runbook_metric`.",
                "docs/project/milestones.md": "Shipped `bgp_historical_metric`.",
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


    def check_selector(self, expression, name="rules.yml", lenient=frozenset()):
        """Check one expression against only the vocabularies it selects on."""
        families = {
            CHECK.normalize_metric(token, self.inventory)
            for token in re.findall(r"([A-Za-z_:][A-Za-z0-9_:]*)\s*\{", expression)
        }
        labels = set(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|!)", expression))
        vocabularies = {
            key: values
            for key, values in self.vocabularies.items()
            if key[0] in families and key[1] in labels
        }
        return CHECK.check_label_values(
            {name: [("line 1", expression)]}, vocabularies, self.inventory, lenient
        )

    def test_live_label_selectors_name_values_the_daemon_emits(self):
        self.assertEqual(
            self.vocabularies[("bgp_sighup_reload_outcomes_total", "outcome")],
            {
                "complete",
                "known_partial",
                "rejected_no_effect",
                "ignored_in_flight",
                "task_failed",
            },
        )
        checked, skipped = CHECK.check_label_values(
            self.label_consumers, self.vocabularies, self.inventory, self.lenient
        )
        self.assertGreater(checked, 0)
        self.assertEqual(skipped, [])

    def test_daemon_renaming_a_selected_label_value_is_rejected(self):
        rust = dict(self.rust)
        self.assertEqual(rust[CHECK.TELEMETRY].count('"known_partial"'), 1)
        rust[CHECK.TELEMETRY] = rust[CHECK.TELEMETRY].replace(
            '"known_partial"', '"partial"'
        )
        vocabularies = CHECK.closed_label_vocabularies(rust, self.inventory)
        with self.assertRaises(ValueError) as raised:
            CHECK.check_label_values(
                self.label_consumers, vocabularies, self.inventory, self.lenient
            )
        message = str(raised.exception)
        self.assertRegex(
            message,
            r"examples/prometheus/rustbgpd-alerts\.yml \(line \d+\): "
            r'bgp_sighup_reload_outcomes_total\{outcome="known_partial"\} '
            r'names value "known_partial" the daemon cannot emit',
        )
        # The synthetic promtool series is what kept the rule tests green.
        self.assertIn("examples/prometheus/rustbgpd-alerts_test.yml (line ", message)
        self.assertNotIn("task_failed", message)

    def test_present_value_and_open_labels_pass(self):
        checked, skipped = self.check_selector(
            'increase(bgp_sighup_reload_outcomes_total{instance=~"$instance",'
            'job="anything",peer!="192.0.2.1",outcome="task_failed"}[10m]) > 0'
        )
        self.assertEqual((checked, skipped), (1, []))
        # Foreign families and the absent-label matcher carry no daemon value.
        self.assertEqual(
            self.check_selector('up{job="rustbgpd"} == 0'), (0, [])
        )

    def test_unknown_exact_and_negative_values_are_rejected(self):
        for matcher in ('outcome="partial"', 'outcome!="partial"'):
            with self.subTest(matcher=matcher), self.assertRaisesRegex(
                ValueError,
                r'rules\.yml \(line 1\): bgp_sighup_reload_outcomes_total\{outcome!?="partial"\} '
                r'names value "partial" the daemon cannot emit',
            ):
                self.check_selector(f"bgp_sighup_reload_outcomes_total{{{matcher}}}")

    def test_regex_alternation_checks_each_literal(self):
        family = "bgp_blackhole_discard_rejected_total"
        self.assertEqual(
            self.check_selector(
                f'{family}{{reason=~"active_limit_exceeded|install_rate_limited"}}'
            ),
            (2, []),
        )
        for operator in ("=~", "!~"):
            with self.subTest(operator=operator), self.assertRaisesRegex(
                ValueError, 'names value "rate_limited" the daemon cannot emit'
            ) as raised:
                self.check_selector(
                    f'{family}{{reason{operator}"active_limit_exceeded|rate_limited"}}'
                )
            self.assertNotIn('"active_limit_exceeded" the daemon', str(raised.exception))

    def test_complex_regex_and_template_variables_are_skipped_not_failed(self):
        for pattern in ("known_.*", "$outcome", "(known|task)_failed"):
            with self.subTest(pattern=pattern):
                checked, skipped = self.check_selector(
                    f'bgp_sighup_reload_outcomes_total{{outcome=~"{pattern}"}}'
                )
                self.assertEqual(checked, 0)
                self.assertEqual(len(skipped), 1)
                self.assertIn(pattern, skipped[0])

    def test_braces_inside_a_quoted_value_do_not_hide_a_selector(self):
        family = "bgp_sighup_reload_outcomes_total"
        # (a) a quantifier is a complex regex: skipped and counted, never dropped.
        checked, skipped = self.check_selector(f'{family}{{outcome=~"known_[0-9]{{1,2}}"}}')
        self.assertEqual(checked, 0)
        self.assertEqual(len(skipped), 1)
        self.assertIn('outcome=~"known_[0-9]{1,2}"', skipped[0])
        # (b), (c) an exact value is checked whole, whichever brace it contains.
        for value in ("bogus}x", "x{y", "a{b}c"):
            with self.subTest(value=value), self.assertRaises(ValueError) as raised:
                self.check_selector(f'{family}{{outcome="{value}"}}')
            self.assertIn(
                f'{family}{{outcome="{value}"}} names value "{value}" the daemon cannot emit',
                str(raised.exception),
            )
        # (d) an open label keeps being ignored, and the closed label beside it
        # is still checked.
        self.assertEqual(
            self.check_selector(
                f'{family}{{peer=~"${{peer:regex}}",job="a}}b{{c",outcome="task_failed"}}'
            ),
            (1, []),
        )
        with self.assertRaisesRegex(ValueError, 'names value "partial" the daemon'):
            self.check_selector(f'{family}{{peer=~"${{peer:regex}}",outcome="partial"}}')

    def test_selector_wrapped_across_lines_is_checked_at_its_own_line(self):
        key = ("bgp_policy_eval_errors_total", "kind")
        text = (
            "description: >-\n"
            '  bgp_policy_eval_errors_total{direction="import",\n'
            '  kind="%s"} on edge1 increased'
        )
        arguments = ({key: self.vocabularies[key]}, self.inventory, frozenset({"t.yml"}))
        self.assertEqual(
            CHECK.check_label_values({"t.yml": [(10, text % "overflow")]}, *arguments),
            (1, []),
        )
        with self.assertRaisesRegex(
            ValueError,
            r't\.yml \(line 11\): bgp_policy_eval_errors_total\{kind="bogus"\} names value',
        ):
            CHECK.check_label_values({"t.yml": [(10, text % "bogus")]}, *arguments)
        # The shipped rule tests wrap exactly this selector in an expected annotation.
        wrapped = [
            text for _, text in self.label_consumers[sorted(self.lenient)[0]]
            if 'bgp_policy_eval_errors_total{direction="import",\n' in text
        ]
        self.assertEqual(len(wrapped), 1)

    def test_empty_exact_value_on_a_closed_label_is_checked(self):
        family = "bgp_sighup_reload_outcomes_total"
        # A family's label set is fixed, so `=""` selects nothing unless the
        # daemon emits the empty string for that label.
        with self.assertRaisesRegex(
            ValueError,
            rf'{family}\{{outcome=""\}} names value "" the daemon cannot emit',
        ):
            self.check_selector(f'{family}{{outcome=""}}')
        # `!=""` is a presence test, not a value: ignored and not counted.
        self.assertEqual(self.check_selector(f'{family}{{outcome!=""}}'), (0, []))
        self.assertEqual(
            self.check_selector(f'{family}{{outcome!="",outcome="complete"}}'), (1, [])
        )
        # Open labels really are emitted empty, and stay ignored: a listed open
        # label anywhere, and the rule tests' `interface=""` series.
        self.assertEqual(
            self.check_selector(f'{family}{{peer="",outcome="complete"}}'), (1, [])
        )
        self.assertEqual(
            self.check_selector('bgp_peer_session_established{interface=""}', "t.yml",
                                frozenset({"t.yml"})),
            (0, []),
        )
        # A vocabulary that does carry the empty string accepts it.
        key = (family, "outcome")
        self.assertEqual(
            CHECK.check_label_values(
                {"rules.yml": [("line 1", f'{family}{{outcome=""}}')]},
                {key: self.vocabularies[key] | {""}},
                self.inventory,
            ),
            (1, []),
        )
        self.assertEqual(
            CHECK.function_literals(
                'fn label(unset: bool) -> &str { if unset { "" } else { "set" } }',
                None, "label", "fn label",
            ),
            {"", "set"},
        )
        self.assertEqual(
            CHECK.call_argument_literals({"a.rs": 'fn f() { m.set(peer, ""); }'}, "set", 1),
            {""},
        )

    def test_template_variable_on_a_closed_label_is_skipped_and_counted(self):
        family = "bgp_sighup_reload_outcomes_total"
        for matcher in ('="$outcome"', '="${outcome:regex}"', '=~"${outcome:pipe}"'):
            with self.subTest(matcher=matcher):
                checked, skipped = self.check_selector(f"{family}{{outcome{matcher}}}")
                self.assertEqual(checked, 0)
                self.assertEqual(len(skipped), 1)
                self.assertIn(f"outcome{matcher}", skipped[0])

    def test_selector_the_checker_cannot_read_fails_instead_of_passing(self):
        family = "bgp_sighup_reload_outcomes_total"
        for body in ("outcome='bogus'", "outcome=`bogus`", 'outcome="bogus', "outcome=bogus"):
            with self.subTest(body=body), self.assertRaisesRegex(
                ValueError, "selector the checker cannot read"
            ):
                self.check_selector(f"rate({family}{{{body}}}[5m])")
        self.assertEqual(
            self.check_selector(f'{family}{{}} + {family}{{ outcome = "complete" , }}'),
            (1, []),
        )

    def test_histogram_bound_selectors_match_the_emitted_spelling(self):
        family = "bgp_rib_policy_transition_actor_poll_duration_seconds"
        self.assertEqual(
            self.vocabularies[(family, "le")],
            {
                "0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.2", "0.5",
                "1", "2.5", "5", "10", "30", "+Inf",
            },
        )
        for bound in ("0.2", "0.01", "1", "30", "+Inf"):
            with self.subTest(bound=bound):
                self.assertEqual(
                    self.check_selector(f'{family}_bucket{{le="{bound}"}}'), (1, [])
                )
        # PromQL equality is an exact string match on the emitted label, so a
        # numerically equal spelling selects nothing.
        for bound in ("0.200", "0.010", "1.0", "30.0", "Inf", "0.3"):
            with self.subTest(bound=bound), self.assertRaisesRegex(
                ValueError, f'names value "{bound}" the daemon cannot emit'
            ):
                self.check_selector(f'{family}_bucket{{le="{bound}"}}')

    def test_histogram_bound_rendering_normalizes_only_the_source_literal(self):
        for literal, emitted in (
            ("0.200", "0.2"), ("1.0", "1"), ("0.005", "0.005"), ("30.0", "30"),
            ("2.5", "2.5"), ("1_000.0", "1000"), ("10", "10"), ("1e3", "1000"),
        ):
            with self.subTest(literal=literal):
                self.assertEqual(CHECK.emitted_bucket_label(literal), emitted)
        for literal in ("0.00001", "1e20", "-1.0", "f64::INFINITY"):
            with self.subTest(literal=literal), self.assertRaisesRegex(
                ValueError, "cannot render histogram bound"
            ):
                CHECK.emitted_bucket_label(literal)

    def test_label_assembly_body_yields_only_the_mapped_label_values(self):
        family = "bgp_runtime_config_settlement_active"
        fence_reasons = {
            "none", "budget_expired", "executor_lost", "known_divergence",
            "publication_ambiguous", "acknowledgement_lost", "operator_forced",
        }
        self.assertEqual(self.vocabularies[(family, "fence_reason")], fence_reasons)
        self.assertEqual(
            self.vocabularies[(family, "response_attached")], {"attached", "detached"}
        )
        for label, values in (
            ("fence_reason", fence_reasons),
            ("response_attached", {"attached", "detached"}),
        ):
            for value in sorted(values):
                with self.subTest(label=label, value=value):
                    self.assertEqual(
                        self.check_selector(f'{family}{{{label}="{value}"}}'), (1, [])
                    )
        for matcher in ('fence_reason="attached"', 'response_attached="none"'):
            with self.subTest(matcher=matcher), self.assertRaisesRegex(
                ValueError, "the daemon cannot emit"
            ):
                self.check_selector(f"{family}{{{matcher}}}")

    def test_blackhole_rejection_reasons_exclude_the_installable_default(self):
        family = "bgp_blackhole_discard_rejected_total"
        reasons = {
            "not_ebgp", "broad_prefix", "active_limit_exceeded", "install_rate_limited",
        }
        self.assertEqual(self.vocabularies[(family, "reason")], reasons)
        for reason in sorted(reasons):
            with self.subTest(reason=reason):
                self.assertEqual(
                    self.check_selector(f'{family}{{reason="{reason}"}}'), (1, [])
                )
        # `eligible` labels installable candidates, which never reach the counter.
        with self.assertRaisesRegex(
            ValueError, 'names value "eligible" the daemon cannot emit'
        ):
            self.check_selector(f'{family}{{reason="eligible"}}')

    def test_narrowed_function_sources_fail_when_the_body_changes(self):
        rust = dict(self.rust)
        rust[CHECK.BLACKHOLE] = rust[CHECK.BLACKHOLE].replace(
            'reason = "broad_prefix";', 'reason = "covering_prefix";'
        )
        with self.assertRaisesRegex(
            ValueError,
            r"derive_desired in src/blackhole\.rs literals changed: "
            r"gained \['covering_prefix'\], lost \['broad_prefix'\]",
        ):
            CHECK.closed_label_vocabularies(rust, self.inventory)

        rust = dict(self.rust)
        self.assertEqual(rust[CHECK.SETTLEMENT].count("self.phase.as_str(),"), 1)
        rust[CHECK.SETTLEMENT] = rust[CHECK.SETTLEMENT].replace(
            "self.phase.as_str(),", "", 1
        )
        with self.assertRaisesRegex(
            ValueError, "labels .* has 3 elements for the 4 labels in METRIC_LABELS"
        ):
            CHECK.closed_label_vocabularies(rust, self.inventory)

    def test_unclassified_label_fails_only_in_shipped_selectors(self):
        expression = 'bgp_update_malformed_total{disposition="session_reset",reason="x"}'
        with self.assertRaisesRegex(
            ValueError, r'\{reason="x"\} selects a label with no closed label source'
        ):
            self.check_selector(expression)
        self.assertEqual(
            self.check_selector(expression, "tests.yml", frozenset({"tests.yml"})),
            (1, []),
        )

    def test_closed_label_source_without_selector_is_rejected(self):
        with self.assertRaisesRegex(
            ValueError, r"without a shipped selector: \['evpn_df_role\{role\}'\]"
        ):
            CHECK.check_label_values(
                {"rules.yml": [("line 1", "bgp_ready")]},
                {("evpn_df_role", "role"): {"df", "nondf"}},
                self.inventory,
            )

    def test_call_site_literals_ignore_other_arguments_and_variables(self):
        sources = {
            "a.rs": "fn f() { self.metrics\n.set_rib_prefixes(&peer.to_string(), "
            '"all", gauge(a, "x")); m.set_rib_prefixes(peer, family, 0); '
            'm.set_rib_prefixes_later(peer, "later", 0); }',
            "b.rs": 'fn g() { m.other(peer, "other", 0); }',
        }
        self.assertEqual(
            CHECK.call_argument_literals(sources, "set_rib_prefixes", 1), {"all"}
        )
        sources["a.rs"] += " const QUOTE: char = '\"';"
        with self.assertRaisesRegex(ValueError, "a.rs: quote character literal"):
            CHECK.call_argument_literals(sources, "set_rib_prefixes", 1)

    def test_closed_label_source_rows_are_verified_against_the_source(self):
        original = CHECK.CLOSED_LABEL_SOURCES
        cases = (
            ((("bgp_missing_total",), "x", ()), "does not emit"),
            (
                (("bgp_rib_prefixes",), "afi_safi", (("call", "set_loc_rib_prefixes", 0),)),
                "set_loc_rib_prefixes does not write bgp_rib_prefixes",
            ),
            (
                (("evpn_df_role",), "role", (("fn", "src/moved.rs", None, "set"),)),
                "src/moved.rs is not a production source",
            ),
            (
                (("evpn_df_role",), "role", (("fn", CHECK.TELEMETRY, None, "set_missing"),)),
                "expected one fn set_missing",
            ),
            (
                (
                    ("bgp_peer_manager_operator_query_wait_seconds",),
                    "le",
                    (("buckets", CHECK.TELEMETRY, "RIB_ACTOR_DURATION_BUCKETS"),),
                ),
                "RIB_ACTOR_DURATION_BUCKETS does not bound",
            ),
        )
        try:
            for row, message in cases:
                CHECK.CLOSED_LABEL_SOURCES = (row,)
                with self.subTest(row=row), self.assertRaisesRegex(ValueError, message):
                    CHECK.closed_label_vocabularies(self.rust, self.inventory)
        finally:
            CHECK.CLOSED_LABEL_SOURCES = original


if __name__ == "__main__":
    unittest.main()
