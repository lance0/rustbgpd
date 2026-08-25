#!/usr/bin/env python3
import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


PATH = Path(__file__).with_name("check-grafana-dashboard.py")
SPEC = importlib.util.spec_from_file_location("dashboard_check", PATH)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class DashboardMetricLinkTests(unittest.TestCase):
    def evpn_dashboard(self):
        return json.loads(CHECK.EVPN_DASHBOARD.read_text())

    def check_evpn(self, dashboard):
        source = CHECK.METRICS.read_text()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evpn.json"
            path.write_text(json.dumps(dashboard))
            CHECK.check_evpn_dashboard(
                path, CHECK.rust_metric_inventory(source), source
            )

    def evpn_panel(self, dashboard, title):
        return next(
            panel
            for panel in CHECK.all_panels(dashboard["panels"])
            if panel.get("title") == title
        )

    def remove_panel(self, panels, panel_id):
        for index, panel in enumerate(panels):
            if panel.get("id") == panel_id:
                panels.pop(index)
                return True
            if self.remove_panel(panel.get("panels", []), panel_id):
                return True
        return False

    def rust(self, kind="IntGauge", name="bgp_ready", registered=True):
        registration = (
            "registry.register(Box::new(ready.clone())).unwrap();" if registered else ""
        )
        return f'''let ready = {kind}::new("{name}", "help").unwrap();
{registration}
#[cfg(test)] mod tests {{ const OLD: &str = "bgp_old"; }}'''

    def refs(self, expression='bgp_ready{instance="$instance"}'):
        dashboard = {
            "templating": {"list": [{"name": "instance", "type": "query",
                "query": "label_values(bgp_ready, instance)"}]},
            "panels": [{"id": 1, "title": "Health", "targets": [
                {"refId": "A", "expr": expression}]}],
        }
        return CHECK.dashboard_metric_references(dashboard)

    def test_registered_metric_resolves(self):
        CHECK.check_metric_linkage(self.refs(), CHECK.rust_metric_inventory(self.rust()))

    def test_line_comments_preserve_one_newline_and_handle_eof(self):
        self.assertEqual(CHECK.rust_lex("left// one\nright"), ("left\nright", []))
        self.assertEqual(CHECK.rust_lex("left// one\n// two\nright"), ("left\n\nright", []))
        self.assertEqual(CHECK.rust_lex("left// eof"), ("left", []))

    def test_registration_rename_ignores_old_comment_and_test_literal(self):
        rust = self.rust(name="bgp_new").replace(
            "#[cfg(test)]", "// bgp_ready remains documented here\n#[cfg(test)]"
        )
        with self.assertRaisesRegex(ValueError, "bgp_ready.*Health/A"):
            CHECK.check_metric_linkage(self.refs(), CHECK.rust_metric_inventory(rust))

    def test_dashboard_typo_reports_context(self):
        with self.assertRaisesRegex(ValueError, "bgp_typo.*Health/A"):
            CHECK.check_metric_linkage(
                self.refs("bgp_typo{instance=\"x\"}"),
                CHECK.rust_metric_inventory(self.rust()),
            )

    def test_histogram_suffixes_are_kind_aware(self):
        histogram = CHECK.rust_metric_inventory(
            self.rust("HistogramVec", "bgp_latency_seconds")
        )
        refs = {"bgp_latency_seconds_bucket": ["Health/A"],
                "bgp_latency_seconds_count": ["Health/B"],
                "bgp_latency_seconds_sum": ["Health/C"]}
        CHECK.check_metric_linkage(refs, histogram)
        with self.assertRaisesRegex(ValueError, "bgp_ready_bucket"):
            CHECK.check_metric_linkage(
                {"bgp_ready_bucket": ["Health/A"]},
                CHECK.rust_metric_inventory(self.rust()),
            )

    def test_functions_labels_and_literals_are_not_metrics(self):
        refs = self.refs('sum by (peer) (rate(bgp_ready{state="up"}[5m])) > 0')
        self.assertEqual(set(refs), {"bgp_ready"})

    def test_recording_rule_alias_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unsupported.*recording:alias"):
            CHECK.dashboard_metric_references({"templating": {"list": []},
                "panels": [{"id": 1, "title": "X", "targets": [
                    {"refId": "A", "expr": "recording:alias"}]}]})

    def test_empty_reference_and_inventory_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "no dashboard metric"):
            CHECK.dashboard_metric_references({"templating": {"list": []}, "panels": []})
        with self.assertRaisesRegex(ValueError, "no registered Rust metrics"):
            CHECK.rust_metric_inventory("// bgp_ready")

    def test_unregistered_constructor_and_free_strings_do_not_count(self):
        rust = self.rust(registered=False).replace(
            "#[cfg(test)]",
            '// let fake = IntGauge::new("bgp_ready", "help").unwrap();\n'
            "// registry.register(Box::new(fake.clone())).unwrap();\n"
            "#[cfg(test)]",
        ) + '\nlet note = "bgp_ready";'
        with self.assertRaisesRegex(ValueError, "no registered Rust metrics"):
            CHECK.rust_metric_inventory(rust)

    def test_jemalloc_metric_requires_collect_emission(self):
        rust = '''registry.register(Box::new(jemalloc_stats::JemallocCollector::new()));
struct JemallocCollector { allocated: IntGauge }
let allocated = IntGauge::new("jemalloc_allocated_bytes", "help").unwrap();
Self { allocated }
let families = self.allocated.collect();'''
        self.assertIn("jemalloc_allocated_bytes", CHECK.rust_metric_inventory(rust))
        for old, new in [
            ("JemallocCollector::new()", "OtherCollector::new()"),
            ("allocated: IntGauge", "other: IntGauge"),
            ("Self { allocated }", "Self { other: allocated }"),
            ("self.allocated.collect()", "vec![]"),
        ]:
            with self.subTest(mutation=old), self.assertRaises(ValueError):
                CHECK.rust_metric_inventory(rust.replace(old, new))

    def test_mixed_bare_alias_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "recording_alias"):
            self.refs('bgp_ready{x="y"} + recording_alias')

    def test_mixed_metricless_name_selector_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "__name__"):
            self.refs('bgp_ready{x="y"} + {__name__=~"bgp_.*"}')

    def test_code_shaped_normal_and_raw_strings_do_not_count(self):
        fake = 'let fake = IntGauge::new("bgp_fake", "help").unwrap(); registry.register(Box::new(fake.clone()));'
        escaped = fake.replace('"', '\\"')
        source = f'let text = "{escaped}"; let raw = r#"{fake}"#;'
        with self.assertRaisesRegex(ValueError, "no registered Rust metrics"):
            CHECK.rust_metric_inventory(source)

    def test_live_evpn_dashboard_and_frozen_source_inventory(self):
        source = CHECK.METRICS.read_text()
        self.assertEqual(
            {
                name: definition
                for name, definition in CHECK.registered_metric_definitions(source).items()
                if name.startswith("evpn_")
            },
            CHECK.EVPN_METRICS,
        )
        self.check_evpn(self.evpn_dashboard())

    def test_evpn_metric_typo_and_invalid_label_fail_closed(self):
        dashboard = self.evpn_dashboard()
        panel = self.evpn_panel(dashboard, "Active DF assignments")
        expression = panel["targets"][0]["expr"]
        for replacement, error in (
            (expression.replace("evpn_df_role", "evpn_df_roles"), "exact expression"),
            (expression.replace('role="df"', 'role="df",mac="00:00:00:00:00:01"'),
             "exact expression"),
        ):
            with self.subTest(replacement=replacement):
                panel["targets"][0]["expr"] = replacement
                with self.assertRaisesRegex(ValueError, error):
                    self.check_evpn(dashboard)
                panel["targets"][0]["expr"] = expression

    def test_evpn_alpha_marker_and_required_row_fail_closed(self):
        dashboard = self.evpn_dashboard()
        dashboard["title"] = "rustbgpd EVPN Operations"
        with self.assertRaisesRegex(ValueError, "title.*Alpha marker"):
            self.check_evpn(dashboard)

        dashboard = self.evpn_dashboard()
        dashboard["panels"] = [
            panel
            for panel in dashboard["panels"]
            if panel.get("title") != "Duplicate-MAC quarantine"
        ]
        with self.assertRaisesRegex(ValueError, "missing required operator rows.*Duplicate-MAC"):
            self.check_evpn(dashboard)

    def test_evpn_kind_and_cardinality_guards_fail_closed(self):
        dashboard = self.evpn_dashboard()
        panel = self.evpn_panel(dashboard, "DF role changes")
        expression = panel["targets"][0]["expr"]
        panel["targets"][0]["expr"] = expression.replace(
            "sum by (instance, vni)", "sum by (instance, vni, esi)"
        )
        with self.assertRaisesRegex(ValueError, "unsafe aggregation.*esi"):
            CHECK.check_evpn_promql_safety(
                panel["targets"][0]["expr"],
                panel["targets"][0]["legendFormat"],
                CHECK.EVPN_METRICS,
                "test",
            )

        dashboard = self.evpn_dashboard()
        panel = self.evpn_panel(dashboard, "FDB-NHG repair and cleanup")
        panel["targets"][0]["expr"] = panel["targets"][0]["expr"].replace(
            "rate(", "("
        )
        with self.assertRaisesRegex(ValueError, "counter.*must use rate/increase"):
            CHECK.check_evpn_promql_safety(
                panel["targets"][0]["expr"],
                panel["targets"][0]["legendFormat"],
                CHECK.EVPN_METRICS,
                "test",
            )

        dashboard = self.evpn_dashboard()
        panel = self.evpn_panel(dashboard, "Type-5 IP-VRF route state")
        panel["targets"][0]["expr"] = (
            'rate(evpn_ip_vrf_observed_routes{instance=~"$instance",vrf=~"$vrf"}'
            '[$__rate_interval])'
        )
        with self.assertRaisesRegex(ValueError, "gauge.*must not use rate/increase"):
            CHECK.check_evpn_promql_safety(
                panel["targets"][0]["expr"],
                panel["targets"][0]["legendFormat"],
                CHECK.EVPN_METRICS,
                "test",
            )

    def test_evpn_multi_value_vrf_uses_regex_matching(self):
        dashboard = self.evpn_dashboard()
        panel = self.evpn_panel(dashboard, "Type-5 IP-VRF route state")
        panel["targets"][0]["expr"] = panel["targets"][0]["expr"].replace(
            'vrf=~"$vrf"', 'vrf="$vrf"'
        )
        with self.assertRaisesRegex(ValueError, "multi-value.*must use the =~"):
            CHECK.check_evpn_promql_safety(
                panel["targets"][0]["expr"],
                panel["targets"][0]["legendFormat"],
                CHECK.EVPN_METRICS,
                "test",
            )

    def test_evpn_load_bearing_promql_mutations_fail_closed(self):
        mutations = (
            ("Active DF assignments", ' == 1)', ' >= 0)'),
            ("Type-5 IP-VRF route state", "sum by", "avg by"),
            (
                "Time since first recorded move for active quarantines",
                " and on (instance, vni, mac) ",
                " + on (instance, vni, mac) ",
            ),
            ("Quarantined local Type-2 keys", " == 1)", " == 1) or vector(0)"),
        )
        for title, old, new in mutations:
            with self.subTest(panel=title):
                dashboard = self.evpn_dashboard()
                target = self.evpn_panel(dashboard, title)["targets"][0]
                self.assertIn(old, target["expr"])
                target["expr"] = target["expr"].replace(old, new, 1)
                with self.assertRaisesRegex(ValueError, "exact expression"):
                    self.check_evpn(dashboard)

    def test_evpn_target_legend_and_datasource_are_exact(self):
        for field, replacement, error in (
            ("legendFormat", "{{instance}} vague", "retain legend"),
            (
                "datasource",
                {"type": "prometheus", "uid": "prometheus-fixed"},
                "bind the Prometheus.*datasource",
            ),
        ):
            with self.subTest(field=field):
                dashboard = self.evpn_dashboard()
                target = self.evpn_panel(dashboard, "Active DF assignments")["targets"][0]
                target[field] = replacement
                with self.assertRaisesRegex(ValueError, error):
                    self.check_evpn(dashboard)

    def test_evpn_extra_data_panel_fails_closed(self):
        dashboard = self.evpn_dashboard()
        dashboard["panels"].append(
            {
                "id": 999,
                "type": "timeseries",
                "title": "Unsafe per-MAC quarantine detail",
                "targets": [
                    {
                        "refId": "A",
                        "expr": (
                            "evpn_duplicate_mac_quarantine_active"
                            '{instance=~"$instance"}'
                        ),
                        "legendFormat": "{{mac}}",
                        "datasource": CHECK.EVPN_TARGET_DATASOURCE,
                    }
                ],
            }
        )
        with self.assertRaisesRegex(ValueError, "unexpected data panels.*Unsafe per-MAC"):
            self.check_evpn(dashboard)

    def test_evpn_duplicate_required_panel_title_fails_closed(self):
        dashboard = self.evpn_dashboard()
        duplicate = json.loads(
            json.dumps(self.evpn_panel(dashboard, "Active DF assignments"))
        )
        duplicate["id"] = 999
        dashboard["panels"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "exactly one.*counts=.*Active DF"):
            self.check_evpn(dashboard)

    def test_live_dashboard_presentation_mutations_pass_full_check(self):
        dashboard = json.loads(CHECK.DASHBOARD.read_text())
        for index, panel in enumerate(CHECK.all_panels(dashboard["panels"])):
            changes = {"description": "changed",
                       "collapsed": not panel.get("collapsed", False),
                       "id": panel["id"] + 1000}
            if panel["title"] in {"BLACKHOLE discard activity", "BLACKHOLE active rows"}:
                changes["gridPos"] = {**panel["gridPos"], "h": 9, "y": 17}
            else:
                changes["gridPos"] = {"x": index % 24}
            panel.update(changes)
        blackhole = next(
            panel
            for panel in dashboard["panels"]
            if panel["title"] == "BLACKHOLE discard activity"
        )
        blackhole_row = next(
            panel
            for panel in dashboard["panels"]
            if panel["title"] == "Kernel discard routes"
        )
        dashboard["panels"].remove(blackhole)
        blackhole_row["panels"].append(blackhole)
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / "dashboard.json"
            copy.write_text(json.dumps(dashboard))
            original, CHECK.DASHBOARD = CHECK.DASHBOARD, copy
            try:
                with redirect_stdout(io.StringIO()):
                    CHECK.main()
                orr = next(panel for panel in dashboard["panels"]
                           if panel["title"] == "ORR SPF activity and topology")
                for field in ("expr", "legendFormat"):
                    saved = orr["targets"][0][field]
                    orr["targets"][0][field] = "broken"
                    copy.write_text(json.dumps(dashboard))
                    with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                        CHECK.main()
                    orr["targets"][0][field] = saved
                blackhole = next(
                    panel
                    for panel in CHECK.all_panels(dashboard["panels"])
                    if panel["title"] == "BLACKHOLE discard activity"
                )
                mutations = ((blackhole["targets"][0], "expr", "broken"),
                             (blackhole["targets"][0], "legendFormat", "broken"),
                             (blackhole, "gridPos", {"x": 0}))
                for subject, field, replacement in mutations:
                    saved = subject[field]
                    subject[field] = replacement
                    copy.write_text(json.dumps(dashboard))
                    with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                        CHECK.main()
                    subject[field] = saved
                active = next(
                    panel for panel in CHECK.all_panels(dashboard["panels"])
                    if panel["title"] == "BLACKHOLE active rows"
                )
                for subject, field, replacement in (
                    (active["targets"][0], "expr", "broken"),
                    (active, "gridPos", {"x": 0, "w": 8}),
                    (active["fieldConfig"], "defaults", {"unit": "ops"}),
                    (active, "options", {"reduceOptions": {"calcs": ["last"]}}),
                ):
                    saved = subject[field]
                    subject[field] = replacement
                    copy.write_text(json.dumps(dashboard))
                    with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                        CHECK.main()
                    subject[field] = saved
                self.assertTrue(self.remove_panel(dashboard["panels"], blackhole["id"]))
                copy.write_text(json.dumps(dashboard))
                stderr = io.StringIO()
                targets = CHECK.TARGETS
                legends = CHECK.REQUIRED_LEGENDS
                CHECK.TARGETS = {
                    key: value
                    for key, value in targets.items()
                    if key[0] != "BLACKHOLE discard activity"
                }
                CHECK.REQUIRED_LEGENDS = {
                    key: value
                    for key, value in legends.items()
                    if key[0] != "BLACKHOLE discard activity"
                }
                try:
                    with self.assertRaises(SystemExit), redirect_stderr(stderr):
                        CHECK.main()
                finally:
                    CHECK.TARGETS = targets
                    CHECK.REQUIRED_LEGENDS = legends
                self.assertIn(
                    "BLACKHOLE discard activity panel must exist", stderr.getvalue()
                )
            finally:
                CHECK.DASHBOARD = original


if __name__ == "__main__":
    unittest.main()
