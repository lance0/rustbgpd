#!/usr/bin/env python3
"""Seeded false-green controls for the actual-daemon EVPN memory consumer."""

import argparse
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("evpn_qualification", HERE / "qualify.py")
Q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(Q)


def metrics_text(allocated=100_000_000):
    return f"jemalloc_allocated_bytes {allocated}\n" + "".join(
        f'bgp_evpn_recovery_provenance_exhausted_total{{cause="{cause}"}} 0\n' for cause in Q.CAUSES)


def witness(arm, clients=3, routes=10):
    candidate = arm == "candidate"
    return {"members": clients, "owned_groups": int(candidate), "owned_members": clients if candidate else 0,
            "owned_routes": clients * routes if candidate else 0,
            "private_routes": 0 if candidate else clients * (clients - 1) * routes,
            "dirty": 0, "retained": clients * 64 if candidate else 0,
            "peak": clients * 128 if candidate else 0, "peer_budget": 16 * 1024 ** 2,
            "daemon_budget": 256 * 1024 ** 2, "pending_resets": 0, "completion_receipts": 0,
            "marker_debt": 0, "retained_recovery": 0,
            "refresh_pending": 0, "eor_pending": 0, "protocol_obligations": 0,
            "peers": [[Q.COMMON.peer(index), 1 if candidate else None, False,
                       64 if candidate else 0, 128 if candidate else 0, 0, False, False, False, False]
                      for index in range(clients)]}


def driver_text(clients, routes):
    expected = (clients - 1) * routes
    return (f"converged (initial) clients={clients} expected={expected} ms=42\n"
            f"evpn_receipt clients={clients} expected={expected} epochs=0 converged_epochs=0 "
            f"flaps=0 reloads=0 receivers={clients} min_live={expected} max_live={expected} "
            "invalid=0 parse_errors=0 self_reflected=0\n")


class TestQualification(unittest.TestCase):
    def test_readiness_retains_http_error_code_separately(self):
        error = Q.urllib.error.HTTPError("http://readyz", 503, "busy", {}, None)
        with patch.object(Q, "fetch", side_effect=error):
            self.assertEqual(Q.probe_readiness(), {"status": 503, "http_error_code": 503})
        with patch.object(Q, "fetch", side_effect=TimeoutError("timeout")):
            self.assertEqual(Q.probe_readiness(), {"status": 0, "http_error_code": None})
        with patch.object(Q, "fetch", return_value=(200, "ready")):
            self.assertEqual(Q.probe_readiness(), {"status": 200, "http_error_code": None})

    def test_private_bar_misses_do_not_abort_later_memory_cells(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryFile() as lock:
            args = argparse.Namespace(output=temporary, correctness_only=False)
            manifest = {"schedule": Q.SCHEDULE}
            def cell(*args):
                if args[2] == "private":
                    raise Q.AcceptanceFailure("baseline bar miss")
            with patch.object(Q, "manifest_for", return_value=manifest), \
                 patch.object(Q, "verify_export"), \
                 patch.dict(Q.os.environ, {"RUSTBGPD_HOST_LOCK_FD": str(lock.fileno())}), \
                 patch.object(Q, "run_cell", side_effect=cell) as run, \
                 patch.object(Q, "analyze") as analyze:
                Q.run(args)
            self.assertEqual([call.args[2] for call in run.call_args_list], list(Q.SCHEDULE) * len(Q.SHAPES))
            self.assertEqual([call.args[5] for call in run.call_args_list], list(range(24)))
            analyze.assert_called_once_with(args)

    def test_candidate_bar_and_private_invalid_still_abort_memory_cells(self):
        for arm, error in (("candidate", Q.AcceptanceFailure("candidate bar miss")),
                           ("private", ValueError("technical failure"))):
            with self.subTest(arm=arm), tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryFile() as lock:
                args = argparse.Namespace(output=temporary, correctness_only=False)
                def cell(*args, arm=arm, error=error):
                    if args[2] == arm:
                        raise error
                with patch.object(Q, "manifest_for", return_value={"schedule": Q.SCHEDULE}), \
                     patch.object(Q, "verify_export"), \
                     patch.dict(Q.os.environ, {"RUSTBGPD_HOST_LOCK_FD": str(lock.fileno())}), \
                     patch.object(Q, "run_cell", side_effect=cell) as run, \
                     patch.object(Q, "analyze") as analyze:
                    with self.assertRaises(type(error)):
                        Q.run(args)
                self.assertEqual(run.call_count, 1 if arm == "candidate" else 2)
                analyze.assert_not_called()

    def test_cleanup_error_during_bar_failure_remains_technical(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, leg = root / "fixture-input", root / "leg"
            fixture.mkdir()
            leg.mkdir()
            (fixture / "config.toml").write_text("fixture")
            record = {"status": "FAIL", "error": "baseline bar miss"}
            with patch.object(Q.COMMON, "stop_owned", side_effect=ValueError("still running")):
                with self.assertRaisesRegex(ValueError, "owned-resource cleanup") as caught:
                    try:
                        raise Q.AcceptanceFailure("baseline bar miss")
                    finally:
                        Q.cleanup_cell(record, leg, fixture, "driver", "daemon")
            self.assertIsInstance(caught.exception.__context__, Q.AcceptanceFailure)
            retained = json.loads((leg / "result.json").read_text())
            self.assertEqual(retained["status"], "INVALID")
            self.assertEqual(retained["error"], "baseline bar miss")

    def test_control_bar_failure_summary_is_fail_not_invalid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.make_campaign(root)
            path = next(root.glob("memory-*-private-*/result.json"))
            row = json.loads(path.read_text())
            row.update(status="FAIL", error="readiness HTTP 503")
            Q.write_json(path, row)
            with self.assertRaises(Q.AcceptanceFailure):
                Q.analyze(args)
            summary = json.loads((root / "summary.json").read_text())
            self.assertEqual(summary["status"], "FAIL")
            self.assertEqual(summary["failed_cells"][0]["arm"], "private")
            self.assertEqual(summary["failed_cells"][0]["error"], "readiness HTTP 503")

    def test_cleanup_failure_still_attempts_both_children_and_retains_original_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, leg = root / "fixture-input", root / "leg"
            fixture.mkdir()
            leg.mkdir()
            (fixture / "config.toml").write_text("fixture")
            record = {"status": "FAIL", "error": "original acceptance failure"}
            controller = Mock()
            controller.close.side_effect = ValueError("sampler did not stop")
            with patch.object(Q.COMMON, "stop_owned", side_effect=[ValueError("driver cleanup"), None]) as stop:
                with self.assertRaisesRegex(ValueError, "owned-resource cleanup"):
                    Q.cleanup_cell(record, leg, fixture, "driver", "daemon", controller)
                self.assertEqual([call.args[0] for call in stop.call_args_list], ["driver", "daemon"])
            retained = json.loads((leg / "result.json").read_text())
            self.assertEqual(retained["status"], "INVALID")
            self.assertEqual(retained["error"], "original acceptance failure")
            self.assertEqual(len(retained["cleanup_errors"]), 2)
            self.assertTrue((leg / "fixture/config.toml").exists())

    def test_each_executed_reset_cause_fails_even_with_exact_receivers(self):
        self.assertEqual(Q.metrics(metrics_text())["jemalloc_allocated_bytes"], 100_000_000)
        for cause in Q.CAUSES:
            with self.subTest(cause=cause):
                text = metrics_text().replace(f'cause="{cause}"}} 0', f'cause="{cause}"}} 1')
                with self.assertRaisesRegex(Q.AcceptanceFailure, "executed EVPN"):
                    Q.metrics(text)

    def test_missing_reset_and_non_jemalloc_builds_are_invalid(self):
        for text in ("\n".join(metrics_text().splitlines()[:-1]),
                     metrics_text().replace("jemalloc_allocated_bytes", "process_resident_memory_bytes"),
                     metrics_text().replace("100000000", "NaN")):
            with self.assertRaises(ValueError):
                Q.metrics(text)

    def test_unrelated_prometheus_labels_can_contain_spaces(self):
        text = metrics_text() + 'bgp_peer_state{description="evpn client gen-a",peer="127.1.0.1"} 6\n'
        self.assertEqual(Q.metrics(text)["jemalloc_allocated_bytes"], 100_000_000)

    def test_two_private_arms_cannot_pass_as_owned_candidate(self):
        Q.ownership(witness("candidate"), "candidate", 3, 10)
        Q.ownership(witness("private"), "private", 3, 10)
        with self.assertRaisesRegex(ValueError, "candidate did not actually own"):
            Q.ownership(witness("private"), "candidate", 3, 10)

    def test_aggregate_claim_cannot_hide_private_or_missing_peer(self):
        for mutate in (lambda row: row["peers"][0].__setitem__(1, None),
                       lambda row: row["peers"].__setitem__(1, row["peers"][0]),
                       lambda row: row.__setitem__("private_routes", 1),
                       lambda row: row["peers"][0].__setitem__(5, 1),
                       lambda row: row["peers"][0].__setitem__(6, True),
                       lambda row: row.__setitem__("retained", -1),
                       lambda row: row.__setitem__("peak", row["daemon_budget"] + 1)):
            row = witness("candidate")
            mutate(row)
            with self.assertRaises(ValueError):
                Q.ownership(row, "candidate", 3, 10)

    def test_exact_receiver_count_is_not_enough(self):
        text = driver_text(3, 10)
        Q.receipt(text, 3, 10)
        for bad in (text.replace("invalid=0", "invalid=1"),
                    text.replace("max_live=20", "max_live=21"),
                    text + "evpn_session_lost client=1\n",
                    text + "FAIL: receiver state changed before finish acknowledgement\n",
                    text + text):
            with self.assertRaises(ValueError):
                Q.receipt(bad, 3, 10)

    def test_private_derivation_changes_only_candidate_constructor(self):
        main = "RibManager::new().with_readiness_queries(rib_readiness_rx);\n"
        rib = "impl RibManager {\n    fn sample_outbound_dirty_gauges(&self) {\n    }\n}\n"
        observer = "        self.bench_evpn_group_receipt();\n"
        candidate = Q.derived_texts(main, rib, observer, "candidate")
        private = Q.derived_texts(main, rib, observer, "private")
        self.assertEqual(candidate[1], private[1])
        self.assertEqual(private[0], main)
        self.assertIn(".with_bench_evpn_group_ownership()", candidate[0])
        for broken in (main + main, main.replace("rib_readiness_rx", "moved_rx"), candidate[0]):
            with self.assertRaises(ValueError):
                Q.derived_texts(broken, rib, observer, "private")

    def make_campaign(self, root, slope=5):
        (root / "source.tar").write_bytes(b"source identity fixture")
        manifest = {"schema": "rustbgpd.evpn-memory.v1", "head": "f" * 40,
                    "source_sha256": Q.digest(root / "source.tar"), "shapes": Q.SHAPES,
                    "schedule": Q.SCHEDULE, "settle_seconds": 45, "daemon_bytes": Q.DAEMON_BYTES,
                    "max_slope_bytes_per_delivery": Q.MAX_SLOPE_BYTES}
        Q.write_json(root / "campaign.json", manifest)
        index = 0
        for clients, routes in Q.SHAPES:
            deliveries = clients * (clients - 1) * routes
            for arm in Q.SCHEDULE:
                leg = root / f"memory-{index:02}-{arm}-{clients}x{routes}"
                leg.mkdir()
                index += 1
                allocated = 100_000_000 + deliveries * (slope if arm == "candidate" else 300)
                cg = {"memory.current": allocated + 1024, "memory.peak": allocated + 2048,
                      "memory.max": Q.DAEMON_BYTES, "memory.swap.max": 0,
                      "memory.swap.current": 0, "memory.swap.peak": 0}
                owned = witness(arm, clients, routes)
                row = {"status": "PASS", "correctness_only": False, "arm": arm, "clients": clients,
                       "routes_per_client": routes, "ownership": owned,
                       "executed_resets": dict.fromkeys(Q.CAUSES, 0), "driver_exit": 0,
                       "readiness": [{"status": 200, "elapsed_seconds": .001}],
                       "memory": {**cg, "jemalloc_allocated_bytes": allocated}}
                Q.write_json(leg / "result.json", row)
                Q.write_json(leg / "cgroup.json", cg)
                (leg / "metrics.txt").write_text(metrics_text(allocated))
                (leg / "observer.log").write_text("evpn_qualification " + json.dumps(owned) + "\n")
                (leg / "daemon.log").write_text('evpn_qualification {interleaved stdout fragment}\n')
                (leg / "driver.log").write_text(driver_text(clients, routes))
        return argparse.Namespace(output=str(root))

    def test_raw_slopes_are_separate_and_bar_catches_regression(self):
        for slope, status in ((5, "PASS"), (10, "PASS"), (11, "FAIL")):
            with self.subTest(slope=slope), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                args = self.make_campaign(root, slope)
                if status == "FAIL":
                    with self.assertRaisesRegex(Q.AcceptanceFailure, "slope exceeds"):
                        Q.analyze(args)
                else:
                    Q.analyze(args)
                summary = json.loads((root / "summary.json").read_text())
                self.assertEqual(summary["status"], status)
                self.assertEqual(len(summary["slopes"]), 4)
                self.assertFalse(summary["production_activation_qualified"])
                for row in summary["slopes"]:
                    self.assertEqual(row["bytes_per_delivery"]["jemalloc_allocated_bytes"],
                                     slope if row["arm"] == "candidate" else 300)

    def test_missing_sample_cannot_change_the_median_roster(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.make_campaign(root)
            next(root.glob("memory-*/result.json")).unlink()
            with self.assertRaisesRegex(ValueError, "matrix"):
                Q.analyze(args)

    def test_raw_reset_failure_cannot_be_hidden_by_a_pass_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.make_campaign(root)
            raw = next(root.glob("memory-*/metrics.txt"))
            raw.write_text(raw.read_text().replace('cause="admission_invariant"} 0',
                                                   'cause="admission_invariant"} 1'))
            with self.assertRaisesRegex(Q.AcceptanceFailure, "executed EVPN"):
                Q.analyze(args)

    def test_changed_bar_cannot_reclassify_a_failed_campaign(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self.make_campaign(root, 11)
            path = root / "campaign.json"
            row = json.loads(path.read_text())
            row["max_slope_bytes_per_delivery"] = 12
            Q.write_json(path, row)
            with self.assertRaisesRegex(ValueError, "bars changed"):
                Q.analyze(args)

    def test_export_verifier_rejects_runtime_drift_and_extra_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {"src/main.rs": "RibManager::new().with_readiness_queries(rib_readiness_rx);",
                     "crates/rib/src/manager/mod.rs": "    fn sample_outbound_dirty_gauges(&self) {\n}\n                    self.handle_end_of_rib(peer, afi, safi);\n",
                     "bench/scale/evpn-qualification/observer.rs": "        self.bench_evpn_group_receipt();\n",
                     "bench/scale/evpn-qualification/input_observer.rs": "// input applied observer\n",
                     "crates/wire/src/lib.rs": "// actual runtime input\n"}
            with tarfile.open(root / "source.tar", "w") as archive:
                for name, text in files.items():
                    member = tarfile.TarInfo(name)
                    data = text.encode()
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
                member = tarfile.TarInfo("crates/wire/README-link")
                member.type = tarfile.SYMTYPE
                member.linkname = "src/lib.rs"
                archive.addfile(member)
            source = root / "sources/candidate"
            for name, text in files.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            (source / "crates/wire/README-link").symlink_to("src/lib.rs")
            Q.derive(source, "candidate")
            Q.verify_export(root, "candidate")
            path = source / "crates/wire/src/lib.rs"
            path.write_text("// changed behavior\n")
            with self.assertRaisesRegex(ValueError, "source drift"):
                Q.verify_export(root, "candidate")
            path.write_text(files["crates/wire/src/lib.rs"])
            (source / "build.rs").write_text("fn main() {}")
            with self.assertRaisesRegex(ValueError, "untracked build inputs"):
                Q.verify_export(root, "candidate")


if __name__ == "__main__":
    unittest.main()
