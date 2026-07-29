import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "verify-vpn-query-campaign.py"
SPEC = importlib.util.spec_from_file_location("vpn_verify", SCRIPT)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class VerifyCampaign(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        (self.root / "bin").mkdir()
        (self.root / "timing").mkdir()
        for name in ("vpn_query_timing", "vpn_query_allocation"):
            (self.root / "bin" / name).write_bytes(name.encode())
        timing_hash = hashlib.sha256(b"vpn_query_timing").hexdigest()
        allocation_hash = hashlib.sha256(b"vpn_query_allocation").hexdigest()
        manifest = {
            "schema": 2, "base_commit": "a" * 40, "rustc": "rustc fixture",
            "host_fence": "pass", "source_tree_clean": True,
            "fixed_order": list(VERIFY.CASES),
            "timing_binary_sha256": timing_hash,
            "allocation_binary_sha256": allocation_hash,
        }
        self.write("manifest.json", manifest)
        for ordinal, size, case, repetition in VERIFY.expected_cells():
            actor = 10_000_000 + repetition * 10
            service = 300_000_000 + actor
            receipt = {
                "schema": 2, "mode": "timing", "ordinal": ordinal,
                "routes": size, "case": case, "repetition": repetition,
                "binary_sha256": timing_hash,
                "source_commit": "a" * 40, "timeout_seconds": 120,
                "query": {
                    "actor_handler_ns": actor,
                    "service_method_ns": service, "post_actor_ns": 300_000_000,
                    "actor_rows": size, "actor_capacity": size,
                    "returned_rows": size if case == "U" else size // 16,
                    "dispatch": 1, "checksum": ordinal,
                },
            }
            self.write(f"timing/{ordinal:02d}.json", receipt)
        self.write("allocation.json", {
            "schema": 2, "mode": "allocation", "routes": 1_000_000, "case": "U",
            "binary_sha256": allocation_hash, "peak_live_requested_bytes": 1024,
            "source_commit": "a" * 40, "timeout_seconds": 120,
            "vmrss_bytes": 999999999999, "vmhwm_bytes": 999999999999,
        })

    def tearDown(self):
        self.temp.cleanup()

    def write(self, relative, value):
        (self.root / relative).write_text(json.dumps(value), encoding="utf-8")

    def mutate(self, relative, callback):
        path = self.root / relative
        value = json.loads(path.read_text())
        callback(value)
        self.write(relative, value)

    def test_valid_fixture_and_observational_rss(self):
        result = VERIFY.verify(self.root)
        self.assertEqual(result["classification"], "no_redesign")

    def test_rejects_count_order_dual_case_underflow_and_binary_corruption(self):
        mutations = [
            ("timing/48.json", lambda: (self.root / "timing/48.json").unlink()),
            ("timing/02.json", lambda: self.mutate("timing/02.json",
                                                   lambda d: d.update(ordinal=3))),
            ("timing/01.json", lambda: self.mutate("timing/01.json",
                                                   lambda d: d.update(queries={}))),
            ("timing/01.json", lambda: self.mutate("timing/01.json",
                                                   lambda d: d["query"].update(
                                                       actor_handler_ns=20_000_000))),
            ("timing/01.json", lambda: self.mutate("timing/01.json",
                                                   lambda d: d.update(timeout_seconds=121))),
            ("timing/01.json", lambda: self.mutate("timing/01.json",
                                                   lambda d: d.update(source_commit="b" * 40))),
            ("bin/vpn_query_timing", lambda: (self.root / "bin/vpn_query_timing")
             .write_bytes(b"corrupt")),
        ]
        for index, (_, mutation) in enumerate(mutations):
            with self.subTest(mutation=mutation):
                mutation()
                with self.assertRaises(VERIFY.Invalid):
                    VERIFY.verify(self.root)
                if index + 1 < len(mutations):
                    self.tearDown()
                    self.setUp()

    def test_classifier_precedence_and_thresholds(self):
        timings = {
            (size, case): [10 * (index + 1)] * 8
            for index, size in enumerate(VERIFY.SIZES) for case in ("U", "F")
        }
        allocation = {"peak_live_requested_bytes": 1}
        self.assertEqual(VERIFY.classify({}, timings, allocation)["classification"],
                         "no_redesign")
        timings[(10_000, "U")] = [25_000_001] * 8
        timings[(10_000, "F")] = [25_000_001] * 8
        timings[(100_000, "U")] = [25_000_002] * 8
        timings[(100_000, "F")] = [25_000_002] * 8
        timings[(1_000_000, "U")] = [25_000_003] * 8
        timings[(1_000_000, "F")] = [25_000_003] * 8
        self.assertEqual(VERIFY.classify({}, timings, allocation)["classification"],
                         "design_followup")
        for key in timings:
            timings[key] = [200_000_001] * 8
        self.assertEqual(VERIFY.classify({}, timings, allocation)["classification"], "urgent")
        timings[(10_000, "F")] = [100_000_000] * 8
        self.assertEqual(VERIFY.classify({}, timings, allocation)["classification"],
                         "instrumentation_suspect")
        timings[(10_000, "F")] = [200_000_001] * 8
        timings[(10_000, "U")][1] *= 2
        self.assertEqual(VERIFY.classify({}, timings, allocation)["classification"],
                         "inconclusive")
        allocation["peak_live_requested_bytes"] = VERIFY.CAPACITY + 1
        self.assertEqual(VERIFY.classify({}, timings, allocation)["classification"],
                         "capacity_censored")

    def test_size_specific_noise_and_monotonic_instrumentation(self):
        allocation = {"peak_live_requested_bytes": 1}
        timings = {
            (size, case): [100] * 8 for size in VERIFY.SIZES for case in ("U", "F")
        }
        timings[(1_000_000, "U")] = [100, 106] * 4
        timings[(1_000_000, "F")] = [100, 106] * 4
        self.assertEqual(VERIFY.classify({}, timings, allocation)["classification"],
                         "no_redesign")
        timings[(10_000, "U")] = [100, 106] * 4
        timings[(10_000, "F")] = [100, 106] * 4
        self.assertEqual(VERIFY.classify({}, timings, allocation)["classification"],
                         "inconclusive")
        timings = {
            (size, case): [300 - index * 100] * 8
            for index, size in enumerate(VERIFY.SIZES) for case in ("U", "F")
        }
        self.assertEqual(VERIFY.classify({}, timings, allocation)["classification"],
                         "instrumentation_suspect")


if __name__ == "__main__":
    unittest.main()
