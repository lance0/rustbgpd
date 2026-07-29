import hashlib
import importlib.util
import json
import pathlib
import shutil
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
        (self.root / "attempt-1" / "timing").mkdir(parents=True)
        for name in ("vpn_query_timing", "vpn_query_allocation"):
            (self.root / "bin" / name).write_bytes(name.encode())
        timing_hash = hashlib.sha256(b"vpn_query_timing").hexdigest()
        allocation_hash = hashlib.sha256(b"vpn_query_allocation").hexdigest()
        manifest = {
            "schema": 2, "base_commit": "a" * 40, "rustc": "rustc fixture",
            "host_fence": "pass", "source_tree_clean": True,
            "source_tree": "c" * 40, "attempts": 1,
            "fixed_order": list(VERIFY.CASES),
            "timing_binary_sha256": timing_hash,
            "allocation_binary_sha256": allocation_hash,
        }
        self.write("manifest.json", manifest)
        for ordinal, size, case, repetition in VERIFY.expected_cells():
            actor = size * 10 + repetition * 10
            service = 300_000_000 + actor
            receipt = {
                "schema": 2, "mode": "timing", "ordinal": ordinal,
                "routes": size, "case": case, "repetition": repetition,
                "binary_sha256": timing_hash,
                "source_commit": "a" * 40, "timeout_seconds": 120,
                "attempt": 1,
                "query": {
                    "actor_handler_ns": actor,
                    "service_method_ns": service, "post_actor_ns": 300_000_000,
                    "actor_rows": size, "actor_capacity": size,
                    "returned_rows": size if case == "U" else size // 16,
                    "dispatch": 1, "checksum": VERIFY.CHECKSUMS[(size, case)],
                },
            }
            self.write(f"attempt-1/timing/{ordinal:02d}.json", receipt)
        self.write("allocation.json", {
            "schema": 2, "mode": "allocation", "routes": 1_000_000, "case": "U",
            "binary_sha256": allocation_hash, "peak_live_requested_bytes": 1024,
            "source_commit": "a" * 40, "timeout_seconds": 120,
            "attempt": 1,
            "vmrss_bytes": 999999999999, "vmhwm_bytes": 999999999999,
            "query": {"actor_rows": 1_000_000, "actor_capacity": 1_000_000,
                      "returned_rows": 1_000_000,
                      "actor_handler_ns": 10, "service_method_ns": 11,
                      "post_actor_ns": 1,
                      "checksum": VERIFY.CHECKSUMS[(1_000_000, "U")], "dispatch": 1},
        })
        phases = ["build"] + [f"attempt-1-timing-{i}" for i in range(1, 49)] + [
            "allocation"
        ]
        header = ("phase\tattempt\tutc\tload_1m\tload_1m_max\tgovernor\t"
                  "required_governor\tcompeting_process_count\tcompeting_processes\tstatus\n")
        rows = "".join(f"{phase}\t1\tnow\t0\t2\tperformance\tperformance\t0\tnone\tpass\n"
                       for phase in phases)
        (self.root / "host-preflight.tsv").write_text(header + rows)

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
            ("attempt-1/timing/48.json", lambda: (self.root / "attempt-1/timing/48.json").unlink()),
            ("attempt-1/timing/02.json", lambda: self.mutate("attempt-1/timing/02.json",
                                                   lambda d: d.update(ordinal=3))),
            ("attempt-1/timing/01.json", lambda: self.mutate("attempt-1/timing/01.json",
                                                   lambda d: d.update(queries={}))),
            ("attempt-1/timing/01.json", lambda: self.mutate("attempt-1/timing/01.json",
                                                   lambda d: d["query"].update(
                                                       actor_handler_ns=20_000_000))),
            ("attempt-1/timing/01.json", lambda: self.mutate("attempt-1/timing/01.json",
                                                   lambda d: d.update(timeout_seconds=121))),
            ("attempt-1/timing/01.json", lambda: self.mutate("attempt-1/timing/01.json",
                                                   lambda d: d.update(source_commit="b" * 40))),
            ("bin/vpn_query_timing", lambda: (self.root / "bin/vpn_query_timing")
             .write_bytes(b"corrupt")),
            ("attempt-1/timing/01.json",
             lambda: self.mutate("attempt-1/timing/01.json",
                                 lambda d: d["query"].update(checksum=999))),
            ("allocation.json",
             lambda: self.mutate("allocation.json",
                                 lambda d: d["query"].update(returned_rows=999))),
            ("allocation.json",
             lambda: self.mutate("allocation.json",
                                 lambda d: d["query"].update(checksum=999))),
            ("allocation.json",
             lambda: self.mutate("allocation.json",
                                 lambda d: d["query"].update(post_actor_ns=2))),
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
        for index, size in enumerate(VERIFY.SIZES):
            for case in ("U", "F"):
                timings[(size, case)] = [200_000_001 + index] * 8
        self.assertEqual(VERIFY.classify({}, timings, allocation)["classification"], "urgent")
        timings[(10_000, "F")] = [100_000_000] * 8
        self.assertEqual(VERIFY.classify({}, timings, allocation)["classification"],
                         "instrumentation_suspect")

        timings = {
            (size, case): [100] * 8
            for size in VERIFY.SIZES for case in ("U", "F")
        }
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
            (size, case): [100 * (index + 1)] * 8
            for index, size in enumerate(VERIFY.SIZES) for case in ("U", "F")
        }
        timings[(1_000_000, "U")] = [300, 318] * 4
        timings[(1_000_000, "F")] = [300, 318] * 4
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

    def test_complete_retry_and_typed_capacity_censor(self):
        shutil.copytree(self.root / "attempt-1", self.root / "attempt-2")
        self.mutate("manifest.json", lambda d: d.update(attempts=2))
        self.mutate("allocation.json", lambda d: d.update(attempt=2))
        for path in (self.root / "attempt-2" / "timing").glob("*.json"):
            value = json.loads(path.read_text())
            value["attempt"] = 2
            path.write_text(json.dumps(value))
        with (self.root / "host-preflight.tsv").open("a") as stream:
            for ordinal in range(1, 49):
                stream.write(
                    f"attempt-2-timing-{ordinal}\t1\tnow\t0\t2\tperformance\t"
                    "performance\t0\tnone\tpass\n"
                )
        self.assertEqual(VERIFY.verify(self.root)["classification"], "no_redesign")
        allocation = json.loads((self.root / "allocation.json").read_text())
        allocation.update(outcome="capacity_censored", censor_phase="service_query",
                          ordinal=49, repetition=1)
        self.write("censor.json", allocation)
        (self.root / "allocation.json").unlink()
        self.assertEqual(VERIFY.verify(self.root)["classification"],
                         "capacity_censored")
        (self.root / "censor.json").unlink()
        self.write("allocation.json", {k: v for k, v in allocation.items()
                                      if k not in ("outcome", "censor_phase", "ordinal",
                                                   "repetition")})
        (self.root / "attempt-2" / "timing" / "48.json").unlink()
        with self.assertRaises(VERIFY.Invalid):
            VERIFY.verify(self.root)
        shutil.copy(self.root / "attempt-1" / "timing" / "48.json",
                    self.root / "attempt-2" / "timing" / "48.json")
        (self.root / "attempt-3").mkdir()
        with self.assertRaises(VERIFY.Invalid):
            VERIFY.verify(self.root)
        (self.root / "attempt-3").rmdir()
        censor = json.loads(
            (self.root / "attempt-2" / "timing" / "11.json").read_text())
        censor.pop("query")
        censor.update(outcome="capacity_censored", censor_phase="actor_receipt")
        self.write("censor.json", censor)
        for ordinal in range(11, 49):
            (self.root / "attempt-2" / "timing" / f"{ordinal:02d}.json").unlink()
        (self.root / "allocation.json").unlink()
        log = self.root / "host-preflight.tsv"
        log.write_text("\n".join(
            line for line in log.read_text().splitlines()
            if not line.startswith("allocation\t")
            and not (line.startswith("attempt-2-timing-")
                     and int(line.split("\t")[0].rsplit("-", 1)[1]) > 11)
        ) + "\n")
        self.assertEqual(VERIFY.verify(self.root)["classification"],
                         "capacity_censored")

        self.tearDown()
        self.setUp()
        for ordinal in range(11, 49):
            (self.root / "attempt-1" / "timing" / f"{ordinal:02d}.json").unlink()
        censor = {
            "schema": 2, "mode": "timing", "outcome": "capacity_censored",
            "censor_phase": "service_query", "ordinal": 11, "routes": 10_000,
            "case": "U", "repetition": 6, "timeout_seconds": 120,
            "source_commit": "a" * 40,
            "attempt": 1,
            "binary_sha256": hashlib.sha256(b"vpn_query_timing").hexdigest(),
        }
        self.write("censor.json", censor)
        self.mutate("manifest.json", lambda d: d.update(attempts=2))
        (self.root / "allocation.json").unlink()
        lines = (self.root / "host-preflight.tsv").read_text().splitlines()
        def retained_phase(line):
            phase = line.split("\t")[0]
            return phase == "build" or (
                phase.startswith("attempt-1-timing-")
                and int(phase.rsplit("-", 1)[1]) <= 11
            )
        kept = [lines[0]] + [
            line for line in lines[1:] if retained_phase(line)
        ]
        (self.root / "host-preflight.tsv").write_text("\n".join(kept) + "\n")
        self.assertEqual(VERIFY.verify(self.root)["classification"],
                         "capacity_censored")
        (self.root / "attempt-2").mkdir()
        with self.assertRaises(VERIFY.Invalid):
            VERIFY.verify(self.root)
        (self.root / "attempt-2").rmdir()
        for field, value in (("schema", 1), ("censor_phase", ""),
                             ("censor_phase", "unknown"),
                             ("censor_phase", "forced_fixture")):
            original = censor[field]
            self.mutate("censor.json", lambda d, f=field, v=value: d.update({f: v}))
            with self.assertRaises(VERIFY.Invalid):
                VERIFY.verify(self.root)
            self.mutate("censor.json",
                        lambda d, f=field, v=original: d.update({f: v}))

    def test_provenance_and_preflight_corruption(self):
        self.mutate("manifest.json", lambda d: d.update(source_tree="bad"))
        with self.assertRaises(VERIFY.Invalid):
            VERIFY.verify(self.root)
        self.mutate("manifest.json", lambda d: d.update(source_tree="c" * 40))
        log = self.root / "host-preflight.tsv"
        log.write_text(log.read_text().replace("allocation\t1\t", "unexpected\t1\t"))
        with self.assertRaises(VERIFY.Invalid):
            VERIFY.verify(self.root)
        log.write_text(log.read_text().replace(
            "unexpected\t1\tnow\t0\t2\tperformance\tperformance\t0\tnone\tpass",
            "allocation\t1\tnow\t0\t2\tpowersave\tperformance\t1\tvpn_query_timi\tpass"))
        with self.assertRaises(VERIFY.Invalid):
            VERIFY.verify(self.root)

    def test_attempt_inventory_rejects_undeclared_and_malformed(self):
        (self.root / "attempt-2").mkdir()
        with self.assertRaises(VERIFY.Invalid):
            VERIFY.verify(self.root)
        (self.root / "attempt-2").rename(self.root / "attempt-extra")
        with self.assertRaises(VERIFY.Invalid):
            VERIFY.verify(self.root)

    def test_all_cell_same_checksum_corruption(self):
        for path in (self.root / "attempt-1" / "timing").glob("*.json"):
            value = json.loads(path.read_text())
            value["query"]["checksum"] = 7
            path.write_text(json.dumps(value))
        with self.assertRaises(VERIFY.Invalid):
            VERIFY.verify(self.root)


if __name__ == "__main__":
    unittest.main()
