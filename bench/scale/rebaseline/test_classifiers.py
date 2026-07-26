#!/usr/bin/env python3
"""Fixture tests for the committed RIB rebaseline classifiers."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
sys.path.insert(0, str(HERE))

import classify_dhat  # noqa: E402


class ClassifierFixtures(unittest.TestCase):
    def run_check(self, script: str, source: str, expected: str) -> None:
        subprocess.run(
            [
                sys.executable,
                str(HERE / script),
                str(FIXTURES / source),
                "--check",
                str(FIXTURES / expected),
            ],
            check=True,
        )

    def test_cpu_fixture(self) -> None:
        self.run_check("classify_cpu.py", "cpu.folded", "cpu.expected.tsv")

    def test_bgperf_csv_fixture(self) -> None:
        self.run_check(
            "sanitize_bgperf_csv.py", "bgperf.raw.csv", "bgperf.expected.csv"
        )
        subprocess.run(
            [
                sys.executable,
                str(HERE / "sanitize_bgperf_csv.py"),
                "--from-sanitized",
                str(FIXTURES / "bgperf.expected.csv"),
                "--check",
                str(FIXTURES / "bgperf.expected.csv"),
            ],
            check=True,
        )

    def test_bgperf_csv_rejects_paths_extra_fields_and_oversize(self) -> None:
        raw = (FIXTURES / "bgperf.raw.csv").read_text(encoding="utf-8")
        bad_inputs = (
            ("path", raw.replace("rustbgpd 0.51.0", "/home/operator/rustbgpd")),
            ("extra field", raw.rstrip("\n") + ",extra\n"),
            ("oversize", raw + ("x" * (16 * 1024))),
            ("header drift", raw.replace("max cpu %", "cpu max", 1)),
            ("missing field", raw.replace(",0,0,,,\n", ",0,0,,\n")),
            ("required mismatch", raw.replace(",200000,200000,40,", ",10000,10000,40,")),
            ("received mismatch", raw.replace(",200000,200000,40,", ",200000,199999,40,")),
            ("tester error", raw.replace(",0,0,,,\n", ",1,0,,,\n")),
            ("tester timeout", raw.replace(",0,0,,,\n", ",0,1,,,\n")),
            ("failed", raw.replace(",0,0,,,\n", ",0,0,FAILED,,\n")),
            ("message", raw.replace(",0,0,,,\n", ",0,0,,boom,\n")),
            ("filter", raw.replace(",0,0,,,\n", ",0,0,,,policy\n")),
            ("flags", raw.replace(",124.000,,2026", ",124.000,-s,2026")),
            ("negative metric", raw.replace(",50.25,98,", ",-1,98,")),
            ("nan metric", raw.replace(",50.25,98,", ",NaN,98,")),
            ("hostile exponent", raw.replace(",50.25,98,", ",1e999999999,98,")),
            ("long hex id", raw.replace("rustbgpd 0.51.0", "deadbeefdeadbeef")),
            ("zero loaded metrics", raw.replace(",45,5,40,50.25,98,0.321,", ",0,5,40,0,0,0,")),
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, (case, text) in enumerate(bad_inputs):
                with self.subTest(case=case):
                    path = Path(directory) / f"bad-bgperf-{index}.csv"
                    path.write_text(text, encoding="utf-8")
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(HERE / "sanitize_bgperf_csv.py"),
                            str(path),
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)

    def test_dhat_fixture_and_sanitized_derivative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            derivative = Path(directory) / "dhat.derivative.tsv"
            subprocess.run(
                [
                    sys.executable,
                    str(HERE / "classify_dhat.py"),
                    str(FIXTURES / "dhat.json"),
                    "--check",
                    str(FIXTURES / "dhat.expected.tsv"),
                    "--derivative",
                    str(derivative),
                ],
                check=True,
            )
            text = derivative.read_text(encoding="utf-8")
            self.assertNotIn("0x", text)
            self.assertNotIn("crates/", text)
            self.assertIn("GroupRibOut::apply_delta", text)
            self.assertIn("[u8%3B 32]", text)
            self.assertIn("percent%25allocate", text)
            aggregated = [
                line
                for line in text.splitlines()
                if line.startswith("Group RIB-Out table\t101\t")
            ]
            self.assertEqual(len(aggregated), 1)
            self.assertIn("GroupRibOut::apply_delta", aggregated[0])

            subprocess.run(
                [
                    sys.executable,
                    str(HERE / "classify_dhat.py"),
                    "--from-derivative",
                    str(derivative),
                    "--check",
                    str(FIXTURES / "dhat.expected.tsv"),
                ],
                check=True,
            )

    def test_dhat_sanitization_fails_closed(self) -> None:
        fixture = json.loads((FIXTURES / "dhat.json").read_text(encoding="utf-8"))
        bad_frames = (
            "/home/operator/rustbgpd.rs:1:1",
            "rustbgpd_rib::manager::RibManager::new",
            "0x1: rustbgpd_rib::0xfeed::allocate (crates/rib/src/lib.rs:1:1)",
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, bad_frame in enumerate(bad_frames):
                with self.subTest(frame=bad_frame):
                    document = dict(fixture)
                    document["ftbl"] = list(fixture["ftbl"])
                    document["ftbl"][1] = bad_frame
                    path = Path(directory) / f"bad-{index}.json"
                    path.write_text(json.dumps(document), encoding="utf-8")
                    result = subprocess.run(
                        [sys.executable, str(HERE / "classify_dhat.py"), str(path)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertRegex(result.stderr, "refusing unsanitized|path or address")

    def test_dhat_current_demangled_adj_rib_in_owner(self) -> None:
        self.assertEqual(
            classify_dhat.classify_stack(
                ["<rustbgpd_rib::adj_rib_in::AdjRibIn>::insert"]
            ),
            "Adj-RIB-In route storage",
        )

    def test_dhat_current_demangled_loc_rib_owner(self) -> None:
        self.assertEqual(
            classify_dhat.classify_stack(
                [
                    "<rustbgpd_rib::loc_rib::LocRib>::recompute::"
                    "<core::slice::iter::Iter<&rustbgpd_rib::route::Route>>"
                ]
            ),
            "Loc-RIB best-path map",
        )

    def test_dhat_current_demangled_group_and_per_peer_owners(self) -> None:
        group_owner = "<rustbgpd_rib::update_group::GroupRibOut>::apply_delta"
        self.assertEqual(
            classify_dhat.classify_stack([group_owner]),
            "Group RIB-Out table",
        )
        self.assertEqual(
            classify_dhat.classify_stack(
                [
                    "<prefix_trie::map::PrefixMap<ipnet::ipnet::Ipv4Net, u32>>::insert",
                    group_owner,
                ]
            ),
            "Prefix-trie index - group table",
        )
        self.assertEqual(
            classify_dhat.classify_stack(
                ["<rustbgpd_rib::adj_rib_out::AdjRibOut>::apply_delta"]
            ),
            "Per-peer Adj-RIB-Out",
        )

    def test_dhat_current_demangled_slab_and_daemon_owners(self) -> None:
        self.assertEqual(
            classify_dhat.classify_stack(
                [
                    "<rustbgpd_rib::slab::RouteSlab<rustbgpd_rib::route::Route>>::insert",
                    "<rustbgpd_rib::adj_rib_in::AdjRibIn>::insert",
                ]
            ),
            "Adj-RIB-In route storage",
        )
        for owner in (
            "<rustbgpd_rib::manager::RibManager>::new",
            "<rustbgpd_transport::session::PeerSession>::new",
        ):
            with self.subTest(owner=owner):
                self.assertEqual(
                    classify_dhat.classify_stack([owner]),
                    "Daemon core",
                )

    def test_dhat_cache_requires_import_decision_cache_owner(self) -> None:
        self.assertEqual(
            classify_dhat.classify_stack(
                [
                    "<rustbgpd_transport::session::import_decision_cache::"
                    "ImportDecisionCache>::insert"
                ]
            ),
            "Transport import-decision cache",
        )
        self.assertNotEqual(
            classify_dhat.classify_stack(
                [
                    "<alloc::boxed::Box<lru::LruEntry<"
                    "rustbgpd_transport::session::import_decision_cache::"
                    "ImportDecisionKey, "
                    "rustbgpd_transport::session::rejected_routes::"
                    "RejectedRouteEntry>>>::new"
                ]
            ),
            "Transport import-decision cache",
        )

    def test_dhat_unsymbolized_live_stack_explains_profiling_build(self) -> None:
        document = {
            "dhatFileVersion": 2,
            "ftbl": ["", "", ""],
            "pps": [{"gb": 1, "fs": [1]}],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsymbolized.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(HERE / "classify_dhat.py"), str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no symbolized stack", result.stderr)
        self.assertIn("--profile release-prof", result.stderr)
        self.assertIn("stripped release profile", result.stderr)

    def test_explain_cache_peak_uses_daemon_vmhwm_not_sampled_tree_max(self) -> None:
        runner = HERE.parents[2] / "docs" / "perf" / "run-explain-cache-variant.sh"
        marker = (
            "# Summary: steady = median of post-convergence samples; "
            "peak = daemon kernel VmHWM.\n"
        )
        script = runner.read_text(encoding="utf-8")
        summary = script.split(marker, 1)[1].split("\nPY\n", 1)[0]
        self.assertTrue(summary.startswith("python3 - \"$OUT\" <<'PY'\n"))
        python = summary.split("\n", 1)[1]

        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / "provenance.env").write_text(
                "converged_monotonic=11.0\n", encoding="utf-8"
            )
            (out / "rss.tsv").write_text(
                "monotonic_seconds\tutc\ttree_rss_kib\n"
                "10.0\t2026-07-25T00:00:00Z\t1024\n"
                "11.0\t2026-07-25T00:00:01Z\t2048\n",
                encoding="utf-8",
            )
            (out / "proc-status-final.txt").write_text(
                "VmRSS:\t2048 kB\nVmHWM:\t4096 kB\n", encoding="utf-8"
            )
            subprocess.run(
                [sys.executable, "-c", python, str(out)],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            )
            values = dict(
                line.split("=", 1)
                for line in (out / "summary.env").read_text().splitlines()
            )

        self.assertEqual(values["peak_rss_kib_daemon_vmhwm"], "4096")
        self.assertEqual(values["peak_rss_mib_daemon_vmhwm"], "4.0")
        self.assertEqual(
            values["sampled_tree_peak_rss_kib_lower_bound"],
            "2048",
        )

    def test_dhat_derivative_bounds_fail_without_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "derivative.tsv"
            for flag, limit in (
                ("--max-derivative-rows", "1"),
                ("--max-derivative-bytes", "100"),
            ):
                with self.subTest(flag=flag):
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(HERE / "classify_dhat.py"),
                            str(FIXTURES / "dhat.json"),
                            "--derivative",
                            str(output),
                            flag,
                            limit,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
