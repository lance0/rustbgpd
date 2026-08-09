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

# The summary block is the one embedded Python the runner invokes outside any
# shell function, so its own invocation line is the anchor.
SUMMARY_HEREDOC = "python3 - \"$OUT\" <<'PY'"


def runner_script() -> tuple[Path, str]:
    runner = HERE.parents[2] / "docs" / "perf" / "run-explain-cache-variant.sh"
    return runner, runner.read_text(encoding="utf-8")


def require_anchor(script: str, marker: str, runner: Path) -> None:
    """Fail with the fix, not a bare ``substring not found``.

    These tests locate embedded Python by the shell code around it. Anchor on
    a function definition or the ``python3`` invocation line -- never on
    comment prose, which gets reworded and silently stops matching.
    """
    if marker in script:
        return
    raise AssertionError(
        f"anchor {marker!r} no longer appears in {runner}. This test extracts "
        "embedded Python by the shell code around it; update the anchor to "
        "match the renamed shell code. Do not re-anchor on comment prose -- "
        "prose gets reworded and takes the test red with it."
    )


class ClassifierFixtures(unittest.TestCase):
    def runner_embedded_python(self, marker: str) -> str:
        """Extract the ``<<'PY'`` heredoc that follows ``marker`` in the runner."""
        runner, script = runner_script()
        require_anchor(script, marker, runner)
        start = script.index(marker)
        body_start = script.index("<<'PY'\n", start) + len("<<'PY'\n")
        body_end = script.index("\nPY\n", body_start)
        return script[body_start:body_end]

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
            (
                "required mismatch",
                raw.replace(",200000,200000,40,", ",10000,10000,40,"),
            ),
            (
                "received mismatch",
                raw.replace(",200000,200000,40,", ",200000,199999,40,"),
            ),
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
            (
                "zero loaded metrics",
                raw.replace(",45,5,40,50.25,98,0.321,", ",0,5,40,0,0,0,"),
            ),
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
                    self.assertRegex(
                        result.stderr, "refusing unsanitized|path or address"
                    )

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
        python = self.runner_embedded_python(SUMMARY_HEREDOC)

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
            (out / "settled-proc.env").write_text(
                "settled_proc_vmrss_kib=2048\n"
                "settled_proc_vmhwm_kib=4096\n"
                "settled_proc_vmpeak_kib=8192\n"
                "settled_proc_vmsize_kib=6144\n",
                encoding="utf-8",
            )
            (out / "settled-metrics.env").write_text(
                "jemalloc_allocated_bytes=1000\n"
                "jemalloc_active_bytes=2000\n"
                "jemalloc_resident_bytes=3000\n"
                "jemalloc_mapped_bytes=4000\n",
                encoding="utf-8",
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
        self.assertEqual(values["settled_proc_vmrss_kib"], "2048")
        self.assertEqual(values["settled_proc_vmhwm_kib"], "4096")
        self.assertEqual(values["settled_proc_vmpeak_kib"], "8192")
        self.assertEqual(values["settled_proc_vmsize_kib"], "6144")
        self.assertEqual(values["jemalloc_allocated_bytes"], "1000")
        self.assertEqual(values["jemalloc_active_bytes"], "2000")
        self.assertEqual(values["jemalloc_resident_bytes"], "3000")
        self.assertEqual(values["jemalloc_mapped_bytes"], "4000")

    @staticmethod
    def settled_metrics_fixture() -> str:
        return (
            "bgp_update_groups 1\n"
            'bgp_update_group_members{group="7"} 2\n'
            "bgp_update_group_fallback_peers 0\n"
            "bgp_update_group_residue_entries 0\n"
            "bgp_rib_outbound_registered_peers 2\n"
            'bgp_rejected_routes_retained{peer="127.1.0.1"} 0\n'
            'bgp_rejected_routes_retained{peer="127.1.0.2"} 0\n'
            'bgp_peer_outbound_queue_depth{peer="127.1.0.1"} 0\n'
            'bgp_peer_outbound_queue_depth{peer="127.1.0.2"} 0\n'
            "jemalloc_allocated_bytes 1000\n"
            "jemalloc_active_bytes 2000\n"
            "jemalloc_resident_bytes 3000\n"
            "jemalloc_mapped_bytes 4000\n"
        )

    def run_settled_metrics_validator(
        self, fixture: str, *, dhat: int = 0
    ) -> subprocess.CompletedProcess[str]:
        python = self.runner_embedded_python("validate_settled_metrics()")
        with tempfile.TemporaryDirectory() as directory:
            metrics = Path(directory) / "metrics.prom"
            metrics.write_text(fixture, encoding="utf-8")
            return subprocess.run(
                [sys.executable, "-c", python, str(metrics), "2", str(dhat)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

    def test_settled_metrics_validator_rejects_every_false_green(self) -> None:
        fixture = self.settled_metrics_fixture()
        valid = self.run_settled_metrics_validator(fixture)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertIn("jemalloc_allocated_bytes=1000", valid.stdout)

        mutations = {
            "missing group count": fixture.replace("bgp_update_groups 1\n", ""),
            "wrong group members": fixture.replace(
                'bgp_update_group_members{group="7"} 2',
                'bgp_update_group_members{group="7"} 1',
            ),
            "fallback peer": fixture.replace(
                "bgp_update_group_fallback_peers 0",
                "bgp_update_group_fallback_peers 1",
            ),
            "withdrawal residue": fixture.replace(
                "bgp_update_group_residue_entries 0",
                "bgp_update_group_residue_entries 1",
            ),
            "missing registration": fixture.replace(
                "bgp_rib_outbound_registered_peers 2",
                "bgp_rib_outbound_registered_peers 1",
            ),
            "missing rejected-route peer": fixture.replace(
                'bgp_rejected_routes_retained{peer="127.1.0.2"} 0\n', ""
            ),
            "retained rejection": fixture.replace(
                'bgp_rejected_routes_retained{peer="127.1.0.2"} 0',
                'bgp_rejected_routes_retained{peer="127.1.0.2"} 1',
            ),
            "missing writer-depth peer": fixture.replace(
                'bgp_peer_outbound_queue_depth{peer="127.1.0.2"} 0\n', ""
            ),
            "writer backlog": fixture.replace(
                'bgp_peer_outbound_queue_depth{peer="127.1.0.2"} 0',
                'bgp_peer_outbound_queue_depth{peer="127.1.0.2"} 1',
            ),
            "missing jemalloc": fixture.replace("jemalloc_allocated_bytes 1000\n", ""),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                result = self.run_settled_metrics_validator(mutation)
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_settled_metrics_validator_does_not_mislabel_dhat_as_jemalloc(
        self,
    ) -> None:
        fixture = "\n".join(
            line
            for line in self.settled_metrics_fixture().splitlines()
            if not line.startswith("jemalloc_")
        )
        result = self.run_settled_metrics_validator(fixture, dhat=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_settled_proc_validator_requires_every_numeric_kib_field(self) -> None:
        python = self.runner_embedded_python("validate_settled_proc_status()")
        valid = (
            "VmRSS:\t2048 kB\n"
            "VmHWM:\t4096 kB\n"
            "VmPeak:\t8192 kB\n"
            "VmSize:\t6144 kB\n"
        )
        mutations = {
            "valid": (valid, 0),
            "missing VmRSS": (valid.replace("VmRSS:\t2048 kB\n", ""), 1),
            "missing VmHWM": (valid.replace("VmHWM:\t4096 kB\n", ""), 1),
            "missing VmPeak": (valid.replace("VmPeak:\t8192 kB\n", ""), 1),
            "missing VmSize": (valid.replace("VmSize:\t6144 kB\n", ""), 1),
            "wrong unit": (valid.replace("VmRSS:\t2048 kB", "VmRSS:\t2048 MB"), 1),
        }
        for label, (fixture, expected_rc) in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                status = Path(directory) / "status"
                status.write_text(fixture, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, "-c", python, str(status)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(result.returncode, expected_rc, result.stderr)

    def test_zero_reload_evidence_is_captured_before_stub_release(self) -> None:
        runner = HERE.parents[2] / "docs" / "perf" / "run-explain-cache-variant.sh"
        script = runner.read_text(encoding="utf-8")
        order = [
            'until [[ -e "$EVIDENCE_DIR/ready" ]]',
            'mv "$candidate" "$OUT/metrics-after.prom"',
            'validate_settled_proc_status "$OUT/proc-status-after.txt"',
            'touch "$EVIDENCE_DIR/ack"',
            'if wait "$H_PID"',
        ]
        positions = [script.index(marker) for marker in order]
        self.assertEqual(positions, sorted(positions))

        harness = (HERE.parent / "reloadstall" / "src" / "main.rs").read_text(
            encoding="utf-8"
        )
        handshake = harness.rindex(
            "await_evidence_capture(evidence_dir, EVIDENCE_TIMEOUT)"
        )
        done = harness.rindex('println!("done rss_mib={}", rss_mib(pid));')
        self.assertLess(handshake, done)

    def test_dhat_receipt_requires_allocator_artifact_before_success(self) -> None:
        runner = HERE.parents[2] / "docs" / "perf" / "run-explain-cache-variant.sh"
        script = runner.read_text(encoding="utf-8")
        gate_start = script.index("if ((DHAT != 0)); then")
        gate_end = script.index("\nfi\n", gate_start) + len("\nfi\n")
        gate = script[gate_start:gate_end]
        required = gate_start + gate.index(
            '[[ -f "$OUT/dhat-heap.json" && -s "$OUT/dhat-heap.json" ]] || {'
        )
        require_anchor(script, SUMMARY_HEREDOC, runner)
        summary = script.index(SUMMARY_HEREDOC)
        success = script.index("printf 'status=success\\n'")
        self.assertLess(required, summary)
        self.assertLess(required, success)

        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            artifact = out / "dhat-heap.json"
            cases = (
                ("disabled and absent", "0", 0),
                ("enabled and absent", "1", 1),
                ("enabled and empty", "1", 1),
                ("enabled and directory", "1", 1),
                ("enabled and nonempty regular", "1", 0),
            )
            for label, dhat, expected_rc in cases:
                with self.subTest(label=label):
                    if artifact.is_dir():
                        artifact.rmdir()
                    else:
                        artifact.unlink(missing_ok=True)
                    if label.endswith("empty"):
                        artifact.touch()
                    elif label.endswith("directory"):
                        artifact.mkdir()
                    elif label.endswith("nonempty regular"):
                        artifact.write_text("{}\n", encoding="utf-8")
                    result = subprocess.run(
                        [
                            "bash",
                            "-c",
                            f"set -euo pipefail\nOUT=$1\nDHAT=$2\n{gate}",
                            "_",
                            str(out),
                            dhat,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertEqual(result.returncode, expected_rc, result.stderr)

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
