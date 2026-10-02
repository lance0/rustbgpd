#!/usr/bin/env python3
"""Fixture tests for the committed RIB rebaseline classifiers."""

from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
sys.path.insert(0, str(HERE))

import classify_dhat  # noqa: E402
import sanitize_bgperf_csv  # noqa: E402

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
        self.run_check(
            "sanitize_bgperf_csv.py",
            "bgperf.provenance.raw.csv",
            "bgperf.provenance.expected.csv",
        )
        self.run_check(
            "sanitize_bgperf_csv.py",
            "bgperf.fork.raw.csv",
            "bgperf.fork.expected.csv",
        )
        for sanitized in ("bgperf.expected.csv", "bgperf.fork.expected.csv"):
            subprocess.run(
                [
                    sys.executable,
                    str(HERE / "sanitize_bgperf_csv.py"),
                    "--from-sanitized",
                    str(FIXTURES / sanitized),
                    "--check",
                    str(FIXTURES / sanitized),
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

    def test_bgperf_provenance_schema_rejects_unbounded_identity(self) -> None:
        raw = (FIXTURES / "bgperf.provenance.raw.csv").read_text(encoding="utf-8")
        bad_inputs = (
            raw.replace("bgperf/rustbgpd:receipt", "../rustbgpd"),
            raw.replace("2.19.0+branch.master.639423360c80", "/tmp/tester"),
            raw.replace("4.8.0", "deadbeefdeadbeef"),
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, text in enumerate(bad_inputs):
                path = Path(directory) / f"bad-provenance-{index}.csv"
                path.write_text(text, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, str(HERE / "sanitize_bgperf_csv.py"), str(path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)

    def test_bgperf_fork_schema_rejects_drift_and_incomplete_runs(self) -> None:
        raw = (FIXTURES / "bgperf.fork.raw.csv").read_text(encoding="utf-8")
        tail = ",0,0,,,,152,bgperf/rustbgpd:sync-dhat,"
        bad_inputs = (
            # A 28-value row under the 29-field header: the contention column
            # is missing, so every later field would shift by one.
            ("missing contention value", raw.replace(",,,,152,", ",,,,")),
            ("contention column dropped", raw.replace(" max foreign cpu %,", "", 1)),
            ("contention not a count", raw.replace(",,,,152,", ",,,,/tmp,")),
            ("short of full table", raw.replace(",198000,200000,", ",198000,199999,")),
            ("wrong check-point", raw.replace(",198000,200000,", ",200000,200000,")),
            ("tester error", raw.replace(tail, tail.replace(",0,0,", ",1,0,", 1))),
            ("failed", raw.replace(tail, tail.replace(",,,,", ",FAILED,,,", 1))),
            ("foreign image", raw.replace("bgperf/rustbgpd:sync-dhat", "../rustbgpd")),
            ("empty image", raw.replace("bgperf/rustbgpd:sync-dhat", "")),
            ("other daemon image", raw.replace("bgperf/rustbgpd:sync-dhat", "bgperf/bird:latest")),
            ("digest image", raw.replace("bgperf/rustbgpd:sync-dhat", "bgperf/rustbgpd@sha256:0bfe26ff")),
            # The fork's release build lands in the default tag.
            ("default release tag", raw.replace("bgperf/rustbgpd:sync-dhat", "bgperf/rustbgpd")),
            ("latest release tag", raw.replace("bgperf/rustbgpd:sync-dhat", "bgperf/rustbgpd:latest")),
            (
                "container-like tag",
                raw.replace("bgperf/rustbgpd:sync-dhat", "bgperf/rustbgpd:0bfe26ffb2fa0cf08f1e"),
            ),
            ("path version", raw.replace("3.37.0\n", "/tmp/gobgp\n")),
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, (case, text) in enumerate(bad_inputs):
                with self.subTest(case=case):
                    self.assertNotEqual(text, raw)
                    path = Path(directory) / f"bad-fork-{index}.csv"
                    path.write_text(text, encoding="utf-8")
                    result = subprocess.run(
                        [sys.executable, str(HERE / "sanitize_bgperf_csv.py"), str(path)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0)

        sanitized = (FIXTURES / "bgperf.fork.expected.csv").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "short.csv"
            path.write_text(
                sanitized.replace(",198000,200000,", ",198000,199999,"), encoding="utf-8"
            )
            result = subprocess.run(
                [sys.executable, str(HERE / "sanitize_bgperf_csv.py"), "--from-sanitized", str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_bgperf_poll_mode_survives_sanitization(self) -> None:
        raw = (FIXTURES / "bgperf.fork.raw.csv").read_text(encoding="utf-8")
        rows = list(csv.reader(io.StringIO(raw), skipinitialspace=True))
        rows[0].insert(-3, "neighbor poll mode")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "poll.csv"
            sanitized = Path(directory) / "sanitized.csv"
            outputs = []
            for mode in ("poll1", "poll5", "off"):
                with self.subTest(mode=mode):
                    values = rows[1][:-3] + [mode] + rows[1][-3:]
                    with path.open("w", newline="") as output:
                        csv.writer(output).writerows([rows[0], values])
                    reduced = sanitize_bgperf_csv.load(path)
                    outputs.append(reduced)
                    named = list(csv.DictReader(io.StringIO(reduced)))[0]
                    self.assertEqual(named["neighbor_poll_mode"], mode)
                    self.assertEqual(named["received"], "200000")
                    sanitized.write_text(reduced, encoding="utf-8")
                    self.assertEqual(sanitize_bgperf_csv.load_sanitized(sanitized), reduced)
            self.assertEqual(len(set(outputs)), 3)
            with self.assertRaisesRegex(ValueError, "differs"):
                sanitize_bgperf_csv.check(sanitized, outputs[0])

    def test_bgperf_poll_mode_rejects_invalid_modes_and_schema_drift(self) -> None:
        raw = (FIXTURES / "bgperf.fork.raw.csv").read_text(encoding="utf-8")
        rows = list(csv.reader(io.StringIO(raw), skipinitialspace=True))
        rows[0].insert(-3, "neighbor poll mode")
        rows[1].insert(-3, "off")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            for mode in ("", "poll2", "OFF", "off/unknown", "off\t", " off", "off "):
                with self.subTest(mode=mode):
                    rows[1][-4] = mode
                    with path.open("w", newline="") as output:
                        csv.writer(output).writerows(rows)
                    with self.assertRaises(ValueError):
                        sanitize_bgperf_csv.load(path)
                    sanitized = (FIXTURES / "bgperf.fork.expected.csv").read_text()
                    records = list(csv.reader(io.StringIO(sanitized)))
                    records[0].append("neighbor_poll_mode")
                    records[1].append(mode)
                    with path.open("w", newline="") as output:
                        csv.writer(output, lineterminator="\n").writerows(records)
                    with self.assertRaises(ValueError):
                        sanitize_bgperf_csv.load_sanitized(path)

            rows[1][-4] = "poll1"
            mutations = [
                (rows[0][:-1], rows[1]),
                (rows[0], rows[1][:-1]),
                (rows[0] + ["extra"], rows[1] + ["extra"]),
                (rows[0], rows[1][:5] + ["200000"] + rows[1][6:]),
                (rows[0], rows[1][:6] + ["199999"] + rows[1][7:]),
                (rows[0], rows[1][:-3] + ["bgperf/rustbgpd:latest"] + rows[1][-2:]),
            ]
            for header, values in mutations:
                with self.subTest(header=header, values=values):
                    with path.open("w", newline="") as output:
                        csv.writer(output).writerows([header, values])
                    with self.assertRaises(ValueError):
                        sanitize_bgperf_csv.load(path)

    def test_sanitized_poll_mode_requires_the_fork_checkpoint(self) -> None:
        sanitized = (FIXTURES / "bgperf.fork.expected.csv").read_text()
        rows = list(csv.reader(io.StringIO(sanitized)))
        rows[0].append("neighbor_poll_mode")
        rows[1].append("poll1")
        rows[1][rows[0].index("required")] = "200000"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrong-checkpoint.csv"
            with path.open("w", newline="") as output:
                csv.writer(output, lineterminator="\n").writerows(rows)
            with self.assertRaisesRegex(ValueError, "requires the 99% check-point"):
                sanitize_bgperf_csv.load_sanitized(path)

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

    def test_dhat_separates_attribute_backing_from_nested_payloads(self) -> None:
        stored_path = "<rustbgpd_transport::session::inbound::RouteAttrBundle>::new"
        self.assertEqual(
            classify_dhat.classify_stack(
                [
                    "<alloc::vec::Vec<rustbgpd_wire::attribute::PathAttribute>>::with_capacity",
                    stored_path,
                    "<rustbgpd_rib::adj_rib_in::AdjRibIn>::insert",
                ]
            ),
            "Interned attribute-set backing",
        )
        self.assertEqual(
            classify_dhat.classify_stack(
                [
                    "<rustbgpd_wire::attribute::AsPath as core::clone::Clone>::clone",
                    "<rustbgpd_wire::attribute::PathAttribute as core::clone::Clone>::clone",
                    stored_path,
                    "<rustbgpd_rib::adj_rib_in::AdjRibIn>::insert",
                ]
            ),
            "Nested path-attribute payloads",
        )

    def test_dhat_does_not_relabel_unowned_attribute_allocations(self) -> None:
        self.assertEqual(
            classify_dhat.classify_stack(
                [
                    "<alloc::vec::Vec<rustbgpd_wire::attribute::PathAttribute>>::with_capacity",
                    "<rustbgpd_api::neighbor_service::NeighborService>::list_neighbors",
                ]
            ),
            "API / peer-manager",
        )

    def test_dhat_generic_bundle_vector_and_other_allocations(self) -> None:
        # Symbol-only prefix captured from the real-table DHAT profile. The
        # raw source location identifies RouteAttrBundle::new's base.to_vec().
        outer = [
            "<alloc::alloc::Global as core::alloc::Allocator>::allocate",
            "alloc::raw_vec::RawVecInner<A>::try_allocate_in",
            "alloc::raw_vec::RawVecInner<A>::with_capacity_in",
            "alloc::raw_vec::RawVec<T,A>::with_capacity_in",
            "alloc::vec::Vec<T,A>::with_capacity_in",
            "<T as alloc::slice::<impl [T]>::to_vec_in::ConvertVec>::to_vec",
            "alloc::slice::<impl [T]>::to_vec_in",
            "alloc::slice::<impl [T]>::to_vec",
        ]
        bundle = "rustbgpd_transport::session::inbound::RouteAttrBundle::new"
        transport = [
            "rustbgpd_transport::session::PeerSession::process_update",
            "rustbgpd_transport::session::PeerSession::process_read_buffer",
        ]
        self.assertEqual(
            classify_dhat.classify_stack(outer + [bundle] + transport),
            "Interned attribute-set backing",
        )
        for payload in ("PathAttribute", "AsPath", "AsPathSegment"):
            with self.subTest(payload=payload):
                self.assertEqual(
                    classify_dhat.classify_stack(outer + [
                        f"<rustbgpd_wire::attribute::{payload} as core::clone::Clone>::clone",
                        bundle,
                    ] + transport),
                    "Nested path-attribute payloads",
                )
        for temporary in (
            ["alloc::sync::Arc<T>::new", "rustbgpd_rib::attr_set::AttrSet::new", bundle],
            outer + ["rustbgpd_wire::attribute::decode_path_attributes_revised_observed"],
            outer,
            ["alloc::slice::<impl [T]>::to_vec", bundle],
            ["alloc::raw_vec::RawVec<T,A>::with_capacity_in", bundle],
        ):
            with self.subTest(temporary=temporary):
                self.assertEqual(
                    classify_dhat.classify_stack(temporary + transport),
                    "Transport session buffers/scratch",
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
            "    capture_explain_evidence\n",
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

    def test_explain_variant_input_boundaries(self) -> None:
        python = self.runner_embedded_python("validate_variant_inputs() {")
        valid = ["2", "2000000", "true", "4096", "0", "10"]
        cases = [("valid", valid, 0), ("minimum", valid[:3] + ["1", "0", "10"], 0),
                 ("maximum", valid[:3] + ["2097152", "0", "10"], 0),
                 ("normal defaults", ["8", "400000", "omit", "4096", "4", "30"], 0)]
        for index, value in ((0, "1"), (2, "yes"), (3, "0"), (3, "2097153"),
                             (3, ""), (3, "-1"), (3, "01"), (4, "1"), (5, "0")):
            changed = valid.copy()
            changed[index] = value
            cases.append((f"invalid {index}={value}", changed, 1))
        cases.append(("omit override", ["8", "400000", "omit", "262144", "0", "10"], 1))
        cases.append(("uneven held slice", ["3", "8", "true", "4", "0", "10"], 1))
        cases.append(("uneven reload slice", ["8", "1001", "true", "4", "4", "30"], 1))
        for label, args, expected_rc in cases:
            with self.subTest(label=label):
                result = subprocess.run(
                    [sys.executable, "-c", python, *args], capture_output=True, text=True,
                    env={**os.environ, "GEN_DUALSTACK": "0", "RELOADSTALL_DUALSTACK": "0"},
                )
                self.assertEqual(result.returncode, expected_rc, result.stderr)
        for mode, args in (("held", valid),
                           ("reload", ["8", "400000", "true", "4096", "4", "30"])):
            for generator, harness in (("1", "0"), ("0", "1"), ("1", "1")):
                with self.subTest(mode=mode, generator=generator, harness=harness):
                    result = subprocess.run(
                        [sys.executable, "-c", python, *args], capture_output=True, text=True,
                        env={**os.environ, "GEN_DUALSTACK": generator,
                             "RELOADSTALL_DUALSTACK": harness},
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("unsupported by the IPv4 explain qualification", result.stderr)

    def test_explain_variant_matches_the_emitted_convergence_marker(self) -> None:
        _, script = runner_script()
        assignment = next(line for line in script.splitlines()
                          if line.startswith("EXPECTED_PER_OBSERVER="))
        match = next(line for line in script.splitlines() if line.startswith("until grep -q "))
        match = match.removeprefix("until ").removesuffix("; do")
        # The harness emits total - floor(total/peers), even though its actual
        # member_slice completion targets use quotient/remainder allocation.
        for marker, expected_rc in ((6, 0), (5, 1)):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                (Path(directory) / "reloadstall.log").write_text(
                    f"converged (>= {marker}/observer) at 0.2s rss_mib=12\n", encoding="utf-8")
                result = subprocess.run(
                    ["bash", "-c", "set -euo pipefail\n" + assignment + "\n" + match],
                    env={**os.environ, "PEERS": "3", "TOTAL": "8", "OUT": directory},
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, expected_rc, result.stderr)

    def test_explain_variant_build_uses_actual_scale_workspace(self) -> None:
        _, script = runner_script()
        start = script.index("BUILD_FEATURES=()")
        block = script[start:script.index("\nsha256sum", start)]
        for layout in ("root", "standalone", "metadata-failure", "unexpected"):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                repo = base / "source tree"
                repo.mkdir()
                out = base / "receipt"
                (out / "build").mkdir(parents=True)
                target = base / "actual target"
                workspace = (repo if layout == "root" else
                             repo / "bench" / "scale" if layout == "standalone" else
                             base / "unexpected workspace")
                metadata = base / "metadata.json"
                metadata.write_text(json.dumps(dict(workspace_root=str(workspace),
                                                   target_directory=str(target))), encoding="utf-8")
                tools = base / "tools"
                tools.mkdir()
                cargo = tools / "cargo"
                cargo.write_text(f"#!{sys.executable}\n" + r'''import json, os, pathlib, sys
with pathlib.Path(os.environ["CARGO_LOG"]).open("a") as log:
    log.write(json.dumps(dict(args=sys.argv[1:], target=os.environ.get("CARGO_TARGET_DIR"),
                             rustflags=os.environ.get("RUSTFLAGS"))) + "\n")
if sys.argv[1] == "metadata":
    if os.environ["LAYOUT"] == "metadata-failure":
        sys.exit(42)
    print(pathlib.Path(os.environ["METADATA"]).read_text())
''', encoding="utf-8")
                cargo.chmod(0o755)
                result = subprocess.run(
                    ["bash", "-c", "set -euo pipefail\n" + block +
                     '\nprintf "%s\\n" "$HARNESS" "$DAEMON" "$RBGP"'],
                    env={**os.environ, "REPO": str(repo), "OUT": str(out), "DHAT": "0",
                         "PROFILE": "ci", "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                         "CARGO_TARGET_DIR": "must-be-unset", "RUSTFLAGS": "must-be-unset",
                         "CARGO_LOG": str(base / "cargo.jsonl"), "METADATA": str(metadata),
                         "LAYOUT": layout}, capture_output=True, text=True,
                )
                calls = [json.loads(line) for line in (base / "cargo.jsonl").read_text().splitlines()]
                self.assertTrue(all(call["target"] is None and call["rustflags"] is None
                                    for call in calls))
                if layout in ("metadata-failure", "unexpected"):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(any("--manifest-path" in call["args"] and
                                         call["args"][0] == "build" for call in calls))
                    continue
                self.assertEqual(result.returncode, 0, result.stderr)
                profile = "scale" if layout == "root" else "release"
                root_target = target if layout == "root" else repo / "target"
                self.assertEqual(result.stdout.splitlines(), [str(target / profile / "reloadstall"),
                                                             str(root_target / "ci" / "rustbgpd"),
                                                             str(root_target / "ci" / "rbgp")])
                self.assertEqual(calls[-1]["args"], ["build", "--profile", profile, "--locked",
                                                     "--manifest-path", "bench/scale/reloadstall/Cargo.toml"])
                fields = dict(line.split("=", 1) for line in
                              (out / "provenance.env").read_text().splitlines())
                self.assertEqual(fields["harness_profile"], profile)
                self.assertEqual(fields["harness_target_dir"], str(target))
                self.assertEqual(fields["harness_workspace_root"], str(workspace))

    def test_explain_variant_no_churn_is_only_used_with_zero_reloads(self) -> None:
        _, script = runner_script()
        start = script.index("HARNESS_ENV=()")
        block = script[start:script.index("\ntimeout -k 10", start)]
        for reloads, expected in (("0", "--no-churn"), ("4", "")):
            result = subprocess.run(
                ["bash", "-c", "set -euo pipefail\n" + block + '\nprintf "%s\\n" "${HARNESS_FLAGS[@]}"'],
                env={**os.environ, "RELOADS": reloads, "RUN": "/fixture"},
                capture_output=True, text=True, check=True,
            )
            self.assertEqual(result.stdout.strip(), expected)

    def test_explain_variant_config_and_source_derived_prefixes(self) -> None:
        python = self.runner_embedded_python("prepare_explain_config() {")
        generator = HERE.parent / "reloadstall" / "gen-scenario.py"
        initial = '[policy]\nexport_chain = ["member-out"]\n'
        for peers, total, last in ((2, 2000000, "35.66.63.0/24"),
                                   (1000, 400000, "20.1.143.0/24"),
                                   (3, 8, "20.0.2.0/24")):
            for enabled in ("true", "false", "omit"):
                with self.subTest(peers=peers, enabled=enabled), tempfile.TemporaryDirectory() as directory:
                    config = Path(directory) / "config.toml"
                    config.write_text(initial, encoding="utf-8")
                    result = subprocess.run(
                        [sys.executable, "-c", python, str(config), enabled, "262144",
                         str(total), str(peers), str(generator)],
                        capture_output=True, text=True, check=True,
                    )
                    self.assertEqual(result.stdout, f"early\t20.0.0.0/24\nlate\t{last}\n")
                    if enabled == "omit":
                        self.assertEqual(config.read_text(), initial)
                    else:
                        self.assertIn(f"enabled = {enabled}\ncache_size = 262144", config.read_text())

    def test_explain_variant_capacity_provenance(self) -> None:
        _, script = runner_script()
        start = script.index("printf 'label=%s")
        block = script[start:script.index("\n{ rustc", start)]
        with tempfile.TemporaryDirectory() as directory:
            variables = dict(OUT=directory, LABEL="fixture", COMMIT="abc", TREE="def",
                             PEERS="2", TOTAL="2000000", EXPLAIN="true", CACHE_SIZE="262144",
                             DHAT="0", PROFILE="release", RELOADS="0", CONTROL_SECS="10",
                             EXPECTED_PER_OBSERVER="1000000")
            subprocess.run(["bash", "-c", "set -euo pipefail\n" + block],
                           env={**os.environ, **variables}, check=True)
            fields = dict(line.split("=", 1) for line in
                          (Path(directory) / "provenance.env").read_text().splitlines())
            self.assertEqual(fields["cache_size"], "262144")
            self.assertEqual(fields["explain"], "true")
            self.assertEqual(fields["no_churn"], "1")

    def test_explain_probe_failures_prevent_ack_and_success(self) -> None:
        _, script = runner_script()
        functions = []
        for name in ("validate_explain_evidence", "capture_explain_evidence"):
            start = script.index(f"{name}() {{")
            functions.append(script[start:script.index("\n}\n", start) + 3])
        command = "set -euo pipefail\n" + "\n".join(functions) + (
            '\ncapture_explain_evidence\ntouch "$OUT/ack"\n'
            'printf "status=success\\n" >"$OUT/result"\n'
        )
        cases = ("evicted", "full", "disabled", "failed", "missing", "not_seen",
                 "capacity", "completeness", "family", "no_matches")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                enabled = "false" if case == "disabled" else "true"
                size = 32 if case == "full" else 4
                (out / "explain-prefixes.tsv").write_text(
                    "early\t20.0.0.0/24\nlate\t20.0.7.0/24\n", encoding="utf-8")
                for label in ("early", "late"):
                    answer = dict(peer_address="127.1.0.1", prefix=f"20.0.{0 if label == 'early' else 7}.0/24",
                                  afi_safi="ipv4-unicast", current_policy_generation=1,
                                  cache_size=None if enabled == "false" else size,
                                  evictions_since_reset=None if enabled == "false" else max(0, 8 - size),
                                  matches=[dict(path_id=0, outcome="cache_disabled" if enabled == "false" else
                                                ("evicted" if label == "early" and size < 8 else "permit"))])
                    if label == "early":
                        if case == "not_seen":
                            answer["matches"][0]["outcome"] = "not_seen"
                        elif case == "capacity":
                            answer["cache_size"] = 4096
                        elif case == "completeness":
                            del answer["evictions_since_reset"]
                        elif case == "family":
                            answer["afi_safi"] = "ipv6-unicast"
                        elif case == "no_matches":
                            answer["matches"] = []
                    (out / f"fixture-{label}.json").write_text(json.dumps(answer), encoding="utf-8")
                cli = out / "fixture-cli"
                cli.write_text(f"#!{sys.executable}\n" + '''import os, pathlib, sys
label = "early" if sys.argv[sys.argv.index("--prefix") + 1] == "20.0.0.0/24" else "late"
if not (os.environ["CASE"] == "missing" and label == "late"):
    print((pathlib.Path(os.environ["OUT"]) / f"fixture-{label}.json").read_text())
sys.exit(2 if os.environ["CASE"] == "failed" and label == "late" else
         (1 if os.environ["EXPLAIN"] == "false" else 0))
''', encoding="utf-8")
                cli.chmod(0o755)
                result = subprocess.run(
                    ["bash", "-c", command], capture_output=True, text=True,
                    env={**os.environ, "OUT": directory, "RUN": directory, "RBGP": str(cli),
                         "EXPLAIN": enabled, "CACHE_SIZE": str(size), "TOTAL": "16", "PEERS": "2", "CASE": case},
                )
                positive = case in ("evicted", "full", "disabled")
                self.assertEqual(result.returncode == 0, positive, result.stderr)
                self.assertEqual((out / "ack").exists(), positive)
                self.assertEqual((out / "result").exists(), positive)
                if positive:
                    self.assertIn("late_outcome=", (out / "explain-evidence.env").read_text())

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
