"""Negative controls for the grouped OLD workload and its scope receipt."""

import copy
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import grouped_old as cell


HERE = Path(__file__).resolve().parent


def transport(peers, rows):
    return {
        "sessions": peers, "established": peers, "resets": 0, "seed_fences": peers,
        "final_fences": peers, "wire_exact_receivers": peers,
        "receivers": [
            {"peer": str(IPv4Address("127.32.0.1") + i), "session_id": i + 1, "wire": {
                "present": rows + 1, "withdrawals": 1, "announcements": rows + 4, "empty_initial_eors": 1,
                "replacement_version": 3, "intermediate_fill_seen": True, "trigger_present": True,
                "probe_present": True,
            }} for i in range(peers)
        ],
    }


class GroupedOldReceipt(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name)
        memory = {"memory.peak": 1 << 26, "memory.max": cell.LIMIT_BYTES,
                  "memory.swap.max": 0, "memory.swap.peak": 0, "oom_kill": 0}
        self.host = {
            "shape": "smoke", "unit": "rrtransport-grouped-old-test.scope", "exit": 0,
            "memory_before": dict(memory), "memory_after": dict(memory),
            "compiler_watch": {"samples": 11, "first_compiler": None},
        }
        self.raw = {
            "cell": "grouped-old-capture", "peers": 4, "rows": 64,
            "established_group_members": 4, "full_receivers_before_trigger": 4,
            "first_refused_receivers": 4, "exact_receivers_before_trigger": 4,
            "exact_receivers_after_recovery": 4, "reset_count": 0, "wire_exact_receivers": 4,
            "policy_denied_winner_absent_on_receivers": True, "transport": transport(4, 64),
            "fresh_captures": 4, "walks": 8, "projections": 512,
            "actor_polls": 26, "longest_actor_poll_ns": 72, "capture_turn_poll_ns": 60, "capture_pass_ns": 45, "capture_loop_ns": 35,
            "probe_admission_to_dispatch_ns": 55, "probe_admission_to_winner_ns": 70,
            "probe_overlapped_capture": True, "debug_assertions": False,
            "checkpoint_tally_compiled_in": False, "probe_winner_boundary": "first_matching_query_reply",
            "clocks_ns": {"trigger_admission": 2, "poll_start": 5, "pass_start": 10,
                          "capture_start": 15, "probe_admission": 20, "capture_end": 50,
                          "pass_end": 55, "poll_end": 65, "probe_dispatch": 75, "probe_winner": 90},
        }
        (self.out / "binary.sha256").write_text("a" * 64 + "  /tmp/test-binary\n")

    def check(self, raw=None, host=None, shape="smoke"):
        (self.out / "host.json").write_text(json.dumps(self.host if host is None else host))
        (self.out / "grouped-old.json").write_text(json.dumps(self.raw if raw is None else raw))
        return cell.check(self.out, shape)

    def test_instrument_and_independent_red_controls(self):
        self.assertEqual(self.check()[0], "PASS")
        cases = [
            ("raw.peers", 3), ("raw.rows", 0), ("raw.cell", "restart"),
            ("raw.established_group_members", 0), ("raw.full_receivers_before_trigger", 3),
            ("raw.first_refused_receivers", 3), ("raw.fresh_captures", 1),
            ("raw.walks", True), ("raw.projections", 511), ("raw.reset_count", -1),
            ("raw.exact_receivers_after_recovery", 5), ("raw.probe_overlapped_capture", False),
            ("raw.actor_polls", 0), ("raw.longest_actor_poll_ns", 59), ("raw.capture_turn_poll_ns", 59), ("raw.capture_pass_ns", 0), ("raw.capture_loop_ns", 31),
            ("raw.clocks_ns.probe_admission", 50), ("raw.clocks_ns.capture_end", 70),
            ("raw.clocks_ns.pass_end", 100), ("raw.clocks_ns.probe_dispatch", 54),
            ("raw.probe_admission_to_dispatch_ns", 5), ("raw.probe_admission_to_winner_ns", 17),
            ("raw.debug_assertions", True), ("raw.checkpoint_tally_compiled_in", True),
            ("raw.probe_winner_boundary", "outbound socket write"),
            ("raw.transport.seed_fences", 1), ("raw.transport.receivers", []),
            ("host.unit", "shared.scope"), ("host.shape", "700x400000"), ("host.exit", 1),
            ("host.compiler_watch.samples", 1), ("host.compiler_watch.first_compiler", "100 rustc"),
            ("host.memory_after.memory.swap.max", 1), ("host.memory_after.memory.swap.peak", 1),
            ("host.memory_before.memory.max", "max"), ("host.memory_after.memory.peak", 42),
            ("host.memory_after.oom_kill", 1), ("host.memory_after.memory.peak", 0),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                fixture = copy.deepcopy({"raw": self.raw, "host": self.host})
                part, key = field.split(".", 1)
                target = fixture[part]
                if "." in key:
                    part, key = key.split(".", 1)
                    target = target[part]
                target[key] = value
                self.assertEqual(self.check(**fixture)[0], "INVALID")
        for key, value in (("reset_count", 1), ("exact_receivers_before_trigger", 3),
                           ("exact_receivers_after_recovery", 0)):
            with self.subTest(key=key):
                self.assertEqual(self.check(dict(self.raw, **{key: value}))[0], "FAIL")
        self.assertEqual(self.check()[0], "PASS")

    def test_dense_walk_counts_follow_observed_work(self):
        for walks, projections, verdict in (
            (8, 512, "PASS"),  # Main sizes and populates each of the four proofs.
            (4, 256, "PASS"),  # Single full walk per member.
            (3, 192, "INVALID"),  # Insufficient walks for four fresh captures.
            (0, 0, "INVALID"),
            (4, 255, "INVALID"),  # One projection missing from the dense table.
        ):
            with self.subTest(walks=walks, projections=projections):
                result = self.check(dict(self.raw, walks=walks, projections=projections))
                self.assertEqual(result[0], verdict, result)

    def test_decoded_receiver_mismatch_and_early_wire_failure(self):
        for field, value in (("withdrawals", 0), ("probe_present", False), ("replacement_version", 2),
                             ("empty_initial_eors", 0), ("announcements", 64)):
            with self.subTest(field=field):
                bad = copy.deepcopy(self.raw)
                bad["transport"]["receivers"][-1]["wire"][field] = value
                self.assertEqual(self.check(bad)[0], "FAIL")
        bad = copy.deepcopy(self.raw)
        bad["transport"]["receivers"][-1] = bad["transport"]["receivers"][0]
        self.assertEqual(self.check(bad)[0], "INVALID")
        early = {"cell": self.raw["cell"], "peers": 4, "rows": 64, "wire_failure": "wrong community"}
        self.assertEqual(self.check(early, dict(self.host, exit=1)), ("FAIL", "wrong community"))
        self.assertEqual(self.check(early, self.host)[0], "INVALID")

    def test_quiet_gate_and_mode_follow_workload_shape(self):
        quiet = ("sample\tepoch_s\tload1\tpswpin\tpswpout\tgovernor_count\tperformance_governors\t"
                 "competitors\tquiet\tfailed_dimensions\n"
                 "1\t100\t1\t0\t0\t4\t4\tnone\ttrue\tnone\n"
                 "2\t130\t1\t0\t0\t4\t4\tnone\ttrue\tnone\n")
        self.assertEqual(cell.SHAPES["smoke-chunked"], (12, 2049))
        for shape in ("smoke-chunked", "150x37000", "700x400000"):
            peers, rows = cell.SHAPES[shape]
            raw = dict(self.raw, peers=peers, rows=rows, walks=2*peers, projections=2*peers*rows)
            for key in ("established_group_members", "full_receivers_before_trigger", "first_refused_receivers",
                        "exact_receivers_before_trigger", "exact_receivers_after_recovery", "fresh_captures"):
                raw[key] = peers
            raw.update(transport=transport(peers, rows), wire_exact_receivers=peers)
            host = dict(self.host, shape=shape)
            if shape == "smoke-chunked":
                verdict, detail = self.check(raw, host, shape)
                self.assertEqual(verdict, "PASS", detail)
                self.assertIn("correctness smoke", detail)
                self.assertEqual(self.check(raw, self.host, shape)[0], "INVALID")
                continue
            (self.out / "quiet.tsv").write_text("")
            self.assertEqual(self.check(raw, host, shape)[0], "INVALID")
            (self.out / "quiet.tsv").write_text(quiet)
            self.assertEqual(self.check(raw, host, shape)[0], "PASS")

    def test_shell_creates_isolated_scope_and_preserves_attempt(self):
        fake = self.out / "systemd-run"
        fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$SCOPE_ARGS"\nexit 9\n')
        fake.chmod(0o755)
        args_file = self.out / "scope.args"
        output = self.out / "attempt"
        env = dict(os.environ, PATH=f"{self.out}:{os.environ['PATH']}",
                   RUSTBGPD_HOST_LOCK=str(self.out / "lock"), SCOPE_ARGS=str(args_file))
        argv = [HERE / "run-grouped-old.sh", "/bin/true", output, "smoke"]
        result = subprocess.run(argv, env=env, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2, result.stderr)
        args = args_file.read_text().splitlines()
        self.assertIn("MemoryMax=64G", args)
        self.assertIn("MemorySwapMax=0", args)
        self.assertTrue(any(arg.startswith("--unit=rrtransport-grouped-old-") for arg in args))
        self.assertFalse((output / "quiet.tsv").exists())
        args_file.unlink()
        self.assertNotEqual(subprocess.run(argv, env=env, capture_output=True).returncode, 0)
        self.assertFalse(args_file.exists())

    def test_compiler_sample_aborts_on_observed_process(self):
        pid = self.out / "123"
        pid.mkdir()
        (pid / "comm").write_text("rustc\n")
        watch = {"samples": 0, "first_compiler": None}
        with patch.object(cell.Path, "iterdir", return_value=[pid]), self.assertRaisesRegex(ValueError, "compiler"):
            cell.compiler_sample(watch)
        self.assertEqual(watch["first_compiler"], "123 rustc")


if __name__ == "__main__":
    unittest.main()
