"""Negative controls for the grouped OLD workload and its scope receipt."""

import copy
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import grouped_old as cell


HERE = Path(__file__).resolve().parent
# Exact names the quiet gate rejects that are not compilers or linkers.
OTHER_COMPETITORS = {"perf", "rustbgpd", "rrtransport", "reloadstall", "bird", "bird6", "bgpd",
                     "openbgpd", "gobgpd", "zebra", "frr", "ospfd", "staticd"}


def transport(peers, rows):
    return {
        "sessions": peers, "established": peers, "resets": 0, "seed_fences": peers,
        "final_fences": peers, "wire_exact_receivers": peers,
        "receivers": [
            {"peer": str(IPv4Address("127.32.0.1") + i), "session_id": i + 1, "wire": {
                "present": rows + 2, "withdrawals": 1, "announcements": 2 * rows + 4, "empty_initial_eors": 1,
                "replacement_version": 3, "intermediate_fill_seen": True, "trigger_present": True,
                "probe_present": True, "recovery_probe_present": True,
            }} for i in range(peers)
        ],
    }


def proofs(peers, rows):
    """One cold indexed pool, then every other member reuses it."""
    return [{"strategy": "indexed", "pool": "reused" if i else "built", "keys": rows, "slots": rows,
             "walks": 2, "projections": 2 * rows, "member_charge_bytes": 4096, "daemon_bytes": 4096 + 192 * i // peers}
            for i in range(peers)]


def workload(peers, rows):
    return {
        "peers": peers, "rows": rows, "established_group_members": peers,
        "full_receivers_before_trigger": peers, "first_refused_receivers": peers,
        "wire_exact_receivers": peers, "transport": transport(peers, rows),
        "fresh_captures": peers, "walks": 2 * peers, "group_capture_walks": 2 * peers,
        "projections": 2 * peers * rows, "proofs": proofs(peers, rows),
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
            "compiler_watch": {"samples": 11, "observed": 0, "first_compiler": None},
        }
        self.raw = {
            "cell": "grouped-old-capture", **workload(4, 64), "reset_count": 0,
            "hold_time_secs": 180, "session_runtime_max_stall_ns": 2_000_000,
            "proof_ledger": {"before_bytes": 512, "after_bytes": 4288, "peak_bytes": 4288,
                             "member_limit_bytes": 64 << 20, "daemon_limit_bytes": 512 << 20},
            "actor_polls": 26, "longest_actor_poll_ns": 80, "longest_actor_poll_phase": "recovery",
            "longest_actor_poll_touched": ["dirty", "recovery"],
            "phases": {
                "setup": {"polls": 12, "longest_poll_ns": 30},
                "refusal": {"polls": 1, "longest_poll_ns": 60},
                "dirty": {"polls": 3, "longest_poll_ns": 20, "refused_resync_slices": 4},
                "recovery": {"polls": 6, "longest_poll_ns": 80, "resync_slices": 4},
                "settled": {"polls": 4, "longest_poll_ns": 10},
            },
            "retirement": {"reached": True, "longest_poll_ns": 80},
            "capture_turn_poll_ns": 60, "capture_pass_ns": 45, "capture_loop_ns": 35,
            "probe_admission_to_dispatch_ns": 55, "probe_admission_to_winner_ns": 70,
            "recovery_probe_admission_to_dispatch_ns": 40, "recovery_probe_admission_to_winner_ns": 60,
            "recovery_probe_slice_recovered": True, "debug_assertions": False,
            "checkpoint_tally_compiled_in": False, "probe_winner_boundary": "first_matching_query_reply",
            "clocks_ns": {"trigger_admission": 2, "poll_start": 5, "pass_start": 10,
                          "capture_start": 15, "probe_admission": 20, "capture_end": 50,
                          "pass_end": 55, "poll_end": 65, "probe_dispatch": 75, "probe_winner": 90,
                          "recovery_start": 200, "recovery_probe_admission": 210,
                          "recovery_probe_dispatch": 250, "recovery_probe_winner": 270, "recovery_end": 400},
        }
        (self.out / "binary.sha256").write_text("a" * 64 + "  /tmp/test-binary\n")

    def check(self, raw=None, host=None, shape="smoke"):
        (self.out / "host.json").write_text(json.dumps(self.host if host is None else host))
        (self.out / "grouped-old.json").write_text(json.dumps(self.raw if raw is None else raw))
        return cell.check(self.out, shape)

    def seeded(self, field, value):
        """Grade a copy of the passing fixture with one dotted field replaced."""
        fixture = copy.deepcopy({"raw": self.raw, "host": self.host})
        *path, key = field.split("/")
        target = fixture
        for part in path:
            target = target[int(part) if isinstance(target, list) else part]
        target[key] = value
        return self.check(**fixture)

    def test_instrument_and_independent_red_controls(self):
        self.assertEqual(self.check()[0], "PASS")
        cases = [
            ("raw/peers", 3), ("raw/rows", 0), ("raw/cell", "restart"),
            ("raw/established_group_members", 0), ("raw/full_receivers_before_trigger", 3),
            ("raw/first_refused_receivers", 3), ("raw/fresh_captures", 1),
            ("raw/walks", True), ("raw/projections", 511), ("raw/reset_count", -1),
            ("raw/actor_polls", 0), ("raw/capture_turn_poll_ns", 59), ("raw/capture_pass_ns", 0),
            ("raw/capture_loop_ns", 31),
            ("raw/clocks_ns/probe_admission", 50), ("raw/clocks_ns/capture_end", 70),
            ("raw/clocks_ns/pass_end", 100), ("raw/clocks_ns/probe_dispatch", 54),
            ("raw/probe_admission_to_dispatch_ns", 5), ("raw/probe_admission_to_winner_ns", 17),
            ("raw/debug_assertions", True), ("raw/checkpoint_tally_compiled_in", True),
            ("raw/probe_winner_boundary", "outbound socket write"),
            ("raw/transport/seed_fences", 1), ("raw/transport/receivers", []),
            ("host/unit", "shared.scope"), ("host/shape", "700x400000"), ("host/exit", 1),
            ("host/compiler_watch/samples", 1), ("host/compiler_watch/first_compiler", "100 rustc"),
            ("host/compiler_watch/observed", 1),
            ("host/memory_after/memory.swap.max", 1), ("host/memory_after/memory.swap.peak", 1),
            ("host/memory_before/memory.max", "max"), ("host/memory_after/memory.peak", 42),
            ("host/memory_after/oom_kill", 1), ("host/memory_after/memory.peak", 0),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                self.assertEqual(self.seeded(field, value)[0], "INVALID")
        for key, value in (("reset_count", 1), ("wire_exact_receivers", 3)):
            with self.subTest(key=key):
                self.assertEqual(self.check(dict(self.raw, **{key: value}))[0], "FAIL")
        self.assertEqual(self.check()[0], "PASS")

    def test_every_phase_is_labeled_and_the_longest_poll_names_its_phase(self):
        verdict, detail = self.check()
        self.assertEqual(verdict, "PASS", detail)
        self.assertIn("whole run 0.000 ms in recovery", detail)
        cases = [
            # The longest poll of the run cannot sit in a phase that reports less.
            ("raw/longest_actor_poll_ns", 60, "whole-run longest"),
            ("raw/longest_actor_poll_phase", "refusal", "whole-run longest"),
            ("raw/longest_actor_poll_phase", "seed", "whole-run longest"),
            ("raw/longest_actor_poll_touched", ["dirty"], "phases for the longest"),
            # A pause moved into recovery raises that phase and the whole-run figure together.
            ("raw/phases/recovery/longest_poll_ns", 900, "whole-run longest"),
            ("raw/phases/dirty/longest_poll_ns", 0, "disagree with their longest"),
            ("raw/phases/dirty/polls", 0, "disagree with their longest"),
            ("raw/phases/recovery/polls", 5, "do not sum"),
            ("raw/phases/refusal/polls", 2, "single capture poll"),
            ("raw/phases/refusal/longest_poll_ns", 61, "single capture poll"),
            ("raw/phases/dirty/refused_resync_slices", 0, "full receiver"),
            ("raw/phases/recovery/resync_slices", 0, "no resync slice in recovery"),
            ("raw/retirement", {"reached": False, "longest_poll_ns": None}, "retirement"),
            ("raw/retirement/longest_poll_ns", 81, "retirement"),
            # The recovery probe must be admitted inside a slice that recovered a receiver.
            ("raw/recovery_probe_slice_recovered", False, "did not recover"),
            ("raw/recovery_probe_slice_recovered", None, "did not recover"),
            ("raw/clocks_ns/recovery_start", 80, "recovery probe outside recovery"),
            ("raw/clocks_ns/recovery_probe_admission", 190, "recovery probe outside recovery"),
            ("raw/clocks_ns/recovery_probe_dispatch", 205, "recovery probe outside recovery"),
            ("raw/recovery_probe_admission_to_dispatch_ns", 1, "inconsistent with timestamps"),
            ("raw/recovery_probe_admission_to_winner_ns", 1, "inconsistent with timestamps"),
        ]
        for field, value, why in cases:
            with self.subTest(field=field, value=value):
                verdict, detail = self.seeded(field, value)
                self.assertEqual(verdict, "INVALID", detail)
                self.assertIn(why, detail)
        missing = copy.deepcopy(self.raw)
        del missing["phases"]["settled"]
        self.assertEqual(self.check(missing)[0], "INVALID")
        # A phase with no poll at all fails even when the remaining counts still sum.
        for name in ("setup", "dirty", "recovery", "settled"):
            with self.subTest(unobserved=name):
                unobserved = copy.deepcopy(self.raw)
                unobserved["actor_polls"] -= unobserved["phases"][name]["polls"]
                unobserved["phases"][name].update(polls=0, longest_poll_ns=0)
                if name == "recovery":  # Keep the whole-run maximum consistent without it.
                    unobserved.update(longest_actor_poll_ns=60, longest_actor_poll_phase="refusal",
                                      longest_actor_poll_touched=["refusal"])
                    unobserved["retirement"]["longest_poll_ns"] = 60
                self.assertEqual(self.check(unobserved), ("INVALID", "a phase has no physical RIB poll"))

    def test_each_capture_records_its_strategy_and_ledger_charge(self):
        verdict, detail = self.check()
        self.assertEqual(verdict, "PASS", detail)
        self.assertIn("proofs 1 indexed/built, 3 indexed/reused", detail)
        self.assertIn("largest member charge 4096 of 67108864 bytes", detail)
        cases = [
            ("raw/proofs/0/strategy", "sorted"), ("raw/proofs/1/pool", "built-twice"),
            ("raw/proofs/2/pool", "none"), ("raw/proofs/3/keys", 63), ("raw/proofs/3/slots", 63),
            ("raw/proofs/0/member_charge_bytes", 0), ("raw/proofs/0/member_charge_bytes", (64 << 20) + 1),
            ("raw/proofs/1/daemon_bytes", 4289), ("raw/proofs", []),
            ("raw/proof_ledger/after_bytes", 512), ("raw/proof_ledger/peak_bytes", (512 << 20) + 1),
            ("raw/proof_ledger/member_limit_bytes", 0),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                self.assertEqual(self.seeded(field, value)[0], "INVALID")
        # A capture the ledger refused keeps its cause instead of a bare INVALID.
        cause = ("1 of 4 captures refused by the recovery ledger; first: peer_limit "
                 "(attempted 67108865 member bytes, 70000000 daemon bytes)")
        refused = {"cell": self.raw["cell"], "peers": 4, "rows": 64, "harness_invalid": cause}
        self.assertEqual(self.check(refused, dict(self.host, exit=1)), ("INVALID", cause))
        self.assertEqual(self.check(refused, self.host), ("INVALID", "unconfirmed harness refusal"))

    def test_work_and_announcement_counts_are_exact(self):
        peers, rows = 4, 64
        for walks, per_capture, verdict in (
            (2 * peers, 2, "PASS"),  # Each proof is sized in one walk and populated in a second.
            (peers, 1, "INVALID"),  # One walk per capture.
            (4 * peers, 4, "INVALID"),  # Four walks per capture.
            (0, 0, "INVALID"),
            (2, None, "PASS"),  # One cohort capture: the first proof walks, the rest are served.
            (4, None, "INVALID"),  # Two walks outside the cohort's sealed proof.
        ):
            with self.subTest(walks=walks):
                raw = copy.deepcopy(self.raw)
                raw.update(walks=walks, group_capture_walks=walks, projections=walks * rows)
                for i, proof in enumerate(raw["proofs"]):
                    each = per_capture if per_capture is not None else 2 * (i == 0)
                    proof.update(walks=each, projections=each * rows)
                self.assertEqual(self.check(raw)[0], verdict)
        for field, value, why in (
            ("raw/projections", 2 * peers * rows - 1, "projections disagree"),
            ("raw/group_capture_walks", 2 * peers - 2, "2 walks outside a sealed grouped capture"),
            ("raw/proofs/2/walks", 1, "capture made 1 walks"),
            ("raw/proofs/2/projections", 2 * rows + 1, "capture made 2 walks"),
            ("raw/proofs/2/walks", 0, "walks for 3 walking of 4"),
        ):
            with self.subTest(field=field):
                verdict, detail = self.seeded(field, value)
                self.assertEqual(verdict, "INVALID", detail)
                self.assertIn(why, detail)
        for sent in (3 * rows, 2 * rows + 3, 2 * rows + 5, 3 * (2 * rows + 4)):  # Short, or the table sent again.
            with self.subTest(announcements=sent):
                verdict, detail = self.seeded("raw/transport/receivers/3/wire/announcements", sent)
                self.assertEqual(verdict, "INVALID", detail)
                self.assertIn(f"{sent} announcements, expected exactly {2 * rows + 4}", detail)

    def test_harness_starvation_is_not_a_daemon_reset(self):
        # A reset with a serviced session runtime is the daemon's.
        self.assertEqual(self.check(dict(self.raw, reset_count=1)), ("FAIL", "transport reset"))
        # The same reset after the runtime stalled a keepalive interval is the harness's own.
        stalled = dict(self.raw, reset_count=1, session_runtime_max_stall_ns=60_000_000_000)
        verdict, detail = self.check(stalled)
        self.assertEqual(verdict, "INVALID")
        self.assertIn("session runtime stalled 60.0 s against a 180 s hold time", detail)
        self.assertEqual(self.check(dict(self.raw, session_runtime_max_stall_ns=59_999_999_999))[0], "PASS")
        self.assertEqual(self.check(dict(self.raw, hold_time_secs=0))[0], "INVALID")
        cause = "session runtime stalled 61.2 s against a 180 s hold time: receiver correctness failure"
        early = {"cell": self.raw["cell"], "peers": 4, "rows": 64, "harness_invalid": cause}
        self.assertEqual(self.check(early, dict(self.host, exit=1)), ("INVALID", cause))

    def test_decoded_receiver_mismatch_and_early_wire_failure(self):
        for field, value in (("withdrawals", 0), ("probe_present", False), ("replacement_version", 2),
                             ("empty_initial_eors", 0), ("empty_initial_eors", 2), ("present", 65),
                             ("recovery_probe_present", False)):
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
            raw = dict(self.raw, **workload(peers, rows))
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

    def test_compiler_invalidates_a_measured_shape_and_is_recorded_on_a_smoke(self):
        quiet = ("sample\tepoch_s\tload1\tpswpin\tpswpout\tgovernor_count\tperformance_governors\t"
                 "competitors\tquiet\tfailed_dimensions\n"
                 "1\t100\t1\t0\t0\t4\t4\tnone\ttrue\tnone\n"
                 "2\t130\t1\t0\t0\t4\t4\tnone\ttrue\tnone\n")
        (self.out / "quiet.tsv").write_text(quiet)
        seen = {"samples": 11, "observed": 3, "first_compiler": "123 rustc"}
        verdict, detail = self.check(host=dict(self.host, compiler_watch=seen))
        self.assertEqual(verdict, "PASS", detail)
        self.assertIn("compiler seen during the smoke (123 rustc), timings not usable", detail)
        # The same sighting does not excuse a wrong table.
        bad = copy.deepcopy(self.raw)
        bad["transport"]["receivers"][0]["wire"]["withdrawals"] = 0
        self.assertEqual(self.check(bad, dict(self.host, compiler_watch=seen))[0], "FAIL")
        peers, rows = cell.SHAPES["150x37000"]
        raw = dict(self.raw, **workload(peers, rows))
        measured = dict(self.host, shape="150x37000")
        self.assertEqual(self.check(raw, measured, "150x37000")[0], "PASS")
        self.assertEqual(self.check(raw, dict(measured, compiler_watch=seen), "150x37000"),
                         ("INVALID", "concurrent compiler: 123 rustc"))

        # The watch stops on every compiler and linker the quiet gate rejects.
        gate = (HERE.parent / "host-quiet.sh").read_text()
        rejected = set(re.findall(r'name == "([^"]+)"', gate)) - OTHER_COMPETITORS
        self.assertTrue({"cargo", "rustc", "gcc", "cc1", "ld", "ld.lld", "mold"} <= rejected)
        self.assertEqual(cell.COMPILERS, rejected | {"clippy-driver"})
        for name in sorted(cell.COMPILERS):
            with self.subTest(compiler=name):
                pid = self.out / "77"
                pid.mkdir(exist_ok=True)
                (pid / "comm").write_text(name + "\n")
                with patch.object(cell.Path, "iterdir", return_value=[pid]):
                    with self.assertRaisesRegex(ValueError, f"concurrent compiler: 77 {re.escape(name)}$"):
                        cell.compiler_sample({"samples": 0, "observed": 0, "first_compiler": None}, measured=True)

        pid = self.out / "123"
        pid.mkdir()
        (pid / "comm").write_text("rustc\n")
        watch = {"samples": 0, "observed": 0, "first_compiler": None}
        with patch.object(cell.Path, "iterdir", return_value=[pid]):
            cell.compiler_sample(watch, measured=False)
            cell.compiler_sample(watch, measured=False)
            self.assertEqual(watch, {"samples": 2, "observed": 2, "first_compiler": "123 rustc"})
            with self.assertRaisesRegex(ValueError, "concurrent compiler: 123 rustc"):
                cell.compiler_sample(watch, measured=True)
        self.assertEqual(watch, {"samples": 2, "observed": 3, "first_compiler": "123 rustc"})

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


if __name__ == "__main__":
    unittest.main()
