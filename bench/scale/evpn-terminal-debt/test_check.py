import copy
import unittest

import check


def fixture():
    feeds = [feed("data_admitted", 100, rows=20000), feed("root_before", 200, root=1),
             feed("data_admitted", 300, root=1, rows=4, stamp=11), feed("sample", 500, stamp=11)]
    work = {name: 4 for name in check.COUNTERS}
    work.update(id=1, wall_us=320, keys=4, debtors_before=2, prepare_attempts=2, projection_walks=4,
                current_walks=2, old_walks=2, success_walks=2, elapsed_us=17,
                sparse_seals=0, sparse_walks=0, sparse_rows=0)
    sockets = [{"peer": "127.1.0.2", "cookie": 17, "send_buffer": 8192, "notsent_lowat": 4096}]
    writes = [{"event": "pending", "id": 55, "cookie": 17, "started_us": 101, "wall_us": 110},
              {"event": "complete", "id": 55, "cookie": 17, "started_us": 101, "wall_us": 600}]
    samples = [{"cookie": 17, "started_us": at, "ended_us": at + 5,
                "rwnd_limited_us": limited, "sndbuf_limited_us": 0, "notsent": 4096}
               for at, limited in ((150, 1000), (450, 2000))]
    return feeds, [work], sockets, writes, samples, 400, "127.1.0.1"


class DebtChecks(unittest.TestCase):
    def test_actual_admission_revision_kernel_and_all_walks(self):
        result = check.debt_receipt(*fixture())
        self.assertIsNotNone(result)
        self.assertEqual(result["work"]["inventory_visits"], 16)
        self.assertEqual(result["marker_refusals"], 0)
        self.assertEqual(result["marker_refusals_by_site"], {"flush": 0, "retry": 0, "initial": 0, "refresh": 0})
        # A passing fixture still fails the predeclared zero-inventory-work bar.
        self.assertGreater(result["work"]["inventory_visits"], 0)

    def test_false_complete_current_session_channel_and_debt_are_rejected(self):
        for field, value in (("complete", False), ("current", False), ("record_session", 6),
                             ("session", 0), ("channel_match", False), ("owed", 0), ("dirty", True)):
            for position in range(4):
                with self.subTest(field=field, position=position):
                    args = fixture()
                    args[0][position][field] = value
                    self.assertIsNone(check.debt_receipt(*args))

    def test_common_obligation_or_noop_cannot_replace_real_data_admission(self):
        for event, rows in (("sample", 20000), ("data_admitted", 0)):
            with self.subTest(event=event, rows=rows):
                args = fixture()
                args[0][0].update(event=event, rows=rows)
                self.assertIsNone(check.debt_receipt(*args))

    def test_source_exclusion_cannot_supply_the_changed_recipient_witness(self):
        args = fixture()
        for row in args[0]:
            row["peer"] = "127.1.0.1"
        self.assertIsNone(check.debt_receipt(*args))

    def test_same_session_reconnect_with_matching_new_channel_is_rejected(self):
        args = fixture()
        for row in args[0][1:]:
            row["channel"] = 2
        self.assertTrue(all(row["channel_match"] and row["session"] == 7 for row in args[0]))
        self.assertIsNone(check.debt_receipt(*args))

    def test_source_socket_ack_without_new_admitted_target_is_rejected(self):
        args = fixture()
        args[0][2]["table_stamp"] = args[0][0]["table_stamp"]
        args[0][-1]["table_stamp"] = args[0][0]["table_stamp"]
        self.assertIsNone(check.debt_receipt(*args))

    def test_later_good_snapshot_cannot_hide_settlement_or_session_replacement(self):
        for field, value in (("owed", 0), ("current", False), ("session", 8)):
            with self.subTest(field=field):
                args = fixture()
                transient = feed("sample", 350, stamp=11)
                transient[field] = value
                args[0].insert(3, transient)
                self.assertIsNone(check.debt_receipt(*args))

    def test_replacement_revision_requires_admission_or_proved_noop_lineage(self):
        for event, rows, accepted in (("data_admitted", 1, True), ("complete_noop", 0, True),
                                      ("sample", 0, False), ("data_admitted", 0, False)):
            with self.subTest(event=event, rows=rows):
                args = fixture()
                args[0].insert(3, feed(event, 350, root=1, revision=3, rows=rows, stamp=11))
                args[0][-1]["revision"] = 3
                self.assertEqual(check.debt_receipt(*args) is not None, accepted)

    def test_missing_root_or_nested_producer_work_is_invalid(self):
        args = fixture()
        args[1].clear()
        with self.assertRaisesRegex(ValueError, "missing actual root"):
            check.debt_receipt(*args)
        for field in ("stage_rows", "delta_rows", "prepare_attempts", "projection_walks", "projection_rows",
                      "current_walks", "old_walks", "old_delta_rows", "success_walks", "success_rows"):
            with self.subTest(field=field):
                args = fixture()
                args[1][0][field] = 0
                with self.assertRaises(ValueError):
                    check.debt_receipt(*args)

    def test_sparse_renewal_root_reports_zero_inventory_work(self):
        args = fixture()
        sparse = {name: 0 for name in ("prepare_attempts", "projection_walks", "projection_rows", "current_walks",
                                       "current_rows", "old_walks", "old_rows", "old_delta_rows", "success_walks",
                                       "success_rows")}
        args[1][0].update(sparse, sparse_seals=2, sparse_walks=2, sparse_rows=8)
        result = check.debt_receipt(*args)
        self.assertEqual(result["work"]["inventory_visits"], 0)
        self.assertEqual((result["work"]["sparse_seals"], result["work"]["sparse_key_visits"]), (2, 8))
        for change, reason in (({"sparse_seals": 0, "sparse_walks": 0, "sparse_rows": 0},
                                "omitted staging, delta or complete producer"),
                               ({"old_rows": 5}, "omitted visited inventory"),
                               ({"sparse_walks": 3}, "sparse renewal verification"),
                               ({"sparse_rows": 0}, "sparse renewal verification")):
            with self.subTest(change=change):
                broken = copy.deepcopy(args)
                broken[1][0].update(change)
                with self.assertRaisesRegex(ValueError, reason):
                    check.debt_receipt(*broken)
        broken = copy.deepcopy(args)
        del broken[1][0]["sparse_seals"]
        with self.assertRaisesRegex(ValueError, "missing or malformed work counter"):
            check.debt_receipt(*broken)

    def test_pause_notsent_or_pending_alone_is_not_kernel_pressure(self):
        for mode in ("no-increase", "wrong-cookie", "pending-after-samples", "completed-before-samples", "outside-debt",
                     "completed-before-root", "both-samples-before-root", "failed-write"):
            with self.subTest(mode=mode):
                args = fixture()
                if mode == "no-increase":
                    args[4][1]["rwnd_limited_us"] = args[4][0]["rwnd_limited_us"]
                elif mode == "wrong-cookie":
                    args[4][1]["cookie"] = 99
                elif mode == "pending-after-samples":
                    args[3][0]["wall_us"] = 300
                elif mode == "completed-before-samples":
                    args[3][1]["wall_us"] = 120
                elif mode == "completed-before-root":
                    args[3][1]["wall_us"] = 190
                elif mode == "both-samples-before-root":
                    args[4][1].update(started_us=180, ended_us=185)
                elif mode == "failed-write":
                    args[3][1]["event"] = "failed"
                else:
                    args[4][1].update(started_us=501, ended_us=506)
                self.assertIsNone(check.debt_receipt(*args))

    def test_live_socket_roster_requires_all_actual_endpoints_and_readbacks(self):
        peers = {"127.1.0.1", "127.1.0.2", "127.1.0.3"}
        daemon = [{"peer": peer, "cookie": index + 1, "send_buffer": 8192, "notsent_lowat": 4096,
                   "local": "127.0.0.1:17986", "remote": f"{peer}:1234"} for index, peer in enumerate(sorted(peers))]
        receivers = [{"peer": row["peer"], "cookie": row["cookie"] + 10, "receive_buffer": 8192,
                      "local": row["remote"], "remote": row["local"]} for row in daemon]
        check.socket_roster(daemon, receivers, peers)
        for mode in ("missing", "readback", "endpoint", "cookie", "lowat"):
            with self.subTest(mode=mode):
                broken = copy.deepcopy(receivers)
                server = copy.deepcopy(daemon)
                if mode == "missing":
                    broken.pop()
                elif mode == "readback":
                    broken[0]["receive_buffer"] = 4096
                elif mode == "endpoint":
                    broken[0]["local"] = "127.1.0.99:1234"
                elif mode == "cookie":
                    broken[0]["cookie"] = server[0]["cookie"]
                else:
                    server[0]["notsent_lowat"] = 8192
                with self.assertRaises(ValueError):
                    check.socket_roster(server, broken, peers)

    def test_send_buffer_limited_delta_is_an_independent_kernel_witness(self):
        args = fixture()
        for row in args[4]:
            row["sndbuf_limited_us"] = row["rwnd_limited_us"]
            row["rwnd_limited_us"] = 0
        self.assertIsNotNone(check.debt_receipt(*args))

    def test_ss_units_cookie_and_absent_zero_fields(self):
        raw = "State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\nESTAB 0 4096 127.0.0.1:17986 127.1.0.2:123 uid:1000 ino:1 sk:11\n cubic rwnd_limited:1.25ms(2.0%) sndbuf_limited:2us(1.0%) notsent:4096\nESTAB 0 0 127.0.0.1:17986 127.1.0.1:124 sk:12\n cubic\n"
        rows = check.ss_rows(raw, 10, 20)
        self.assertEqual(rows[0]["cookie"], 17)
        self.assertEqual(rows[0]["rwnd_limited_us"], 1250)
        self.assertEqual(rows[0]["sndbuf_limited_us"], 2)
        self.assertEqual(rows[1]["rwnd_limited_us"], 0)

    def test_refusal_only_on_retry_path_is_counted(self):
        args = fixture()
        args[0][-1]["markers"].update(retry_attempts=1, retry_refused=1)
        # The old event-only count saw no flush-path refusal event here.
        self.assertFalse(any(row["event"] == "marker_refused" for row in args[0]))
        result = check.debt_receipt(*args)
        self.assertEqual(result["marker_refusals"], 1)
        self.assertEqual(result["marker_refusals_by_site"], {"flush": 0, "retry": 1, "initial": 0, "refresh": 0})

    def test_missing_retry_or_any_send_site_counter_is_invalid(self):
        for name in check.MARKER_COUNTERS:
            for position in range(4):
                with self.subTest(counter=name, position=position):
                    args = fixture()
                    del args[0][position]["markers"][name]
                    with self.assertRaisesRegex(ValueError, "missing terminal-marker send-site counter"):
                        check.debt_receipt(*args)
                    with self.assertRaisesRegex(ValueError, "missing terminal-marker send-site counter"):
                        check.validate_feed(args[0], {"127.1.0.2"})
        args = fixture()
        del args[0][0]["markers"]
        with self.assertRaisesRegex(ValueError, "missing terminal-marker send-site counter"):
            check.debt_receipt(*args)

    def test_send_site_counter_decrease_is_invalid(self):
        args = fixture()
        args[0][1]["markers"].update(retry_attempts=2)
        with self.assertRaisesRegex(ValueError, "nonmonotone terminal-marker"):
            check.debt_receipt(*args)

    def test_kernel_counter_decrease_is_invalid(self):
        args = fixture()
        args[4][1]["rwnd_limited_us"] = 0
        with self.assertRaisesRegex(ValueError, "nonmonotone"):
            check.debt_receipt(*args)


def forced_feed():
    """Debtor rows of a forced cell: refusal while paused, tick send after resume."""
    def row(event, at, owed=1, capacity=4096, **markers):
        value = feed(event, at, owed=0, rows=0)
        value.update(owed=owed, capacity=capacity)
        value["markers"].update(markers)
        return value
    refused = dict(refresh_attempts=1, refresh_refused=1)
    return [row("sample", 50, owed=0, capacity=4096),
            row("data_admitted", 95, capacity=0),
            row("refresh_refused", 96, capacity=0, **refused),
            row("retry_refused", 1_000_096, capacity=0, retry_attempts=1, retry_refused=1, **refused),
            row("sample", 2_100_000, capacity=4096, retry_attempts=1, retry_refused=1, **refused),
            row("retry_offer", 2_199_999, retry_attempts=1, retry_refused=1, **refused),
            row("retry_sent", 2_200_000, owed=0, retry_attempts=2, retry_refused=1, **refused)]


def feed(event, at, root=0, revision=1, rows=0, stamp=10, **fields):
    row = {"event": event, "wall_us": at, "root": root, "revision": revision, "rows": rows,
           "peer": "127.1.0.2", "session": 7, "record_session": 7, "channel": 1, "channel_match": True,
           "complete": True, "current": True, "owed": 1, "dirty": False, "capacity": 4095, "max_capacity": 4096,
           "target_group": 1, "table_stamp": stamp, "markers": {name: 0 for name in check.MARKER_COUNTERS}}
    row.update(fields)
    return row


RESUME, UNFILL = 2_000_000, 3_000_000  # controller wall-clock dispatches, microseconds


class ForcedRefusalChecks(unittest.TestCase):
    def test_refusal_drain_and_tick_clocks(self):
        rows = forced_feed()
        refusal = check.refusal_witness(rows, "127.1.0.2", 70)
        result = check.fallback(rows, refusal, RESUME, UNFILL)
        self.assertEqual((result["drain_us"], result["tick_us"], result["sent_event"], result["retry_refusals"]),
                         (100_000, 200_000, "retry_sent", 1))
        self.assertTrue(check.fallback_within_bar(result))

    def test_forced_cell_without_a_refusal_is_invalid(self):
        rows = [row for row in forced_feed() if row["event"] != "refresh_refused"]
        with self.assertRaisesRegex(ValueError, "no refused refresh-site marker send"):
            check.refusal_witness(rows, "127.1.0.2", 70)
        for field, value in (("capacity", 1), ("owed", 0), ("current", False)):
            with self.subTest(field=field):
                rows = forced_feed()
                rows[2][field] = value
                with self.assertRaisesRegex(ValueError, "refusal is not a full channel"):
                    check.refusal_witness(rows, "127.1.0.2", 70)

    def test_missing_refresh_refusal_counter_is_invalid(self):
        for position in range(len(forced_feed())):
            with self.subTest(position=position):
                rows = forced_feed()
                del rows[position]["markers"]["refresh_refused"]
                with self.assertRaisesRegex(ValueError, "missing terminal-marker send-site counter"):
                    check.validate_feed(rows, {"127.1.0.2"})
                with self.assertRaisesRegex(ValueError, "missing terminal-marker send-site counter"):
                    check.fallback(rows, forced_feed()[2] if position != 2 else rows[2], RESUME, UNFILL)

    def test_skipping_the_first_eligible_retry_offer_fails(self):
        for later_capacity in (4096, 0):
            with self.subTest(later_capacity=later_capacity):
                rows = forced_feed()
                refusal = check.refusal_witness(rows, "127.1.0.2", 70)
                first = dict(rows[-2], wall_us=2_199_990)
                rows[-2]["capacity"] = later_capacity
                rows.insert(-2, first)
                result = check.fallback(rows, refusal, RESUME, UNFILL)
                self.assertLess(result["tick_us"], 1_000_000 + result["drain_us"], "the former timing bar would pass")
                self.assertFalse(check.fallback_within_bar(result))

    def test_capacity_freed_after_the_retry_offer_snapshot_passes(self):
        rows = forced_feed()
        rows[-2]["capacity"] = rows[-1]["capacity"] = 0
        empty = rows.pop(4)
        empty.update(wall_us=2_300_000, owed=0, markers=dict(rows[-1]["markers"]))
        rows.append(empty)
        rows.insert(3, dict(rows[3], event="retry_offer", wall_us=1_000_095,
                            markers=dict(rows[2]["markers"])))
        result = check.fallback(rows, check.refusal_witness(rows, "127.1.0.2", 70), RESUME, UNFILL)
        self.assertLess(result["tick_us"], result["drain_us"])
        self.assertEqual(result["eligible_offer_us"], rows[-3]["wall_us"])
        self.assertTrue(check.fallback_within_bar(result))

    def test_retry_send_before_the_drain_sample_passes(self):
        rows = forced_feed()
        rows[4]["wall_us"] = 2_300_000
        rows[4]["owed"] = 0
        rows[4]["markers"] = dict(rows[-1]["markers"])
        rows.append(rows.pop(4))
        result = check.fallback(rows, check.refusal_witness(rows, "127.1.0.2", 70), RESUME, UNFILL)
        self.assertLess(result["tick_us"], result["drain_us"])
        self.assertTrue(check.fallback_within_bar(result))

    def test_retry_before_resume_passes_with_a_post_resume_drain(self):
        rows = forced_feed()
        rows[-2]["wall_us"], rows[-1]["wall_us"] = RESUME - 2, RESUME - 1
        rows[4]["owed"] = 0
        rows[4]["markers"] = dict(rows[-1]["markers"])
        rows.append(rows.pop(4))
        result = check.fallback(rows, check.refusal_witness(rows, "127.1.0.2", 70), RESUME, UNFILL)
        self.assertLess(result["tick_us"], 0)
        self.assertTrue(check.fallback_within_bar(result))

    def test_markers_settled_outside_the_tick_fail(self):
        for event in ("refresh_sent", "sample"):
            with self.subTest(event=event):
                rows = forced_feed()
                rows[-1]["event"] = event
                result = check.fallback(rows, check.refusal_witness(rows, "127.1.0.2", 70), RESUME, UNFILL)
                self.assertFalse(check.fallback_within_bar(result))
        rows = forced_feed()[:-1]
        result = check.fallback(rows, check.refusal_witness(rows, "127.1.0.2", 70), RESUME, UNFILL)
        self.assertIsNone(result["sent_event"])
        self.assertFalse(check.fallback_within_bar(result))

    def test_missing_drain_clock_is_invalid(self):
        for mode in ("absent", "not-empty", "after-unfill", "before-resume"):
            with self.subTest(mode=mode):
                rows = forced_feed()
                if mode == "absent":
                    del rows[4]
                elif mode == "not-empty":
                    rows[4]["capacity"] = 4095
                elif mode == "after-unfill":
                    rows[4]["wall_us"] = UNFILL + 1
                else:
                    rows[4]["wall_us"] = RESUME - 1
                with self.assertRaisesRegex(ValueError, "missing drain clock"):
                    check.fallback(rows, rows[2], RESUME, UNFILL)

    def test_fill_withdrawn_before_the_fallback_send_is_invalid(self):
        rows = forced_feed()
        refusal = check.refusal_witness(rows, "127.1.0.2", 70)
        # Unfill dispatched right after resume, before the drain and the tick's send.
        with self.assertRaisesRegex(ValueError, "fill withdrawn before the fallback send"):
            check.fallback(rows, refusal, RESUME, RESUME + 300)

    def test_refusal_after_resume_is_invalid(self):
        rows = forced_feed()
        with self.assertRaisesRegex(ValueError, "refusal does not precede"):
            check.fallback(rows, rows[2], 90, UNFILL)


class TimingMedianChecks(unittest.TestCase):
    def rows(self, candidate):
        return [{"arm": arm, "churn-applied-seconds": value, "convergence-seconds": value}
                for arm, value in (("private", 1.0), ("candidate", candidate)) * 3]

    def test_no_refusal_timing_ratio_over_bar_fails(self):
        self.assertTrue(all(field["pass"] for field in check.timing_medians(self.rows(1.03), 1.03).values()))
        self.assertFalse(any(field["pass"] for field in check.timing_medians(self.rows(1.0301), 1.03).values()))

    def test_each_field_is_compared_separately(self):
        rows = self.rows(1.0)
        for row in rows:
            if row["arm"] == "candidate":
                row["convergence-seconds"] = 3.6
        result = check.timing_medians(rows, 1.03)
        self.assertTrue(result["churn-applied-seconds"]["pass"])
        self.assertFalse(result["convergence-seconds"]["pass"])


WORKLOAD = (0.0, 2.0, (-1, 3))  # load dispatch, finish completion, physical cell


def series():
    return [{"scheduled": i * .05, "at": i * .05 + .001, "status": 200, "seconds": .199999} for i in range(41)]


class ReadinessAndWireChecks(unittest.TestCase):
    def test_every_settlement_duty_and_every_reset_cause_must_be_zero(self):
        settled = {name: 0 for name in ("dirty", "owing", "recovery_pending", "marker_debt", "pending_resets", "retained_recovery", "completion_receipts",
                                       "refresh_pending", "eor_pending", "protocol_obligations")}
        self.assertTrue(check.settled(settled))
        for name in settled:
            with self.subTest(duty=name):
                self.assertFalse(check.settled({**settled, name: 1}))
        resets = {name: 0 for name in ("peer_limit", "daemon_limit", "allocation_failure", "capture_unavailable", "admission_invariant")}
        self.assertTrue(check.reset_free(resets))
        for name in resets:
            with self.subTest(cause=name):
                self.assertFalse(check.reset_free({**resets, name: 1}))
        with self.assertRaises(ValueError):
            check.reset_free({**resets, "unknown": 0})

    def test_readiness_boundaries_and_errors(self):
        rows = series()
        self.assertTrue(check.readiness(rows, *WORKLOAD))
        for status, seconds in ((503, .01), (0, .01), (200, .2)):
            with self.subTest(status=status, seconds=seconds):
                bad = copy.deepcopy(rows)
                bad[1].update(status=status, seconds=seconds)
                self.assertFalse(check.readiness(bad, *WORKLOAD))
        for field, value in (("at", .1), ("scheduled", .15)):
            with self.subTest(field=field):
                bad = copy.deepcopy(rows)
                bad[1][field] = value
                with self.assertRaises(ValueError):
                    check.readiness(bad, *WORKLOAD)

    def test_readiness_endpoints_allow_at_most_one_cadence(self):
        rows = series()
        self.assertTrue(check.readiness(rows[1:-1], *WORKLOAD))
        for name, bad, reason in (("start", rows[2:], "starts after"), ("end", rows[:-2], "ends before")):
            with self.subTest(edge=name):
                with self.assertRaisesRegex(ValueError, reason):
                    check.readiness(bad, *WORKLOAD)

    def test_common_shift_of_readiness_clock_is_invalid(self):
        for shift, reason in ((.5, "starts after the workload phase"), (-.5, "ends before the workload phase")):
            with self.subTest(shift=shift):
                rows = series()
                for row in rows:
                    row["scheduled"] += shift
                    row["at"] += shift
                with self.assertRaisesRegex(ValueError, reason):
                    check.readiness(rows, *WORKLOAD)

    def test_truncated_readiness_series_is_invalid(self):
        for edge, rows, reason in (("start", series()[10:], "starts after the workload phase"),
                                   ("end", series()[:-10], "ends before the workload phase")):
            with self.subTest(edge=edge):
                with self.assertRaisesRegex(ValueError, reason):
                    check.readiness(rows, *WORKLOAD)

    def test_one_sample_readiness_series_is_invalid(self):
        for position, reason in ((0, "ends before the workload phase"), (-1, "starts after the workload phase")):
            with self.subTest(position=position):
                with self.assertRaisesRegex(ValueError, reason):
                    check.readiness([series()[position]], *WORKLOAD)

    def test_readiness_outside_physical_cell_is_invalid(self):
        start, end, _ = WORKLOAD
        for cell, reason in (((.01, 3), "workload phase escapes"), ((-1, 1.99), "workload phase escapes"),
                             ((-1, 2.0005), "readiness sample outside")):
            with self.subTest(cell=cell):
                with self.assertRaisesRegex(ValueError, reason):
                    check.readiness(series(), start, end, cell)

    def test_raw_wire_keeps_exact_update_bytes_and_checks_protocol_scope(self):
        update = b"\xff" * 16 + b"\x00\x17\x02" + bytes(4)
        keepalive = b"\xff" * 16 + b"\x00\x13\x04"
        self.assertEqual(check.raw_updates(keepalive + update), update)
        for raw in (update[:-1], b"\xff" * 16 + b"\x00\x17\x05" + b"\x00\x19\x02\x46", keepalive + b"x"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    check.raw_updates(raw)


if __name__ == "__main__":
    unittest.main()


class SamplerStop(unittest.TestCase):
    def test_sampler_issues_the_slot_due_before_stop(self):
        from concurrent.futures import ThreadPoolExecutor
        import json
        from pathlib import Path
        import queue
        import tempfile
        import threading
        from types import SimpleNamespace
        from unittest import mock
        import terminal

        class Base:
            def probe(self, scheduled):
                return {"status": 200, "at": scheduled, "scheduled": scheduled}

        sampler_type = terminal.readiness_type(SimpleNamespace(Readiness=Base, ThreadPoolExecutor=ThreadPoolExecutor))
        with tempfile.TemporaryDirectory() as temporary:
            sampler = sampler_type.__new__(sampler_type)
            sampler.path, sampler.results = Path(temporary) / "readiness.jsonl", queue.Queue()
            sampler.stop_event = threading.Event()
            sampler.thread = mock.Mock(is_alive=mock.Mock(return_value=False))
            clock = {"now": 0.}

            def sleep(_):
                # The stop request lands between two loop checks, after the next slot was due.
                clock["now"] = round(clock["now"] + .006, 6)
                if clock["now"] == .054:
                    sampler.stop()

            with mock.patch.object(terminal.time, "monotonic", side_effect=lambda: clock["now"]), \
                 mock.patch.object(terminal.time, "sleep", side_effect=sleep):
                sampler.run()
            scheduled = [json.loads(line)["scheduled"] for line in sampler.path.read_text().splitlines()]
            self.assertEqual(sorted(scheduled), [0., .05])
            self.assertGreaterEqual(max(scheduled), sampler.stop_at - .05)


class ForcedResumeOrder(unittest.TestCase):
    def test_retry_send_waits_for_the_empty_channel_sample(self):
        from types import SimpleNamespace
        from unittest import mock
        import terminal

        for events in (("retry_sent", "sample"), ("sample", "retry_sent")):
            with self.subTest(events=events):
                controller = object.__new__(terminal.controller_type(SimpleNamespace(
                    Readiness=type("Readiness", (), {"issues_slot_due_before_stop": True}), Controller=object)))
                controller.arm, controller.feed = "candidate", []
                polls = []

                def poll(events=events, polls=polls, controller=controller):
                    event = events[len(polls)]
                    controller.feed.append(feed(event, RESUME + len(polls) + 1,
                                                capacity=4096 if event == "sample" else 4095, owed=0))
                    polls.append(event)

                controller.poll = poll
                with mock.patch.object(terminal.time, "sleep"):
                    self.assertTrue(controller.fallback_send(RESUME, {"peer": "127.1.0.2", "refusal": {"wall_us": 96}}, 60))
                self.assertEqual(polls, list(events), "a retry send alone does not prove the channel drained")

    def test_private_waits_for_a_post_resume_empty_sample(self):
        from types import SimpleNamespace
        from unittest import mock
        import terminal

        controller = object.__new__(terminal.controller_type(SimpleNamespace(
            Readiness=type("Readiness", (), {"issues_slot_due_before_stop": True}), Controller=object)))
        controller.arm, controller.feed = "private", [feed("sample", RESUME - 1, capacity=4096, owed=0)]
        polls = []

        def poll():
            polls.append(True)
            if len(polls) == 2:
                controller.feed.append(feed("sample", RESUME + 1, capacity=4096, owed=0))

        controller.poll = poll
        with mock.patch.object(terminal.time, "sleep"):
            self.assertTrue(controller.fallback_send(RESUME, {"peer": "127.1.0.2", "refusal": {"wall_us": 96}}, 60))
        self.assertEqual(len(polls), 2)

    def test_retry_may_precede_resume_but_must_follow_this_refusal(self):
        from types import SimpleNamespace
        from unittest import mock
        import terminal

        full = {"peer": "127.1.0.2", "refusal": {"wall_us": 96}}
        for retry, expected_polls in ((95, 2), (97, 1)):
            with self.subTest(retry=retry):
                controller = object.__new__(terminal.controller_type(SimpleNamespace(
                    Readiness=type("Readiness", (), {"issues_slot_due_before_stop": True}), Controller=object)))
                controller.arm, controller.feed = "candidate", [feed("retry_sent", retry, owed=0)]
                polls = []

                def poll(controller=controller, polls=polls):
                    polls.append(True)
                    controller.feed.append(feed("sample" if len(polls) == 1 else "retry_sent",
                                                RESUME + len(polls), capacity=4096, owed=0))

                controller.poll = poll
                with mock.patch.object(terminal.time, "sleep"):
                    self.assertTrue(controller.fallback_send(RESUME, full, 60))
                self.assertEqual(len(polls), expected_polls)

    def run_order(self, arm, sent=True):
        from types import SimpleNamespace
        import terminal

        calls = []

        class Controller:
            last_completion, last_command_start = 5.0, {"wall_us": 123}

            def command(self, name, *args):
                calls.append(name)

            def fallback_send(self, after, full, seconds):
                calls.append(("wait", after, full["peer"], seconds))
                return True if sent else None

        failures = []
        q = SimpleNamespace(accept=lambda ok, reason: ok or failures.append(reason))
        started = terminal.resume_after_fallback(Controller(), q, {"peer": "127.1.0.2", "refusal": None})
        calls.append("terminal-unfill")
        return calls, started, failures

    def test_both_arms_withdraw_the_fill_only_after_the_drain_wait(self):
        import terminal

        for arm in ("candidate", "private"):
            with self.subTest(arm=arm):
                calls, started, failures = self.run_order(arm)
                self.assertEqual(calls, ["resume", ("wait", 123, "127.1.0.2", terminal.BARS["convergence_seconds"]),
                                         "terminal-unfill"])
                self.assertEqual((started, failures), (5.0, []))
                calls, _, failures = self.run_order(arm, sent=False)
                self.assertEqual(failures, ["marker retry/channel drain exceeded the convergence bar"])


PEERS = ("127.1.0.1", "127.1.0.2", "127.1.0.3")
REFRESH, DISPATCH = 5_000_000, 5_100_500  # CLOCK_MONOTONIC µs


def receipts(applied=(5_150_000, 5_170_000, 5_160_000), wall_shift=0):
    """Two input receipts per client; the wall clock may step independently."""
    rows = []
    for peer, mono in zip(PEERS, applied):
        rows.append({"peer": peer, "wall_us": 900 + wall_shift, "mono_us": 4_000_000})
        rows.append({"peer": peer, "wall_us": mono - 4_000_000 + wall_shift, "mono_us": mono})
    return rows


def replays(monos=(5_040_000, 5_120_000, 5_210_000), rows=20000):
    return [feed("data_admitted", 1, rows=rows, peer=peer, mono_us=mono) for peer, mono in zip(PEERS, monos)]


class OverlapTimingChecks(unittest.TestCase):
    def test_churn_applied_is_dispatch_to_the_last_monotonic_receipt(self):
        # A wall-clock step between dispatch and the receipts must not move
        # the metric: it is read on CLOCK_MONOTONIC only.
        value = check.churn_applied(receipts(wall_shift=-3_000_000), PEERS, DISPATCH)
        self.assertEqual(value, (5_170_000 - DISPATCH) / 1e6)

    def test_missing_or_zero_receipt_clock_is_invalid(self):
        for stamp in (None, 0, 1.5):
            with self.subTest(stamp=stamp):
                rows = receipts()
                if stamp is None:
                    rows[3].pop("mono_us")
                else:
                    rows[3]["mono_us"] = stamp
                with self.assertRaisesRegex(ValueError, "missing CLOCK_MONOTONIC stamp"):
                    check.churn_applied(rows, PEERS, DISPATCH)

    def test_receipts_must_bracket_the_dispatch(self):
        for applied in ((DISPATCH, 5_170_000, 5_160_000), (DISPATCH - 1, 5_170_000, 5_160_000)):
            with self.subTest(applied=applied):
                with self.assertRaisesRegex(ValueError, "do not bracket"):
                    check.churn_applied(receipts(applied), PEERS, DISPATCH)
        with self.assertRaisesRegex(ValueError, "missing or duplicate"):
            check.churn_applied(receipts()[1:], PEERS, DISPATCH)

    def test_dispatch_outside_the_predeclared_window_is_invalid(self):
        for phase, ok in ((99_999, False), (100_000, True), (102_000, True), (102_001, False)):
            with self.subTest(phase=phase):
                call = lambda phase=phase: check.overlap_phase(  # noqa: E731
                    replays(), PEERS, 20000, REFRESH, REFRESH + phase, 100_000, 2_000)
                if ok:
                    self.assertEqual(call()["phase_us"], phase)
                else:
                    with self.assertRaisesRegex(ValueError, "outside the predeclared phase window"):
                        call()

    def test_replays_drained_before_dispatch_are_invalid(self):
        result = check.overlap_phase(replays(), PEERS, 20000, REFRESH, DISPATCH, 100_000, 2_000)
        self.assertEqual(result, {"phase_us": 100_500, "replays_before_dispatch": 1,
                                  "replay_residue_us": 5_210_000 - DISPATCH})
        with self.assertRaisesRegex(ValueError, "after the refresh replays drained"):
            check.overlap_phase(replays((5_040_000, 5_080_000, DISPATCH)), PEERS, 20000, REFRESH, DISPATCH,
                                100_000, 2_000)

    def test_replay_completions_must_be_complete_unique_and_stamped(self):
        for defect in ("missing", "duplicate", "unstamped", "short"):
            with self.subTest(defect=defect):
                rows = replays()
                if defect == "missing":
                    rows.pop(0)
                    message = "missing refresh replay completion"
                elif defect == "duplicate":
                    rows.append(dict(rows[2]))
                    message = "duplicate refresh replay completion"
                elif defect == "unstamped":
                    rows[1].pop("mono_us")
                    message = "missing CLOCK_MONOTONIC stamp"
                else:
                    rows[1]["rows"] = 19999
                    message = "missing refresh replay completion"
                with self.assertRaisesRegex(ValueError, message):
                    check.overlap_phase(rows, PEERS, 20000, REFRESH, DISPATCH, 100_000, 2_000)


class OverlapDispatch(unittest.TestCase):
    def test_churn_leaves_at_refresh_plus_the_phase_without_observation(self):
        import terminal

        calls = []

        class Controller:
            last_command_start = None

            def command(self, name, *args):
                calls.append(name)
                self.last_command_start = {"command": name, "mono_us": 7_000_000}
                return {"command": name}

            def dispatch_at(self, mono_us):
                calls.append(("dispatch_at", mono_us))

            def poll(self):
                calls.append("poll")

            def before_churn(self, *args):
                calls.append("before_churn")

        self.assertEqual(terminal.dispatch_overlap_churn(Controller()), {"command": "terminal-churn"})
        self.assertEqual(calls, ["refresh", ("dispatch_at", 7_000_000 + terminal.BARS["churn_phase_us"]),
                                 "terminal-churn"])

    def test_dispatch_at_returns_on_the_target_monotonic_microsecond(self):
        from types import SimpleNamespace
        from unittest import mock

        import terminal

        clock = {"ns": 1_000_000_000}
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            clock["ns"] += int(seconds * 1e9)

        def monotonic_ns():
            clock["ns"] += 1_000  # each read costs 1 µs of spin
            return clock["ns"]

        controller = object.__new__(terminal.controller_type(SimpleNamespace(
            Readiness=type("Readiness", (), {"issues_slot_due_before_stop": True}),
            Controller=object)))
        with mock.patch.object(terminal.time, "monotonic_ns", monotonic_ns), \
             mock.patch.object(terminal.time, "sleep", sleep):
            controller.dispatch_at(1_000_000 + 100_000)
        self.assertGreaterEqual(clock["ns"] // 1000, 1_100_000)
        self.assertLess(clock["ns"] // 1000, 1_100_000 + 10)
        self.assertEqual(len(sleeps), 1)
        self.assertLessEqual(sleeps[0], .1)
