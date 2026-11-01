import copy
import unittest

import check


def feed(event, at, root=0, revision=1, rows=0, stamp=10):
    return {"event": event, "wall_us": at, "root": root, "revision": revision, "rows": rows,
            "peer": "127.1.0.2", "session": 7, "record_session": 7, "channel": 1, "channel_match": True,
            "complete": True, "current": True, "owed": 1, "dirty": False, "capacity": 4095, "max_capacity": 4096,
            "target_group": 1, "table_stamp": stamp, "markers": {name: 0 for name in check.MARKER_COUNTERS}}


def fixture():
    feeds = [feed("data_admitted", 100, rows=20000), feed("root_before", 200, root=1),
             feed("data_admitted", 300, root=1, rows=4, stamp=11), feed("sample", 500, stamp=11)]
    work = {name: 4 for name in check.COUNTERS}
    work.update(id=1, wall_us=320, keys=4, debtors_before=2, prepare_attempts=2, projection_walks=4,
                current_walks=2, old_walks=2, success_walks=2, elapsed_us=17)
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
        self.assertEqual(result["marker_refusals_by_site"], {"flush": 0, "retry": 0, "initial": 0})
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
        self.assertEqual(result["marker_refusals_by_site"], {"flush": 0, "retry": 1, "initial": 0})

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


WORKLOAD = (0.0, 2.0, (-1, 3))  # load dispatch, finish completion, physical cell


def series():
    return [{"scheduled": i * .05, "at": i * .05 + .001, "status": 200, "seconds": .199999} for i in range(41)]


class ReadinessAndWireChecks(unittest.TestCase):
    def test_every_settlement_duty_and_every_reset_cause_must_be_zero(self):
        settled = {name: 0 for name in ("dirty", "marker_debt", "pending_resets", "retained_recovery", "completion_receipts",
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
