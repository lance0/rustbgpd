#!/usr/bin/env python3
import importlib.util
import socket
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

PATH = Path(__file__).with_name("raw_bridge_skew.py")
SPEC = importlib.util.spec_from_file_location("raw_bridge_skew", PATH)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)

BRIDGE = bytes.fromhex(
    "380000001c00000000000000000000000700000016000000020000000a000200"
    "02000000000100000800090063000000060005000a000000"
)
IPV4 = bytes.fromhex(
    "4c0000001c000000000000000000000002000000630000000200000008000100"
    "c000020a0a000200020000000001000008000400000000001400030000000000"
    "000000000000000001000000"
)
IPV6 = bytes.fromhex(
    "580000001c00000000000000000000000a000000630000000200000014000100"
    "20010db80010000000000000000000020a000200020000000002000008000400"
    "000000001400030000000000000000000000000001000000"
)
OVERRUN = bytes.fromhex("10000000040000000000000000000000")
REQUEST_CORRELATED_FAILED = bytes.fromhex(
    "400000001c0000000000000018000000020000000200000020000000"
    "08000100c0000202080004000000000014000300000000000000000000000000"
    "00000000"
)


def message(kind, family, ifindex, attrs=b"", seq=0, pid=0, state=2):
    body = struct.pack("=BBHiHBB", family, 0, 0, ifindex, state, 0, 0) + attrs
    raw = struct.pack("=IHHII", 16 + len(body), kind, 0, seq, pid) + body
    return raw + bytes((-len(raw)) % 4)


class ParserTests(unittest.TestCase):
    def test_supplied_literal_bridge_ipv4_and_ipv6_vectors(self):
        bridge, ipv4, ipv6 = MOD.parse_datagram(BRIDGE + IPV4 + IPV6, 0, 0, 44)
        self.assertEqual(
            (bridge.family, bridge.ifindex, bridge.vlan, bridge.master, bridge.lladdr),
            (7, 22, 10, 99, "02:00:00:00:00:01"),
        )
        self.assertEqual(
            (ipv4.family, ipv4.ifindex, ipv4.dst, ipv4.lladdr),
            (2, 99, "192.0.2.10", "02:00:00:00:00:01"),
        )
        self.assertEqual(
            (ipv6.family, ipv6.ifindex, ipv6.dst, ipv6.lladdr),
            (10, 99, "2001:db8:10::2", "02:00:00:00:00:02"),
        )
        self.assertEqual({event.timestamp_ns for event in (bridge, ipv4, ipv6)}, {44})

    def test_delete_is_retained_as_a_distinct_message(self):
        deleted = bytearray(IPV6)
        struct.pack_into("=H", deleted, 4, MOD.RTM_DELNEIGH)
        event = MOD.parse_datagram(bytes(deleted), 0, 0, 7)[0]
        self.assertEqual((event.message, event.dst), ("delete", "2001:db8:10::2"))

    def test_fail_closed_framing_sender_sequence_overrun_and_truncation(self):
        cases = [
            (IPV4, 4, 0),
            (IPV4, 0, MOD.MSG_TRUNC),
            (message(MOD.RTM_NEWNEIGH, socket.AF_INET, 12, seq=1), 0, 0),
            (OVERRUN, 0, 0),
            (b"short", 0, 0),
            (struct.pack("=IHHII", 999, MOD.RTM_NEWNEIGH, 0, 0, 0), 0, 0),
            (IPV4[:-1], 0, 0),
        ]
        for vector, sender, flags in cases:
            with self.subTest(sender=sender, flags=flags, length=len(vector)):
                with self.assertRaises(MOD.MeasurementError):
                    MOD.parse_datagram(vector, sender, flags, 1)

    def test_relevant_header_pid_and_sequence_are_strict(self):
        for seq, pid in ((1, 0), (0, 7)):
            with self.subTest(seq=seq, pid=pid):
                with self.assertRaisesRegex(
                    MOD.MeasurementError, "nonzero sequence|unexpected header pid"
                ):
                    MOD.parse_datagram(
                        message(
                            MOD.RTM_NEWNEIGH,
                            socket.AF_INET,
                            12,
                            seq=seq,
                            pid=pid,
                        ),
                        0,
                        0,
                        1,
                    )

    def test_kernel_request_correlated_failed_invalidation_is_narrow(self):
        event = MOD.parse_datagram(REQUEST_CORRELATED_FAILED, 0, 0, 9)[0]
        self.assertEqual(
            (event.message, event.family, event.ifindex, event.state, event.dst),
            ("new", socket.AF_INET, 2, MOD.NUD_FAILED, "192.0.2.2"),
        )
        self.assertIsNone(event.lladdr)

        valid_state = bytearray(REQUEST_CORRELATED_FAILED)
        struct.pack_into("=H", valid_state, 24, 2)
        deleted = bytearray(REQUEST_CORRELATED_FAILED)
        struct.pack_into("=H", deleted, 4, MOD.RTM_DELNEIGH)
        sequenced = bytearray(REQUEST_CORRELATED_FAILED)
        struct.pack_into("=I", sequenced, 8, 1)
        dst = struct.pack("=HH", 8, MOD.NDA_DST) + socket.inet_aton("192.0.2.2")
        lladdr = struct.pack("=HH", 10, MOD.NDA_LLADDR) + bytes.fromhex("020000000001") + b"\0\0"
        with_lladdr = message(
            MOD.RTM_NEWNEIGH,
            socket.AF_INET,
            2,
            attrs=dst + lladdr,
            pid=24,
            state=MOD.NUD_FAILED,
        )
        without_dst = message(
            MOD.RTM_NEWNEIGH,
            socket.AF_INET,
            2,
            pid=24,
            state=MOD.NUD_FAILED,
        )
        bridge_dst = (
            struct.pack("=HH", 10, MOD.NDA_DST)
            + bytes.fromhex("020000000001")
            + b"\0\0"
        )
        bridge_family = message(
            MOD.RTM_NEWNEIGH,
            MOD.AF_BRIDGE,
            2,
            attrs=bridge_dst,
            pid=24,
            state=MOD.NUD_FAILED,
        )
        for vector in (
            bytes(valid_state),
            bytes(deleted),
            bytes(sequenced),
            with_lladdr,
            without_dst,
            bridge_family,
        ):
            with self.subTest(vector=vector.hex()[:32]):
                with self.assertRaises(MOD.MeasurementError):
                    MOD.parse_datagram(vector, 0, 0, 10)


class BufferSocketFixture:
    def __init__(self, ordinary, forced=None, force_error=None):
        self.ordinary = ordinary
        self.forced = forced
        self.force_error = force_error
        self.effective = 0
        self.options = []

    def setsockopt(self, level, option, value):
        self.options.append((level, option, value))
        if option == socket.SO_RCVBUF:
            self.effective = self.ordinary
        elif option == MOD.SO_RCVBUFFORCE:
            if self.force_error is not None:
                raise self.force_error
            self.effective = self.forced

    def getsockopt(self, _level, _option):
        return self.effective


class ReceiveCapacityTests(unittest.TestCase):
    def test_ordinary_receive_capacity_is_admitted_without_force(self):
        requested = 4096
        sock = BufferSocketFixture(ordinary=8192)
        capacity = MOD._admit_receive_capacity(sock, requested)
        self.assertEqual(capacity, MOD.ReceiveCapacity(requested, 8192, False))
        self.assertEqual(
            [option for _level, option, _value in sock.options],
            [socket.SO_RCVBUF],
        )

    def test_force_denial_is_fatal_before_capacity_admission(self):
        sock = BufferSocketFixture(
            ordinary=4096,
            force_error=PermissionError(1, "not permitted"),
        )
        with self.assertRaisesRegex(MOD.MeasurementError, "SO_RCVBUFFORCE failed"):
            MOD._admit_receive_capacity(sock, 4096)
        self.assertEqual(
            [option for _level, option, _value in sock.options],
            [socket.SO_RCVBUF, MOD.SO_RCVBUFFORCE],
        )

    def test_undersized_capacity_after_force_is_fatal(self):
        sock = BufferSocketFixture(ordinary=4096, forced=8191)
        with self.assertRaisesRegex(MOD.MeasurementError, "undersized"):
            MOD._admit_receive_capacity(sock, 4096)

    def test_force_success_records_effective_capacity(self):
        sock = BufferSocketFixture(ordinary=4096, forced=8192)
        capacity = MOD._admit_receive_capacity(sock, 4096)
        self.assertEqual(capacity, MOD.ReceiveCapacity(4096, 8192, True))


def fixture_event(token, timestamp):
    return MOD.Event(
        message="new",
        family=socket.AF_INET,
        ifindex=4,
        state=2,
        flags=0,
        dst=token,
        lladdr=None,
        vlan=None,
        master=None,
        nda_ifindex=None,
        timestamp_ns=timestamp,
    )


class BackgroundObserverTests(unittest.TestCase):
    def make_observer(self, decoder):
        source, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        return MOD.Observer._for_test(source, decoder), sender

    def test_receive_owner_continues_while_foreground_is_blocked(self):
        decoded = threading.Event()

        def decoder(data, _sender, _flags, timestamp):
            decoded.set()
            return [fixture_event(data.decode(), timestamp)]

        observer, sender = self.make_observer(decoder)
        try:
            sender.send(b"queued-during-foreground-work")
            self.assertTrue(decoded.wait(1))
            events = observer.synchronize()
            self.assertEqual([event.dst for event in events], ["queued-during-foreground-work"])
        finally:
            observer.close()
            sender.close()

    def test_delivery_order_is_receive_order(self):
        observer, sender = self.make_observer(
            lambda data, _sender, _flags, timestamp: [fixture_event(data.decode(), timestamp)]
        )
        try:
            sender.send(b"first")
            sender.send(b"second")
            events = observer.synchronize()
            self.assertEqual([event.dst for event in events], ["first", "second"])
            self.assertLessEqual(events[0].timestamp_ns, events[1].timestamp_ns)
        finally:
            observer.close()
            sender.close()

    def test_async_enobufs_after_apparent_completion_is_sticky(self):
        failed = threading.Event()

        def decoder(data, _sender, _flags, timestamp):
            if data == b"overflow":
                failed.set()
                raise MOD.MeasurementError("NETLINK_ROUTE ENOBUFS")
            return [fixture_event(data.decode(), timestamp)]

        observer, sender = self.make_observer(decoder)
        try:
            sender.send(b"complete")
            self.assertEqual(observer.receive(1)[0].dst, "complete")
            sender.send(b"overflow")
            self.assertTrue(failed.wait(1))
            with self.assertRaisesRegex(MOD.MeasurementError, "ENOBUFS"):
                observer.synchronize()
            with self.assertRaisesRegex(MOD.MeasurementError, "ENOBUFS") as caught:
                observer.close()
            combined = MOD._combine_errors(
                MOD.MeasurementError("foreground failed"),
                caught.exception,
                "observer shutdown",
            )
            self.assertIn("foreground failed", str(combined))
            self.assertIn("ENOBUFS", str(combined))
        finally:
            sender.close()

    def test_close_drains_and_joins_receive_owner(self):
        decoded = threading.Event()

        def decoder(data, _sender, _flags, timestamp):
            decoded.set()
            return [fixture_event(data.decode(), timestamp)]

        observer, sender = self.make_observer(decoder)
        sender.send(b"final")
        self.assertTrue(decoded.wait(1))
        events = observer.close()
        sender.close()
        self.assertEqual([event.dst for event in events], ["final"])
        self.assertFalse(observer._thread.is_alive())
        self.assertEqual(observer.socket.fileno(), -1)

    def test_simultaneous_source_and_control_readiness_drains_before_marker(self):
        real_select = MOD.select.select
        receiver_waiting = threading.Event()
        release_receiver = threading.Event()
        gated = False

        def gated_select(readable, writable, exceptional, timeout=None):
            nonlocal gated
            if (
                timeout is None
                and threading.current_thread().name == "raw-bridge-skew-netlink-receiver"
                and not gated
            ):
                gated = True
                receiver_waiting.set()
                if not release_receiver.wait(1):
                    raise RuntimeError("test receiver gate timed out")
            return real_select(readable, writable, exceptional, timeout)

        with mock.patch.object(MOD.select, "select", side_effect=gated_select):
            observer, sender = self.make_observer(
                lambda data, _sender, _flags, timestamp: [fixture_event(data.decode(), timestamp)]
            )
            self.assertTrue(receiver_waiting.wait(1))
            sender.send(b"before-marker")
            result = []
            errors = []

            def synchronize():
                try:
                    result.extend(observer.synchronize())
                except BaseException as exc:
                    errors.append(exc)

            foreground = threading.Thread(target=synchronize)
            foreground.start()
            self.assertTrue(real_select([observer._control_rx], [], [], 1)[0])
            release_receiver.set()
            foreground.join(1)
            self.assertFalse(foreground.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual([event.dst for event in result], ["before-marker"])
            observer.close()
            sender.close()
        self.assertFalse(
            any(
                thread.name == "raw-bridge-skew-netlink-receiver"
                for thread in threading.enumerate()
            )
        )

    def test_failed_reader_start_closes_control_fds_and_leaves_no_thread(self):
        source, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        source.close()
        control_tx, control_rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with mock.patch.object(MOD.socket, "socketpair", return_value=(control_tx, control_rx)):
            with self.assertRaises((OSError, ValueError)):
                MOD.Observer._for_test(source, lambda *_args: [])
        sender.close()
        self.assertEqual(control_tx.fileno(), -1)
        self.assertEqual(control_rx.fileno(), -1)
        self.assertFalse(
            any(
                thread.name == "raw-bridge-skew-netlink-receiver"
                for thread in threading.enumerate()
            )
        )

    def test_thread_start_failure_closes_every_owned_fd(self):
        source, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        control_tx, control_rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with (
            mock.patch.object(MOD.socket, "socketpair", return_value=(control_tx, control_rx)),
            mock.patch.object(
                MOD.threading.Thread, "start", side_effect=RuntimeError("cannot start")
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "cannot start"):
                MOD.Observer._for_test(source, lambda *_args: [])
        sender.close()
        self.assertEqual(source.fileno(), -1)
        self.assertEqual(control_tx.fileno(), -1)
        self.assertEqual(control_rx.fileno(), -1)
        self.assertFalse(
            any(
                thread.name == "raw-bridge-skew-netlink-receiver"
                for thread in threading.enumerate()
            )
        )


class PairingTests(unittest.TestCase):
    def setUp(self):
        self.expected = [
            {
                "sample_id": "s1",
                "profile": "fixture",
                "phase": "vlan-10-ipv4",
                "vlan": 10,
                "port_ifindex": 12,
                "bridge_ifindex": 4,
                "family": socket.AF_INET,
                "ip": "192.0.2.1",
                "mac": "02:00:00:00:00:01",
            }
        ]

    def event(self, family, timestamp, **kwargs):
        fields = dict(
            message="new",
            family=family,
            ifindex=4,
            state=2,
            flags=0,
            dst=None,
            lladdr=None,
            vlan=None,
            master=None,
            nda_ifindex=None,
            timestamp_ns=timestamp,
        )
        fields.update(kwargs)
        return MOD.Event(**fields)

    def test_first_new_pairs_duplicates_and_delete_are_explicit(self):
        pairer = MOD.Pairer(self.expected)
        pairer.add(
            self.event(
                MOD.AF_BRIDGE,
                100,
                ifindex=12,
                master=4,
                vlan=10,
                lladdr="02:00:00:00:00:01",
            )
        )
        pairer.add(
            self.event(
                socket.AF_INET,
                120,
                dst="192.0.2.1",
                lladdr="02:00:00:00:00:01",
            )
        )
        pairer.add(
            self.event(
                socket.AF_INET,
                125,
                dst="192.0.2.1",
                lladdr="02:00:00:00:00:01",
            )
        )
        pairer.add(
            self.event(
                socket.AF_INET,
                130,
                message="delete",
                dst="192.0.2.1",
                lladdr="02:00:00:00:00:01",
            )
        )
        row = pairer.rows()[0]
        self.assertEqual(
            (row["skew_ns"], row["duplicate_neighbor"], row["delete_events"]),
            (20, 1, 1),
        )
        self.assertEqual(row["missing_reason"], "")

    def test_wrong_identity_clock_regression_and_invalid_nud(self):
        pairer = MOD.Pairer(self.expected)
        pairer.add(
            self.event(
                socket.AF_INET,
                100,
                state=MOD.INVALID_NUD,
                dst="198.51.100.1",
                lladdr="02:00:00:00:00:01",
            )
        )
        self.assertEqual(pairer.wrong_tenant, 0)
        pairer.add(
            self.event(
                socket.AF_INET,
                101,
                dst="198.51.100.1",
                lladdr="02:00:00:00:00:01",
            )
        )
        self.assertEqual(pairer.wrong_tenant, 1)
        with self.assertRaises(MOD.MeasurementError):
            pairer.add(
                self.event(
                    socket.AF_INET,
                    99,
                    dst="192.0.2.1",
                    lladdr="02:00:00:00:00:01",
                )
            )

    def test_duplicate_event_identity_is_rejected(self):
        duplicate = {**self.expected[0], "sample_id": "s2"}
        with self.assertRaises(MOD.MeasurementError):
            MOD.Pairer([*self.expected, duplicate])

    def test_censor_freezes_missing_sides_and_late_duplicates(self):
        pairer = MOD.Pairer(self.expected)
        pairer.add(
            self.event(
                MOD.AF_BRIDGE,
                100,
                ifindex=12,
                master=4,
                vlan=10,
                lladdr="02:00:00:00:00:01",
            )
        )
        pairer.freeze(["s1"])
        pairer.add(
            self.event(
                socket.AF_INET,
                120,
                dst="192.0.2.1",
                lladdr="02:00:00:00:00:01",
            )
        )
        pairer.add(
            self.event(
                MOD.AF_BRIDGE,
                125,
                ifindex=12,
                master=4,
                vlan=10,
                lladdr="02:00:00:00:00:01",
            )
        )
        row = pairer.rows()[0]
        self.assertFalse(row["complete"])
        self.assertEqual(row["missing_reason"], "missing-neighbor")
        self.assertEqual(row["duplicate_fdb"], 0)
        self.assertEqual((row["late_neighbor"], row["late_fdb"]), (1, 1))

    def test_report_is_descriptive_split_by_family_and_timestamp_zero_is_present(self):
        pairer = MOD.Pairer(self.expected)
        pairer.add(
            self.event(
                MOD.AF_BRIDGE,
                0,
                ifindex=12,
                master=4,
                vlan=10,
                lladdr="02:00:00:00:00:01",
            )
        )
        pairer.add(
            self.event(
                socket.AF_INET,
                30,
                dst="192.0.2.1",
                lladdr="02:00:00:00:00:01",
            )
        )
        report = MOD.build_report(pairer.rows(), 1, 0)
        self.assertTrue(report["descriptive_only"])
        self.assertEqual(report["missing_fdb"], 0)
        self.assertEqual(report["absolute_skew"]["p99_9_ns"], 30)
        self.assertEqual(report["by_family"]["ipv4"]["complete"], 1)
        self.assertEqual(report["directions"]["fdb_first"]["count"], 1)
        with self.assertRaises(MOD.MeasurementError):
            MOD.build_report(pairer.rows(), 2, 0)
        with self.assertRaises(MOD.MeasurementError):
            MOD.build_report(pairer.rows(), 1, 1)
        with self.assertRaises(MOD.MeasurementError):
            MOD.build_report(pairer.rows(), 1, 0, 0, {"w_safe_ns": 50})


class PlanAndArtifactTests(unittest.TestCase):
    def test_plan_is_exactly_split_bounded_and_globally_unique(self):
        plan = MOD.deterministic_plan("burst-32")
        rows = plan["planned"]
        self.assertEqual(len(rows), 4000)
        self.assertEqual(plan["active_limit"], 32)
        self.assertEqual(plan["censor_seconds"], 5)
        self.assertEqual(plan["wall_seconds"], 1200)
        self.assertEqual(plan["schema"], 2)
        self.assertIsNone(plan["acceptance"])
        self.assertEqual(
            plan["observer"],
            {
                "post_freeze_retired_neighbors_max": 0,
                "so_rcvbuf_effective_bytes": None,
                "so_rcvbuf_forced": None,
                "so_rcvbuf_requested_bytes": 4 * 1024 * 1024,
            },
        )
        self.assertEqual(len({row["sample_id"] for row in rows}), 4000)
        self.assertEqual(len({row["mac"] for row in rows}), 4000)
        counts = {
            (vlan, family): sum(
                row["vlan"] == vlan and row["family"] == family for row in rows
            )
            for vlan in (10, 20)
            for family in (socket.AF_INET, socket.AF_INET6)
        }
        self.assertEqual(set(counts.values()), {1000})
        with self.assertRaises(MOD.MeasurementError):
            MOD.deterministic_plan("burst-8", 100, {"10": [110], "20": [210]})

    def test_receipt_has_closed_inventory_and_explicit_missing_row(self):
        run = MOD.deterministic_plan(
            "serial-1",
            receive_capacity=MOD.ReceiveCapacity(4 * 1024 * 1024, 8 * 1024 * 1024, False),
        )
        run["planned"] = run["planned"][:1]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "receipt"
            MOD.write_receipt(run, [], output)
            MOD.check_artifacts(output)
            sample = (output / "samples.csv").read_text().splitlines()[1]
            self.assertIn("missing-fdb-and-neighbor", sample)
            self.assertEqual(set(path.name for path in output.iterdir()), {
                "run.json", "samples.csv", "report.json"
            })

    def test_preview_capacity_cannot_be_published_as_a_runtime_receipt(self):
        run = MOD.deterministic_plan("serial-1")
        run["planned"] = run["planned"][:1]
        pairer = MOD.Pairer(run["planned"])
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "receipt"
            with self.assertRaisesRegex(MOD.MeasurementError, "undersized"):
                MOD.write_pairer_receipt(run, pairer, output)
            self.assertFalse(output.exists())


class NeighborRetirementTests(unittest.TestCase):
    def setUp(self):
        self.topology = MOD.TrafficTopology(1)
        self.rows = [
            {"ip": "192.0.2.1"},
            {"ip": "2001:db8::1"},
        ]

    def test_every_planned_ip_is_idempotently_retired_after_freeze(self):
        completed = lambda args, **_kwargs: __import__("subprocess").CompletedProcess(
            args, 0, "", ""
        )
        with (
            mock.patch.object(MOD.subprocess, "run", side_effect=completed) as runner,
            mock.patch.object(self.topology, "_neighbor_inventory", return_value=set()),
        ):
            self.topology.retire_rows(self.rows)
        commands = [call.args[0] for call in runner.call_args_list]
        self.assertEqual(
            commands,
            [
                [
                    "ip",
                    "-4",
                    "neigh",
                    "flush",
                    "to",
                    "192.0.2.1",
                    "dev",
                    self.topology.bridge,
                    "nud",
                    "all",
                ],
                [
                    "ip",
                    "-6",
                    "neigh",
                    "flush",
                    "to",
                    "2001:db8::1",
                    "dev",
                    self.topology.bridge,
                    "nud",
                    "all",
                ],
            ],
        )

    def test_post_freeze_planned_neighbor_bound_is_exact_zero(self):
        completed = lambda args, **_kwargs: __import__("subprocess").CompletedProcess(
            args, 0, "", ""
        )
        with (
            mock.patch.object(MOD.subprocess, "run", side_effect=completed),
            mock.patch.object(self.topology, "_neighbor_inventory", return_value={"192.0.2.1"}),
        ):
            with self.assertRaisesRegex(MOD.MeasurementError, "survived retirement"):
                self.topology.retire_rows(self.rows)

    def test_inventory_includes_every_nud_state_and_rejects_bad_json(self):
        with mock.patch.object(MOD, "_command", return_value='[{"dst":"192.0.2.1"}]\n') as command:
            self.assertEqual(self.topology._neighbor_inventory(), {"192.0.2.1"})
        command.assert_called_once_with(
            [
                "ip",
                "-j",
                "neigh",
                "show",
                "dev",
                self.topology.bridge,
                "nud",
                "all",
            ]
        )
        with mock.patch.object(MOD, "_command", return_value="not-json"):
            with self.assertRaisesRegex(MOD.MeasurementError, "cannot parse"):
                self.topology._neighbor_inventory()


class TopologyRollbackTests(unittest.TestCase):
    def test_mid_setup_failure_deletes_only_created_objects_and_restores_inventory(self):
        topology = MOD.TrafficTopology(1)
        command_calls = []

        def fake_command(args, **_kwargs):
            command_calls.append(args)
            if args == ["ip", "netns", "list"]:
                return "base-netns\n"
            if args == ["ip", "-o", "link", "show"]:
                return "base-links\n"
            if args == ["ip", "link", "set", "rh1000", "master", "rbgpskbr0"]:
                raise MOD.MeasurementError("injected mid-setup failure")
            return ""

        completed = lambda args, **_kwargs: __import__("subprocess").CompletedProcess(
            args, 0, "", ""
        )
        with mock.patch.object(MOD.os, "geteuid", return_value=0), mock.patch.object(
            MOD.shutil, "which", return_value="/fixture/tool"
        ), mock.patch.object(MOD, "_command", side_effect=fake_command), mock.patch.object(
            MOD.subprocess, "run", side_effect=completed
        ) as cleanup:
            with self.assertRaisesRegex(MOD.MeasurementError, "injected mid-setup failure"):
                topology.__enter__()

        cleanup_commands = [call.args[0] for call in cleanup.call_args_list]
        self.assertEqual(
            cleanup_commands,
            [
                ["ip", "link", "del", "rh1000"],
                ["ip", "netns", "del", topology.namespace],
                ["ip", "link", "del", topology.bridge],
            ],
        )
        self.assertEqual(topology.created_host_ports, ["rh1000"])
        self.assertNotIn(["ip", "link", "del", "rh1001"], cleanup_commands)
        self.assertGreaterEqual(command_calls.count(["ip", "netns", "list"]), 2)
        self.assertGreaterEqual(command_calls.count(["ip", "-o", "link", "show"]), 2)


if __name__ == "__main__":
    unittest.main()
