#!/usr/bin/env python3
"""Offline independent vectors and false-positive controls for peer-sync proof."""

import copy
import socket
import subprocess
import sys
import tempfile
import tomllib
import runpy
import time
from pathlib import Path
import unittest

from evpn_peer_sync_oracle import (
    BgpReader, COUNTERS, ESI, FAMILY, Oracle, RT, Route, VXLAN,
    announcement, attribute, decode_type2s, duplicate_totals, type2, withdrawal,
)


from evpn_peer_sync_peer import command_updates, open_body, validate_open


SOURCE = "10.0.0.2"
DUT = "10.0.0.1"
MAC = "02:aa:bb:cc:dd:11"
# RFC 7432 Type2: route type/length, RD, ESI, tag, MAClen/MAC,
# IPlen/IP, and RFC 8365's unshifted VNI100. These are literal byte vectors,
# not expected data reconstructed by the encoder under test.
PREFIX = "00010a0000020064" + "00000000000000000001" + "00000000" + "3002aabbccdd11"
VECTORS = (
    ("", "0221" + PREFIX + "00" + "000064"),
    ("192.0.2.17", "0225" + PREFIX + "20c0000211" + "000064"),
    ("2001:db8::17", "0231" + PREFIX + "8020010db8000000000000000000000017" + "000064"),
)


class PeerSyncOracleTests(unittest.TestCase):
    def test_literal_type2_and_complete_update_vectors(self):
        for ip, expected in VECTORS:
            route = Route("10.0.0.2:100", MAC, ip)
            with self.subTest(ip=ip):
                self.assertEqual(type2(route).hex(), expected)
                self.assertEqual(decode_type2s(bytes.fromhex(expected)), [route])
        expected = (
            "00000051" "40010100" "400200" "c01018"
            "0002fde800000064" "030c000000000008" "0600000000000003"
            "800e2c" "001946040a00000200" + VECTORS[0][1]
        )
        self.assertEqual(announcement([Route("10.0.0.2:100", MAC)], 3,
                                      next_hop=SOURCE).hex(), expected)

    def test_direct_three_to_nine_and_wrong_increment_rejected(self):
        routes = [Route("10.0.0.1:100", MAC, ip) for ip, _ in VECTORS]
        oracle = Oracle()
        oracle.apply(announcement(routes, 3, next_hop=DUT))
        oracle.expect(routes, 3, next_hop=DUT)
        with self.assertRaises(AssertionError):
            oracle.expect(routes, 4, next_hop=DUT)
        oracle.apply(announcement(routes, 9, next_hop=DUT))
        oracle.expect(routes, 9, next_hop=DUT)
        with self.assertRaises(AssertionError):
            oracle.expect(routes, 10, next_hop=DUT)
        oracle.apply(withdrawal(routes))
        oracle.expect_absent(rd="10.0.0.1:100", mac=MAC)

    def test_source_route_cannot_satisfy_local_ownership(self):
        oracle = Oracle()
        source = Route("10.0.0.2:100", MAC)
        local = Route("10.0.0.1:100", MAC)
        oracle.apply(announcement([source], 9, next_hop=SOURCE))
        oracle.expect_absent(rd=local.rd, mac=MAC)
        with self.assertRaises(AssertionError):
            oracle.expect([local], 9, next_hop=DUT)
        oracle.apply(announcement([local], 9, next_hop=DUT))
        with self.assertRaises(AssertionError):
            oracle.expect_absent(rd=local.rd, mac=MAC)

    def test_exact_esi_tag_vni_nexthop_and_rt_are_load_bearing(self):
        expected = Route("10.0.0.1:100", MAC)
        for changed in (Route(expected.rd, MAC, tag=1), Route(expected.rd, MAC, vni=200),
                        Route(expected.rd, MAC, esi=(b"\0" * 10).hex(":"))):
            oracle = Oracle()
            oracle.apply(announcement([changed], 3, next_hop=DUT))
            with self.assertRaises(AssertionError):
                oracle.expect([expected], 3, next_hop=DUT)
        for next_hop, rt in ((SOURCE, RT), (DUT, bytes.fromhex("0002fde8000000c8"))):
            oracle = Oracle()
            oracle.apply(announcement([expected], 3, next_hop=next_hop, route_target=rt))
            with self.assertRaises(AssertionError):
                oracle.expect([expected], 3, next_hop=DUT)

    def test_truncation_and_bad_lengths_never_publish_partial_state(self):
        route = Route("10.0.0.1:100", MAC)
        body = announcement([route], 3, next_hop=DUT)
        oracle = Oracle()
        oracle.apply(body)
        before = copy.deepcopy((oracle.live, oracle.events))
        malformed = [body[:length] for length in range(len(body))]
        # A complete valid Type2 followed by an incomplete Type2 in one MP_REACH.
        reach = FAMILY + b"\x04" + bytes([10, 0, 0, 1]) + b"\0" + type2(route) + b"\x02"
        attrs = attribute(14, reach)
        malformed.append(b"\0\0" + len(attrs).to_bytes(2, "big") + attrs)
        for value in malformed:
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                oracle.apply(value)
            self.assertEqual((oracle.live, oracle.events), before)
        for position, value in ((1, 34), (24, 47), (31, 31)):
            nlri = bytearray(type2(route))
            nlri[position] = value
            with self.assertRaises(ValueError):
                decode_type2s(bytes(nlri))

    def test_duplicate_communities_and_mp_attributes_are_rejected(self):
        route = Route("10.0.0.1:100", MAC)
        reach = attribute(14, FAMILY + b"\4" + bytes([10, 0, 0, 1]) + b"\0" + type2(route))
        mobility = bytes.fromhex("0600000000000003")
        for attrs in (reach + reach,
                      reach + attribute(16, RT + VXLAN + mobility * 2, 0xC0),
                      reach + attribute(16, RT + b"\0", 0xC0)):
            with self.assertRaises(ValueError):
                Oracle().apply(b"\0\0" + len(attrs).to_bytes(2, "big") + attrs)

    def test_existing_reader_retains_fragment_across_timeout(self):
        body = announcement([Route("10.0.0.1:100", MAC)], 9, next_hop=DUT)
        frame = b"\xff" * 16 + (19 + len(body)).to_bytes(2, "big") + b"\x02" + body

        class Stream:
            chunks = iter((frame[:10], socket.timeout(), frame[10:23], frame[23:]))

            def recv(self, _):
                result = next(self.chunks)
                if isinstance(result, Exception):
                    raise result
                return result

        reader, oracle = BgpReader(Stream()), Oracle()
        with self.assertRaises(socket.timeout):
            oracle.read(reader)
        oracle.read(reader)
        oracle.expect([Route("10.0.0.1:100", MAC)], 9, next_hop=DUT)

    def test_metrics_sum_all_series_without_prefix_collisions(self):
        family = COUNTERS[0]
        scrape = (f'process_start_time_seconds 123\n{family}{{vni="100",mac="a"}} 2\n'
                  f'{family}{{vni="100",mac="b"}} 3\n{family}_wrong 100\n')
        result = duplicate_totals(scrape)
        self.assertEqual(result[family], {"present": True, "series": 2, "total": 5})
        self.assertEqual(result[COUNTERS[-1]], {"present": False, "series": 0, "total": 0})
        for bad in ("", "HTTP error", "process_start_time_seconds NaN\n",
                    scrape + f"{COUNTERS[1]} NaN\n", scrape + f"{COUNTERS[1]} -1\n",
                    scrape + f"{COUNTERS[1]}{{broken\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                duplicate_totals(bad)

    def test_combined_withdraw_reannounce_leaves_replacement_installed(self):
        old = Route("10.0.0.1:100", MAC, vni=200)
        new = Route("10.0.0.1:100", MAC)
        oracle = Oracle()
        oracle.apply(announcement([old], 3, next_hop=DUT))
        # Attribute order intentionally puts REACH first, as batching may do.
        attrs = announcement([new], 9, next_hop=DUT)[4:] + withdrawal([old])[4:]
        combined = b"\0\0" + len(attrs).to_bytes(2, "big") + attrs
        before = copy.deepcopy((oracle.live, oracle.events))
        with self.assertRaises(ValueError):
            oracle.apply(combined[:-1])
        self.assertEqual((oracle.live, oracle.events), before)
        oracle.apply(combined)
        oracle.expect([new], 9, next_hop=DUT)
        self.assertEqual([row["action"] for row in oracle.events[-2:]],
                         ["withdraw", "announce"])

    def test_old_capture_and_transient_wrong_sequences_are_rejected(self):
        route = Route("10.0.0.1:100", MAC)
        oracle = Oracle()
        oracle.apply(announcement([route], 9, next_hop=DUT))
        oracle.expect_transition([route], 9, next_hop=DUT, after=0)
        with self.assertRaises(AssertionError):
            oracle.expect_transition([route], 9, next_hop=DUT, after=1)
        oracle.apply(announcement([route], 10, next_hop=DUT))
        oracle.apply(announcement([route], 9, next_hop=DUT))
        with self.assertRaises(AssertionError):
            oracle.expect_transition([route], 9, next_hop=DUT, after=1)
        with self.assertRaises(AssertionError):
            oracle.expect_quiet(after=1, rd=route.rd)
        oracle.apply(withdrawal([route]))
        with self.assertRaises(AssertionError):
            oracle.expect_never_owned(rd=route.rd, mac=MAC)
        oracle.expect_quiet(after=len(oracle.events), rd=route.rd)

    def test_process_identity_must_be_one_valid_sample(self):
        for bad in ("123bogus", "NaN", "Inf", "0", "-1", "123 garbage"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                duplicate_totals(f"process_start_time_seconds {bad}\n")
        with self.assertRaises(ValueError):
            duplicate_totals("process_start_time_seconds 123\n" * 2)

    def test_open_requires_exact_peer_and_evpn_capability(self):
        body = bytearray(open_body())
        body[5:9] = bytes([10, 99, 0, 1])
        validate_open(bytes(body))
        for malformed in (bytes(body) + b"x", bytes(body[:-1]), open_body(),
                          bytes(body).replace(bytes.fromhex("00190046"), bytes.fromhex("00010001"))):
            with self.subTest(body=malformed.hex()), self.assertRaises(ValueError):
                validate_open(malformed)

    def test_receipt_rejects_old_run_phase_error_and_heartbeat(self):
        module = runpy.run_path(str(Path(__file__).with_name("run-evpn-peer-sync-proof.py")))
        load = module["receipt_oracle"]
        valid = {"run_id": "fresh", "established": True, "ack": 2,
                 "heartbeat": time.time(), "events": [], "live": []}
        load(valid, "fresh", 2)
        for mutation in ({"run_id": "old"}, {"ack": 1}, {"established": False},
                         {"error": "disconnected"}, {"heartbeat": time.time() - 10},
                         {"heartbeat": time.time() + 10}):
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                load({**valid, **mutation}, "fresh", 2)

    def test_runner_rejects_bad_revision_before_docker_or_output_creation(self):
        runner = Path(__file__).with_name("run-evpn-peer-sync-proof.py")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "receipt"
            result = subprocess.run([sys.executable, str(runner), "--image", "unused",
                                     "--source-revision", "not-a-sha", "--output", str(output)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("full commit SHA", result.stderr)
            self.assertFalse(output.exists())

    def test_live_config_matches_wire_fixture_and_enables_ip_diagnostics(self):
        from evpn_peer_sync_peer import DUT, DUT_RD, SOURCE
        config = tomllib.loads((Path(__file__).resolve().parents[1] /
                                "peer-sync/rustbgpd.toml").read_text())
        self.assertEqual(config["global"]["router_id"], DUT)
        self.assertEqual(config["neighbors"][0]["address"], SOURCE)
        self.assertEqual(config["neighbors"][0]["families"], ["l2vpn_evpn"])
        instance = config["evpn_instances"][0]
        self.assertEqual((instance["rd"], instance["vni"], instance["route_targets"]),
                         (DUT_RD, 100, ["65000:100"]))
        self.assertTrue(instance["duplicate_ip_detection"]["enabled"])
        self.assertEqual(config["ethernet_segments"][0]["esi"], ESI.hex(":"))

    def test_unexpected_local_key_and_reserved_mobility_bits_fail(self):
        route = Route("10.0.0.1:100", MAC)
        oracle = Oracle()
        oracle.apply(announcement([route], 3, next_hop=DUT))
        oracle.expect_owned_keys([route], rd=route.rd)
        oracle.apply(announcement([Route(route.rd, MAC, "192.0.2.1")], 3, next_hop=DUT))
        with self.assertRaises(AssertionError):
            oracle.expect_owned_keys([route], rd=route.rd)
        malformed = announcement([route], 3, next_hop=DUT).replace(
            bytes.fromhex("0600000000000003"), bytes.fromhex("0600020000000003"))
        oracle.apply(malformed)
        with self.assertRaises(AssertionError):
            oracle.expect([route], 3, next_hop=DUT)

    def test_static_vxlan_allows_absent_but_not_conflicting_encapsulation(self):
        route = Route("10.0.0.1:100", MAC)
        mobility = bytes.fromhex("0600000000000003")
        reach = attribute(14, FAMILY + b"\4" + bytes([10, 0, 0, 1]) + b"\0" + type2(route))
        for communities, accepted in ((RT + mobility, True),
                                      (RT + mobility + VXLAN, True),
                                      (RT + mobility + bytes.fromhex("030c000000000009"), False),
                                      (RT + mobility + VXLAN * 2, False),
                                      (mobility + VXLAN, False)):
            attrs = reach + attribute(16, communities, 0xC0)
            oracle = Oracle()
            oracle.apply(b"\0\0" + len(attrs).to_bytes(2, "big") + attrs)
            if accepted:
                oracle.expect([route], 3, next_hop=DUT)
            else:
                with self.assertRaises(AssertionError):
                    oracle.expect([route], 3, next_hop=DUT)

    def test_withdraw_command_removes_every_announced_source_key(self):
        oracle = Oracle()
        for body in command_updates(9):
            oracle.apply(body)
        announced = set(oracle.live)
        self.assertEqual(len(announced), 7)
        updates = command_updates(None)
        self.assertEqual(len(updates), 1)
        # Independent UPDATE prefix: no classic withdrawals, a single optional
        # MP_UNREACH attribute, AFI25/SAFI70, with no announcement attribute.
        # Seven NLRIs total 269 bytes; AFI/SAFI makes a 272-byte extended-
        # length MP_UNREACH value and 276-byte attributes block.
        self.assertEqual(updates[0][:11].hex(), "00000114900f0110001946")
        before = len(oracle.events)
        oracle.apply(updates[0])
        self.assertEqual(oracle.live, {})
        self.assertEqual({(row["rd"], row["tag"], row["mac"], row["ip"])
                          for row in oracle.events[before:]}, announced)
        self.assertTrue(all(row["action"] == "withdraw" for row in oracle.events[before:]))
        for bad in (0, 4, "withdraw", False):
            with self.subTest(sequence=bad), self.assertRaises(ValueError):
                command_updates(bad)

    def test_received_page_requires_complete_success_shape_before_absence(self):
        from evpn_peer_sync_peer import SOURCE, SOURCE_RD
        module = runpy.run_path(str(Path(__file__).with_name("run-evpn-peer-sync-proof.py")))
        parse = module["received_routes"]
        empty = {"view": "received", "neighbor": SOURCE, "routes": [],
                 "next_page_token": "", "total_count": 0}
        import json
        self.assertEqual(parse(json.dumps(empty)), [])
        route = {"rd": SOURCE_RD, "peer": SOURCE, "route_type": 2, "mac": MAC, "ip": ""}
        positive = {**empty, "routes": [route], "total_count": 1}
        self.assertEqual(parse(json.dumps(positive)), [route])
        malformed = [[], None, {}, {**empty, "view": "advertised"},
                     {**empty, "neighbor": DUT}, {**empty, "next_page_token": "more"},
                     {**empty, "total_count": 1}, {**empty, "total_count": False},
                     {**positive, "routes": [{}]}, {**positive, "routes": [None]},
                     {**positive, "routes": [{**route, "peer": DUT}]}]
        for value in malformed:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse(json.dumps(value))
        for raw in ("", "not JSON", json.dumps(empty) + json.dumps(empty)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse(raw)

    def test_cross_shape_transitions_require_fresh_nine_not_retained_other_key(self):
        parent = Route("10.0.0.1:100", MAC)
        children = [Route(parent.rd, MAC, ip) for ip, _ in VECTORS if ip]
        for original, replacement in (([parent], children), (children, [parent])):
            with self.subTest(replacement=replacement):
                oracle = Oracle()
                oracle.apply(announcement(original, 9, next_hop=DUT))
                checkpoint = len(oracle.events)
                with self.assertRaises(AssertionError):
                    oracle.expect_transition(replacement, 9, next_hop=DUT, after=checkpoint)
                oracle.apply(withdrawal(original))
                oracle.apply(announcement(replacement, 0, next_hop=DUT))
                with self.assertRaises(AssertionError):
                    oracle.expect_transition(replacement, 9, next_hop=DUT, after=checkpoint)
                oracle.apply(announcement(replacement, 9, next_hop=DUT))
                # A later correction cannot hide a transient zero export.
                with self.assertRaises(AssertionError):
                    oracle.expect_transition(replacement, 9, next_hop=DUT, after=checkpoint)
                oracle.expect_transition(replacement, 9, next_hop=DUT,
                                         after=len(oracle.events) - len(replacement))
                oracle.expect_owned_keys(replacement, rd=parent.rd)

    def test_encoder_rejects_out_of_range_and_oversized_inputs(self):
        for route in (Route("10.0.0.2:100", "00"), Route("10.0.0.2:100", MAC, vni=0),
                      Route("10.0.0.2:100", MAC, esi="00")):
            with self.assertRaises(ValueError):
                type2(route)
        with self.assertRaises(ValueError):
            announcement([Route("10.0.0.2:100", MAC)] * 150, 3, next_hop=SOURCE)
        self.assertEqual(ESI.hex(), "00000000000000000001")


if __name__ == "__main__":
    unittest.main()
