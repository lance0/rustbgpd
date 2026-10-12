#!/usr/bin/env python3
"""M122 must reject plausible broken wire/state evidence."""

import copy
import ipaddress
import struct
import subprocess
import unittest
from unittest.mock import patch

import m122_evpn_gr_oracle as oracle
import run_m122_evpn_gr as runner


def message(t, body):
    return b"\xff" * 16 + struct.pack("!HB", len(body) + 19, t) + body


def open_body(restart=False, forwarding=False, llgr_time=30, family=25):
    caps = bytes.fromhex("010400190046")
    gr = struct.pack("!HHBB", 60 | (0x8000 if restart else 0), family, 70, 0x80 if forwarding else 0)
    caps += bytes([64, len(gr)]) + gr
    llgr = struct.pack("!HBB", 25, 70, 0) + llgr_time.to_bytes(3, "big")
    caps += bytes([71, len(llgr)]) + llgr
    optional = bytes([2, len(caps)]) + caps
    return b"\x04" + struct.pack("!HH", 65001, 90) + ipaddress.IPv4Address(oracle.SOURCE).packed + bytes([len(optional)]) + optional


def attr(code, data, flags=None, extended=False):
    if flags is None:
        flags = 0xC0 if code in (8, 16, 22) else 0x80
    if extended:
        return bytes([flags | 0x10, code]) + len(data).to_bytes(2, "big") + data
    return bytes([flags, code, len(data)]) + data


def update_body(attributes):
    return bytes(2) + len(attributes).to_bytes(2, "big") + attributes


def announce(t, s, reflected=False, llgr=False):
    reach = bytes.fromhex("00194604") + ipaddress.IPv4Address(oracle.SOURCE).packed + b"\x00" + oracle.nlri(t, s)
    attrs = attr(14, reach) + attr(16, oracle.RT.to_bytes(8, "big") + oracle.VXLAN.to_bytes(8, "big"))
    if t == 3:
        attrs += attr(22, b"\x00\x06" + oracle.LABEL.to_bytes(3, "big") + ipaddress.IPv4Address(oracle.SOURCE).packed)
    if reflected:
        attrs += attr(9, ipaddress.IPv4Address(oracle.SOURCE).packed) + attr(10, ipaddress.IPv4Address(oracle.RR).packed)
    if llgr:
        attrs += attr(8, oracle.LLGR_STALE.to_bytes(4, "big"))
    return message(2, update_body(attrs))


def withdraw(types, s):
    return message(2, update_body(attr(15, bytes.fromhex("001946") + b"".join(oracle.nlri(t, s) for t in types))))


def fixture(restart_forwarding=True, include_eor=True):
    initial = message(1, open_body()) + b"".join(announce(t, s) for s in (1, 2) for t in range(1, 6))
    restart = message(1, open_body(True, restart_forwarding)) + b"".join(announce(t, 1) for t in range(1, 6))
    if include_eor:
        restart += message(2, update_body(attr(15, bytes.fromhex("001946"))))
    client = message(1, open_body()) + b"".join(announce(t, s, True) for s in (1, 2) for t in range(1, 6))
    client += message(2, update_body(attr(15, bytes.fromhex("001946") + b"".join(oracle.nlri(t, 2) for t in range(1, 6)))))
    client += b"".join(announce(t, 1, True, True) for t in range(1, 6))
    client += message(2, update_body(attr(15, bytes.fromhex("001946") + b"".join(oracle.nlri(t, 1) for t in range(1, 6)))))
    streams = [("0", oracle.SOURCE, oracle.RR, initial), ("2", oracle.SOURCE, oracle.RR, restart),
               ("1", oracle.RR_CLIENT, oracle.CLIENT, client)]
    return [f"{stream}\t{src}\t{dst}\t100\t{raw.hex()}" for stream, src, dst, raw in streams]


def rr_fixture():
    rows = []
    for t in range(1, 6):
        row = {"route_type": t, "rd": f"65001:{t}1", "peer": oracle.SOURCE, "next_hop": oracle.SOURCE,
               "tunnel_type": 8, "extended_communities": [oracle.RT, oracle.VXLAN], "communities": [],
               "ethernet_tag": "0", "esi": ":".join(f"{b:02x}" for b in oracle.esi(1)), "label": oracle.LABEL,
               "mac": "02:00:00:00:12:01", "ip": "192.0.2.1" if t == 2 else oracle.SOURCE,
               "prefix": "203.0.113.1/32", "gateway": "0.0.0.0"}
        rows.append(row)
    return rows


class OracleTests(unittest.TestCase):
    def test_ten_unique_routes_and_complete_lifecycle(self):
        self.assertEqual(len(oracle.expected_nlri([1, 2])), 10)
        result = oracle.analyze_wire(fixture())
        self.assertEqual(len(result["llgr_nlri"]), 5)
        self.assertEqual(len(result["withdrawn_nlri"]), 10)

    def test_survivor_withdrawal_before_llgr_promotion_fails(self):
        lines = fixture()
        first = announce(1, 1, True, True).hex()
        lines[2] = lines[2].replace(first, withdraw(range(1, 6), 1).hex() + first, 1)
        with self.assertRaisesRegex(ValueError, "survivor withdrawal"):
            oracle.analyze_wire(lines)

    def test_survivor_withdrawal_requires_all_five_promotions(self):
        lines = fixture()
        last = announce(5, 1, True, True).hex()
        lines[2] = lines[2].replace(last, withdraw([1], 1).hex() + last, 1)
        with self.assertRaisesRegex(ValueError, "survivor withdrawal"):
            oracle.analyze_wire(lines)

    def test_no_reannouncement_after_expiry_withdrawal(self):
        lines = fixture()
        lines[2] += announce(1, 1, True, True).hex()
        with self.assertRaisesRegex(ValueError, "reannounces"):
            oracle.analyze_wire(lines)

    def test_same_update_cannot_promote_and_withdraw_a_key(self):
        lines = fixture()
        original = announce(1, 1, True, True)
        attrs = original[23:] + attr(15, bytes.fromhex("001946") + oracle.nlri(1, 1))
        lines[2] = lines[2].replace(original.hex(), message(2, update_body(attrs)).hex(), 1)
        with self.assertRaisesRegex(ValueError, "same UPDATE"):
            oracle.analyze_wire(lines)

    def test_omitted_withdrawal_must_follow_source_eor(self):
        lines = fixture()
        with self.assertRaisesRegex(ValueError, "complete source EoR"):
            oracle.analyze_wire([lines[0], lines[2], lines[1]])

    def test_eor_completion_waits_for_fragments_and_preceding_gaps(self):
        lines = fixture()
        restart = bytes.fromhex(lines[1].split("\t")[4])
        eor_length = len(message(2, update_body(attr(15, bytes.fromhex("001946")))))
        for split, tail_first in ((len(restart) - 1, False), (len(restart) - eor_length, True)):
            head = f"2\t{oracle.SOURCE}\t{oracle.RR}\t100\t{restart[:split].hex()}"
            tail = f"2\t{oracle.SOURCE}\t{oracle.RR}\t{100 + split}\t{restart[split:].hex()}"
            first, last = (tail, head) if tail_first else (head, tail)
            with self.subTest(tail_first=tail_first):
                with self.assertRaisesRegex(ValueError, "complete source EoR"):
                    oracle.analyze_wire([lines[0], first, lines[2], last])
                result = oracle.analyze_wire([lines[0], first, last, lines[2]])
                self.assertEqual(result["client_order"]["source_eor_completion"][0], 3)

    def test_message_completion_uses_first_complete_tcp_prefix(self):
        raw = message(4, b"") * 3
        segments = [(119, raw[19:38], 1), (100, raw[:10], 2), (138, raw[38:], 3),
                    (110, raw[10:19], 4), (100, raw[:19], 5)]
        decoded = list(oracle.completed_messages(segments))
        self.assertEqual([position for position, _, _ in decoded], [(4, 19), (4, 38), (4, 57)])
        self.assertTrue(all(typ == 4 and body == b"" for _, typ, body in decoded))

    def test_legitimate_refresh_before_expiry_remains_accepted(self):
        lines = fixture()
        final = withdraw(range(1, 6), 1).hex()
        lines[2] = lines[2].replace(final, announce(1, 1, True, True).hex() + final, 1)
        oracle.analyze_wire(lines)

    def test_zero_label_withdrawals_keep_complete_route_identity(self):
        for t in (1, 2, 5):
            advertised = oracle.nlri(t, 1)
            withdrawn = advertised[:-3] + bytes(3)
            self.assertEqual(oracle.nlri_key(advertised.hex()), oracle.nlri_key(withdrawn.hex()))
            wrong = bytearray(withdrawn)
            wrong[9] ^= 1  # Different RD, despite the same Type/label.
            self.assertNotEqual(oracle.nlri_key(advertised.hex()), oracle.nlri_key(wrong.hex()))

    def test_withdrawal_key_keeps_esi_tag_mac_ip_prefix_originator(self):
        for t, offsets in {1: [10, 20], 2: [20, 25, 32], 3: [10, 15], 4: [10, 21], 5: [20, 24, 25]}.items():
            raw = oracle.nlri(t, 1)
            for offset in offsets:
                wrong = bytearray(raw)
                wrong[offset] ^= 1
                self.assertNotEqual(oracle.nlri_key(raw.hex()), oracle.nlri_key(wrong.hex()))
        with self.assertRaises(ValueError):
            oracle.nlri_key((b"\x06" + oracle.nlri(5, 1)[1:]).hex())

    def test_withdrawal_wrong_family_fails(self):
        lines = fixture()
        original = attr(15, bytes.fromhex("001946") + b"".join(oracle.nlri(t, 2) for t in range(1, 6))).hex()
        broken = attr(15, bytes.fromhex("000146") + b"".join(oracle.nlri(t, 2) for t in range(1, 6))).hex()
        lines[2] = lines[2].replace(original, broken, 1)
        self.assertNotEqual(lines, fixture())
        with self.assertRaises(ValueError):
            oracle.analyze_wire(lines)

    def test_evpn_specific_admission_and_positive_timer(self):
        oracle.admit_open(open_body())
        for body in (open_body(family=1), open_body(llgr_time=0)):
            with self.assertRaises(ValueError):
                oracle.admit_open(body)

    def test_restart_requires_forwarding_bit_and_real_eor(self):
        for lines in (fixture(False), fixture(include_eor=False)):
            with self.assertRaises(ValueError):
                oracle.analyze_wire(lines)

    def test_mp_flags_and_extended_length_encoding(self):
        for code in (14, 15):
            for flags in (0x00, 0x40, 0xA0, 0xC0):
                with self.assertRaises(ValueError):
                    oracle.validate_attributes({code: (flags, b"\x00\x19\x46")})
        lines = fixture()
        old = message(2, update_body(attr(15, bytes.fromhex("001946")))).hex()
        bad = message(2, update_body(attr(15, bytes.fromhex("001946"), flags=0x40))).hex()
        lines[1] = lines[1].replace(old, bad)
        with self.assertRaises(ValueError):
            oracle.analyze_wire(lines)
        lines = fixture()
        extended = message(2, update_body(attr(15, bytes.fromhex("001946"), extended=True))).hex()
        lines[1] = lines[1].replace(old, extended)
        oracle.analyze_wire(lines)

    def test_communities_flags_and_complete_values(self):
        marker = oracle.LLGR_STALE.to_bytes(4, "big")
        oracle.validate_attributes({8: (0xC0, marker)})
        oracle.validate_attributes({8: (0xF0, marker)})
        for flags, value in ((0x80, marker), (0x40, marker), (0xC0, b""), (0xC0, marker + b"\x00")):
            with self.assertRaises(ValueError):
                oracle.validate_attributes({8: (flags, value)})
        lines = fixture()
        # Mutate a genuine complete announcement rather than a standalone attribute.
        original = announce(5, 1, True, True).hex()
        attrs = announce(5, 1, True, True)[23:]
        broken = message(2, update_body(attrs.replace(attr(8, marker), attr(8, marker + b"\x00")))).hex()
        lines[2] = lines[2].replace(original, broken)
        with self.assertRaises(ValueError):
            oracle.analyze_wire(lines)

    def test_flags_on_every_exact_evidence_attribute(self):
        source = ipaddress.IPv4Address(oracle.SOURCE).packed
        cases = [(16, 1, False, oracle.RT.to_bytes(8, "big") + oracle.VXLAN.to_bytes(8, "big")),
                 (22, 3, False, b"\x00\x06" + oracle.LABEL.to_bytes(3, "big") + source),
                 (9, 1, True, source), (10, 1, True, ipaddress.IPv4Address(oracle.RR).packed)]
        for code, route_type, reflected, value in cases:
            original = announce(route_type, 1, reflected)
            legal = (0x80, 0x90) if code in (9, 10) else (0xC0, 0xD0, 0xE0, 0xF0)
            invalid = (0x00, 0x40, 0xA0, 0xC0, 0x81) if code in (9, 10) else (0x00, 0x40, 0x80, 0xA0, 0xC1)
            for flags in legal + invalid:
                with self.subTest(code=code, flags=flags):
                    replacement = attr(code, value, flags=flags, extended=bool(flags & 0x10))
                    attrs = original[23:].replace(attr(code, value), replacement, 1)
                    changed = message(2, update_body(attrs))
                    lines = fixture()
                    index = 2 if reflected else 0
                    self.assertIn(original.hex(), lines[index])
                    lines[index] = lines[index].replace(original.hex(), changed.hex(), 1)
                    if flags in invalid:
                        with self.assertRaisesRegex(ValueError, f"attribute {code} flags"):
                            oracle.analyze_wire(lines)
                    else:
                        oracle.analyze_wire(lines)

    def test_restart_cannot_fill_missing_initial_route(self):
        lines = fixture()
        lines[0] = lines[0].replace(announce(5, 1).hex(), "", 1)
        with self.assertRaises(ValueError):
            oracle.analyze_wire(lines)

    def test_raw_route_rt_next_hop_and_notification_corruption_fail(self):
        mutations = [
            (oracle.nlri(1, 2).hex(), (oracle.nlri(1, 2)[:-3] + bytes(3)).hex()),
            (oracle.RT.to_bytes(8, "big").hex(), (oracle.RT + 1).to_bytes(8, "big").hex()),
            ("001946040a007a02", "001946040a007a63"),
        ]
        for original, broken in mutations:
            lines = fixture()
            self.assertIn(original, lines[0])
            lines[0] = lines[0].replace(original, broken, 1)
            with self.assertRaises(ValueError):
                oracle.analyze_wire(lines)
        lines = fixture()
        lines[0] += message(3, b"\x06\x00").hex()
        with self.assertRaises(ValueError):
            oracle.analyze_wire(lines)

    def test_only_pre_established_collision_cease_is_allowed(self):
        open_ = message(1, open_body()).hex()
        keepalive = message(4, b"").hex()

        def row(src, dst, *raw):
            return f"9\t{src}\t{dst}\t100\t{''.join(raw)}"

        def collided(notification, rr_sends_keepalive=False, source_sends=()):
            # The RR's own connection to the source, closed by the source.
            sent = (open_, keepalive) if rr_sends_keepalive else (open_,)
            return fixture()[:1] + [row(oracle.RR, oracle.SOURCE, *sent),
                                    row(oracle.SOURCE, oracle.RR, open_, *source_sends, notification)] + fixture()[1:]

        oracle.analyze_wire(collided(message(3, b"\x06\x07").hex()))
        oracle.analyze_wire(collided(message(3, b"\x06\x07").hex(), rr_sends_keepalive=True))
        cases = {
            "other Cease subcode": collided(message(3, b"\x06\x02").hex()),
            "FSM error": collided(message(3, b"\x05\x00").hex()),
            "after Established": collided(message(3, b"\x06\x07").hex(), True, (keepalive,)),
            "UPDATE on the stream": collided(message(3, b"\x06\x07").hex(), source_sends=(announce(1, 1).hex(),)),
        }
        for name, lines in cases.items():
            with self.subTest(name), self.assertRaises(ValueError):
                oracle.analyze_wire(lines)

    def test_eor_before_all_five_refreshed_routes_fails(self):
        restart = message(1, open_body(True, True)) + b"".join(announce(t, 1) for t in range(1, 5))
        restart += message(2, update_body(attr(15, bytes.fromhex("001946"))))
        lines = fixture()
        lines[1] = f"2\t{oracle.SOURCE}\t{oracle.RR}\t100\t{restart.hex()}"
        with self.assertRaises(ValueError):
            oracle.analyze_wire(lines)

    def test_rr_exact_fields_reject_wrong_key_vni_rt_and_next_hop(self):
        original = rr_fixture()
        oracle.check_rr(original, [1])
        for field, value in (("rd", "65001:12"), ("label", 999), ("extended_communities", [oracle.RT]), ("next_hop", "10.0.122.99")):
            rows = copy.deepcopy(original)
            rows[0][field] = value
            with self.assertRaises(ValueError):
                oracle.check_rr(rows, [1])

    def test_missing_per_route_stale_fields_are_not_read(self):
        rows = rr_fixture()
        self.assertTrue(all("stale" not in r and "llgr_stale" not in r for r in rows))
        oracle.check_rr(rows, [1])
        with self.assertRaises(ValueError):
            oracle.check_rr(rows, [1], llgr=True)

    def test_client_absence_requires_successful_exact_query(self):
        oracle.check_client({}, [])
        for rows in (None, [], {oracle.client_key(2, 2): [{"attrs": []}]}):
            with self.assertRaises(ValueError):
                oracle.check_client(rows, [])
        with patch.object(runner, "command", side_effect=subprocess.CalledProcessError(1, "docker")):
            with self.assertRaises(subprocess.CalledProcessError):
                runner.wait("absence", runner.sink_rows, lambda rows: oracle.check_client(rows, []))

    def test_client_llgr_requires_community_on_every_identity(self):
        rows = {oracle.client_key(t, 1): [{"attrs": [{"type": 8, "communities": [oracle.LLGR_STALE]}]}] for t in range(1, 6)}
        oracle.check_client(rows, [1], llgr=True)
        rows[oracle.client_key(4, 1)][0]["attrs"] = []
        with self.assertRaises(ValueError):
            oracle.check_client(rows, [1], llgr=True)

    def test_missing_stale_metric_never_becomes_zero(self):
        with patch.object(runner, "docker", return_value=""):
            with self.assertRaises(ValueError):
                runner.metric("bgp_gr_stale_routes")
        with patch.object(runner, "docker", return_value=f'bgp_gr_stale_routes{{peer="{oracle.SOURCE}"}} 0\n'):
            self.assertEqual(runner.metric("bgp_gr_stale_routes"), 0)

    def test_snapshot_requires_llgr_and_eor_stale_gauges(self):
        original_wait = runner.wait
        for phase, llgr, expected in (("llgr-five", True, 5), ("eor-five", False, 0)):
            rr = rr_fixture()
            communities = [oracle.LLGR_STALE] if llgr else []
            for row in rr:
                row["communities"] = ["LLGR_STALE"] if llgr else []
            sink = {oracle.client_key(t, 1): [{"attrs": [{"type": 8, "communities": communities}]}] for t in range(1, 6)}
            for gauge in (0, 5):
                with self.subTest(phase=phase, gauge=gauge), \
                        patch.object(runner, "rr_rows", return_value=rr), \
                        patch.object(runner, "sink_rows", return_value=sink), \
                        patch.object(runner, "flaps", return_value=0), \
                        patch.object(runner, "metric", return_value=gauge), \
                        patch.object(runner, "save") as saved, \
                        patch.object(runner, "wait", side_effect=lambda label, read, check: original_wait(label, read, check, timeout=0)):
                    if gauge != expected:
                        with self.assertRaises(ValueError):
                            runner.snapshot(phase, [1], llgr)
                        saved.assert_not_called()
                    else:
                        runner.snapshot(phase, [1], llgr)
                        self.assertEqual(saved.call_args.args[1]["source_stale"], expected)


if __name__ == "__main__":
    unittest.main()
