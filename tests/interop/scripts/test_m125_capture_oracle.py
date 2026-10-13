#!/usr/bin/env python3
"""Positive byte fixtures and false-green guards for M125."""

import ipaddress
import struct
import unittest

import m125_capture_oracle as oracle
from test_m111_capture_oracle import frame, tlv, update_frame


def opening(source, *, extended=True):
    caps = b"".join(bytes([1, 4]) + struct.pack("!HBB", afi, 0, 1) for afi in (1, 2))
    if extended:
        caps += bytes([5, 6]) + struct.pack("!HHH", 1, 1, 2)
    options = bytes([2, len(caps)]) + caps
    return frame(1, struct.pack("!BHH4sB", 4, 65001, 90,
                 ipaddress.IPv4Address(oracle.ROUTER_IDS[source]).packed, len(options)) + options)


def prefix_sid(afi, *, structure=oracle.STRUCTURE):
    sid = ipaddress.IPv6Address(f"2001:db8:125:1:{afi}::")
    info = b"\x00" + sid.packed + b"\x00" + struct.pack("!H", {1: 19, 2: 18}[afi]) + b"\x00"
    return tlv(5, b"\x00" + tlv(1, info + tlv(1, structure)))


def route_attributes(afi, kind, *, reflected=False):
    prefix = ipaddress.ip_network(oracle.PREFIXES[afi])
    nlri = bytes([prefix.prefixlen]) + prefix.network_address.packed[:prefix.prefixlen // 8]
    if kind == "withdraw":
        return {15: (0x80, struct.pack("!HB", afi, 1) + nlri)}
    nh = ipaddress.IPv6Address(oracle.SOURCE).packed
    attrs = {1: (0x40, b"\x00"), 2: (0x40, b""), 5: (0x40, struct.pack("!I", 100)),
             14: (0x80, struct.pack("!HBB", afi, 1, len(nh)) + nh + b"\x00" + nlri),
             40: (0xC0, prefix_sid(afi))}
    if reflected:
        attrs[9] = (0x80, ipaddress.IPv4Address("10.125.0.2").packed)
        attrs[10] = (0x80, ipaddress.IPv4Address("10.125.0.1").packed)
        attrs[40] = (0xE0, attrs[40][1])
    return attrs


def fixture(mutate=None):
    result = []
    for pair, name in oracle.DIRECTIONS.items():
        sequence = 1000
        packets = [opening(pair[0]), frame(4)]
        if name in ("source_to_rr", "rr_to_sink"):
            for kind in ("announce", "withdraw"):
                for afi in ((1, 2) if kind == "announce" else (2, 1)):
                    attrs = route_attributes(afi, kind, reflected=name == "rr_to_sink")
                    if mutate:
                        mutate(name, afi, kind, attrs)
                    packets.append(update_frame(attrs))
        stream = "0" if pair[0] in (oracle.SOURCE, oracle.RR_SOURCE) else "1"
        for packet in packets:
            result.append("\t".join((stream, *pair, str(sequence), packet.hex())))
            sequence += len(packet)
    return result


class CaptureOracleTests(unittest.TestCase):
    def test_legacy_ipv4_withdrawal_and_duplicate_eor(self):
        rows = fixture()
        for index, line in enumerate(rows):
            fields = line.split("\t")
            if fields[1:3] != [oracle.RR_SINK, oracle.SINK]:
                continue
            packet = bytes.fromhex(fields[-1])
            if packet[18] != 2:
                continue
            attrs = oracle.update(packet[19:])[1]
            if 15 not in attrs or attrs[15][1][:3] != bytes.fromhex("000101"):
                continue
            nlri = attrs[15][1][3:]
            fields[-1] = frame(2, struct.pack("!H", len(nlri)) + nlri + bytes(2)).hex()
            rows[index] = "\t".join(fields)
        # It is the final IPv4 withdrawal's packet, so shortening it does not
        # leave a gap before another payload in this fixture.
        self.assertEqual(oracle.analyze(rows)["families"]["ipv4"]["reflected_withdrawal_encoding"], "legacy")
        for pair in oracle.DIRECTIONS:
            fields = next(row.split("\t") for row in reversed(rows) if row.split("\t")[1:3] == list(pair))
            fields[-2] = str(int(fields[-2]) + len(bytes.fromhex(fields[-1])))
            fields[-1] = frame(2, bytes(4)).hex()
            first = "\t".join(fields)
            fields[-2] = str(int(fields[-2]) + len(bytes.fromhex(fields[-1])))
            with self.assertRaisesRegex(ValueError, "duplicate EoR"):
                oracle.analyze(rows + [first, "\t".join(fields)])

    def test_native_dual_stack_global_services(self):
        receipt = oracle.analyze(fixture())
        self.assertEqual(set(receipt["families"]), {"ipv4", "ipv6"})
        for afi, family in enumerate(receipt["families"].values(), 1):
            self.assertEqual(family["service_sid"], f"2001:db8:125:1:{afi}::")
            self.assertEqual(family["safi"], 1)
            self.assertEqual(family["structure"], [40, 24, 16, 0, 0, 0])

    def test_reflected_wire_mutations_cannot_pass(self):
        def change_safi(attrs):
            value = bytearray(attrs[14][1]); value[2] = 128
            attrs[14] = (0x80, bytes(value))
        def change_next_hop(attrs):
            value = bytearray(attrs[14][1]); value[19] ^= 1
            attrs[14] = (0x80, bytes(value))
        def change_prefix(attrs):
            value = bytearray(attrs[14][1]); value[-1] ^= 1
            attrs[14] = (0x80, bytes(value))
        cases = [
            ("Prefix-SID absent", lambda a: a.pop(40)),
            ("global unicast", change_safi),
            ("source next hop", change_next_hop),
            ("global NLRI", change_prefix),
            ("SID Structure", lambda a: a.update({40: (0xC0, prefix_sid(1, structure=bytes([40, 24, 16, 0, 16, 64])))})),
            ("reflected attribute 9 absent", lambda a: a.pop(9)),
            ("value differs", lambda a: a.update({5: (0x40, struct.pack("!I", 200))})),
        ]
        for pattern, change in cases:
            with self.subTest(pattern=pattern):
                def mutate(name, afi, kind, attrs, change=change):
                    if name == "rr_to_sink" and afi == 1 and kind == "announce":
                        change(attrs)
                with self.assertRaisesRegex(ValueError, pattern):
                    oracle.analyze(fixture(mutate))

    def test_missing_withdrawal_is_rejected(self):
        def mutate(name, afi, kind, attrs):
            if name == "rr_to_sink" and afi == 2 and kind == "withdraw":
                attrs.clear()
        with self.assertRaisesRegex(ValueError, "one announcement and withdrawal"):
            oracle.analyze(fixture(mutate))

    def test_retransmissions_and_split_tcp_are_accepted(self):
        rows = fixture()
        fields = rows.pop().split("\t")
        payload = bytes.fromhex(fields[-1])
        a, b = fields.copy(), fields.copy()
        a[-1] = payload[:11].hex()
        b[-2], b[-1] = str(int(fields[-2]) + 11), payload[11:].hex()
        rows.extend(("\t".join(a), "\t".join(a), "\t".join(b)))
        oracle.analyze(list(reversed(rows)))

    def test_source_link_local_second_next_hop_is_omitted(self):
        def mutate(name, afi, kind, attrs):
            if name == "source_to_rr" and kind == "announce":
                value = attrs[14][1]
                attrs[14] = (0x80, value[:3] + bytes([32]) + value[4:20]
                             + ipaddress.IPv6Address("fe80::1234").packed + value[20:])
        oracle.analyze(fixture(mutate))

    def test_reflected_link_local_next_hop_is_rejected(self):
        def mutate(name, afi, kind, attrs):
            if name == "rr_to_sink" and kind == "announce":
                value = attrs[14][1]
                attrs[14] = (0x80, value[:3] + bytes([32]) + value[4:20]
                             + ipaddress.IPv6Address("fe80::1234").packed + value[20:])
        with self.assertRaisesRegex(ValueError, "retains source link-local"):
            oracle.analyze(fixture(mutate))

    def test_notifications_and_reconnections_are_rejected(self):
        rows = fixture()
        fields = rows[0].split("\t")
        fields[0] = "9"
        with self.assertRaisesRegex(ValueError, "reconnect"):
            oracle.analyze(rows + ["\t".join(fields)])
        for pair in oracle.DIRECTIONS:
            fields = next(row.split("\t") for row in reversed(rows) if row.split("\t")[1:3] == list(pair))
            fields[-2] = str(int(fields[-2]) + len(bytes.fromhex(fields[-1])))
            fields[-1] = frame(3, b"\x06\x00").hex()
            with self.assertRaisesRegex(ValueError, "NOTIFICATION"):
                oracle.analyze(rows + ["\t".join(fields)])

    def test_extra_route_event_and_incomplete_capture_are_rejected(self):
        rows = fixture()
        fields = next(row.split("\t") for row in reversed(rows) if row.split("\t")[1:3] == [oracle.RR_SINK, oracle.SINK])
        fields[-2] = str(int(fields[-2]) + len(bytes.fromhex(fields[-1])))
        packet = update_frame(route_attributes(1, "announce", reflected=True))
        fields[-1] = packet.hex()
        with self.assertRaisesRegex(ValueError, "one announcement and withdrawal"):
            oracle.analyze(rows + ["\t".join(fields)])
        fields[-1] = packet[:-1].hex()
        with self.assertRaisesRegex(ValueError, "partial BGP message"):
            oracle.analyze(rows + ["\t".join(fields)])

    def test_transposition_is_not_a_global_table_service(self):
        for afi in (1, 2):
            with self.assertRaisesRegex(ValueError, "SID Structure"):
                oracle.srv6(prefix_sid(afi, structure=bytes([40, 24, 16, 0, 16, 64])), afi)


if __name__ == "__main__":
    unittest.main()
