#!/usr/bin/env python3
"""Pure byte-fixture regressions for the M111 packet evidence oracle."""

import ipaddress
import struct
import unittest

import m111_capture_oracle as oracle


def frame(kind, body=b""):
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), kind) + body


def opening(source, families=(1, 2), *, extended_next_hop=True):
    caps = b"".join(bytes([1, 4]) + struct.pack("!HBB", afi, 0, 128) for afi in families)
    if extended_next_hop:
        caps += bytes([5, 6]) + struct.pack("!HHH", 1, 128, 2)
    options = bytes([2, len(caps)]) + caps
    return frame(1, struct.pack("!BHH4sB", 4, 65001, 90,
                 ipaddress.IPv4Address(oracle.ROUTER_IDS[source]).packed, len(options)) + options)


def tlv(kind, value):
    return struct.pack("!BH", kind, len(value)) + value


def prefix_sid(afi, *, structure=oracle.STRUCTURE, sid="2001:db8:111:1::", behavior=None):
    behavior = {1: 0x13, 2: 0x12}[afi] if behavior is None else behavior
    info = b"\x00" + ipaddress.IPv6Address(sid).packed + b"\x00" + struct.pack("!H", behavior) + b"\x00"
    return tlv(5, b"\x00" + tlv(1, info + tlv(1, structure)))


def nlri(afi, *, withdrawn=False):
    prefix = ipaddress.ip_network(oracle.PREFIXES[afi])
    # Function 0x1234 occupies the high 16 label bits; low TC bits are zero.
    label = bytes.fromhex("800000" if withdrawn else "123401")
    return bytes([88 + prefix.prefixlen]) + label + oracle.RD + prefix.network_address.packed[:prefix.prefixlen // 8]


def announcement(afi, *, reflected=False):
    nh = bytes(8) + ipaddress.IPv6Address(oracle.SOURCE).packed
    attrs = {1: (0x40, b"\x00"), 2: (0x40, b""), 5: (0x40, struct.pack("!I", 100)),
             14: (0x80, struct.pack("!HBB", afi, 128, len(nh)) + nh + b"\x00" + nlri(afi)),
             16: (0xC0, bytes.fromhex("0002fde90000006f")), 40: (0xC0, prefix_sid(afi))}
    if reflected:
        attrs[9] = (0x80, ipaddress.IPv4Address("10.111.0.2").packed)
        attrs[10] = (0x80, ipaddress.IPv4Address("10.111.0.1").packed)
        attrs[40] = (0xE0, attrs[40][1])
    return attrs


def withdrawal(afi):
    return {15: (0x80, struct.pack("!HB", afi, 128) + nlri(afi, withdrawn=True))}


def update_frame(attrs):
    payload = b""
    for code, (flags, value) in attrs.items():
        length = struct.pack("!H", len(value)) if flags & 0x10 else bytes([len(value)])
        payload += bytes([flags, code]) + length + value
    return frame(2, bytes(2) + struct.pack("!H", len(payload)) + payload)


def fixture(mutate=None):
    directions = {}
    for pair, name in oracle.DIRECTIONS.items():
        packets = [opening(pair[0]), frame(4)]
        if name in ("source_to_rr", "rr_to_sink"):
            for afi in oracle.PREFIXES:
                attrs = announcement(afi, reflected=name == "rr_to_sink")
                if mutate:
                    mutate(name, afi, "announce", attrs)
                packets.append(update_frame(attrs))
            for afi in oracle.PREFIXES:
                attrs = withdrawal(afi)
                if mutate:
                    mutate(name, afi, "withdraw", attrs)
                packets.append(update_frame(attrs))
        directions[pair] = packets
    return directions


def rows(directions):
    result = []
    for pair, packets in directions.items():
        stream = "0" if pair[0] in (oracle.SOURCE, oracle.RR_SOURCE) else "1"
        sequence = 1000
        for packet in packets:
            result.append("\t".join((stream, *pair, str(sequence), packet.hex())))
            sequence += len(packet)
    return result


class CaptureOracleTests(unittest.TestCase):
    def test_receivers_must_advertise_vpnv4_ipv6_next_hop_support(self):
        for pair in ((oracle.RR_SOURCE, oracle.SOURCE), (oracle.SINK, oracle.RR_SINK)):
            data = fixture()
            data[pair][0] = opening(pair[0], extended_next_hop=False)
            with self.assertRaisesRegex(ValueError, "receive capability absent"):
                oracle.analyze(rows(data))

    def test_dual_stack_reflection_and_withdrawal(self):
        receipt = oracle.analyze(rows(fixture()))
        self.assertEqual(set(receipt["families"]), {"vpnv4", "vpnv6"})
        for family in receipt["families"].values():
            self.assertEqual(family["service_sid"], "2001:db8:111:1:1234::")
            self.assertEqual(family["structure"], [40, 24, 16, 0, 16, 64])
        self.assertEqual(len(receipt["streams"]), 4)

    def test_reordered_retransmitted_and_split_tcp(self):
        capture = rows(fixture())
        fields = capture.pop().split("\t")
        payload = bytes.fromhex(fields[-1])
        first, second = fields.copy(), fields.copy()
        first[-1] = payload[:11].hex()
        second[-2], second[-1] = str(int(fields[-2]) + 11), payload[11:].hex()
        capture += ["\t".join(second), "\t".join(first), "\t".join(first)]
        oracle.analyze(list(reversed(capture)))

    def test_extended_attribute_lengths_and_partial_bit(self):
        def mutate(name, afi, kind, attrs):
            if name == "rr_to_sink" and kind == "announce":
                attrs.update({code: (flags | 0x10, value) for code, (flags, value) in attrs.items()})
        oracle.analyze(rows(fixture(mutate)))

    def test_missing_reverse_direction(self):
        data = fixture()
        del data[(oracle.SINK, oracle.RR_SINK)]
        with self.assertRaisesRegex(ValueError, "missing a session direction"):
            oracle.analyze(rows(data))

    def test_initial_connection_attempt_without_payload_is_ignored(self):
        capture = rows(fixture()) + ["\t".join(("9", oracle.SOURCE, oracle.RR_SOURCE, "0", ""))]
        oracle.analyze(capture)

    def test_second_bgp_stream_is_rejected(self):
        capture = rows(fixture()) + ["\t".join(("9", oracle.SOURCE, oracle.RR_SOURCE, "0", opening(oracle.SOURCE).hex()))]
        with self.assertRaisesRegex(ValueError, "reconnect"):
            oracle.analyze(capture)

    def test_label_reserved_bits_and_link_local_next_hop_are_preserved(self):
        def mutate(name, afi, kind, attrs):
            if kind == "announce":
                value = bytearray(attrs[14][1])
                nlri_start = 5 + value[3]
                value[nlri_start + 3] |= 2
                link_local = bytes(8) + ipaddress.IPv6Address("fe80::1").packed
                attrs[14] = (0x80, bytes(value[:4 + value[3]]) + link_local + bytes(value[4 + value[3]:]))
                value = bytearray(attrs[14][1])
                value[3] = 48
                attrs[14] = (0x80, bytes(value))
        oracle.analyze(rows(fixture(mutate)))

    def test_label_bottom_of_stack_is_required(self):
        def mutate(name, afi, kind, attrs):
            if kind == "announce":
                value = bytearray(attrs[14][1])
                value[5 + value[3] + 3] &= ~1
                attrs[14] = (0x80, bytes(value))
        with self.assertRaisesRegex(ValueError, "bottom-of-stack"):
            oracle.analyze(rows(fixture(mutate)))

    def test_ipv4_next_hop_is_rejected_for_srv6_vpnv4(self):
        def mutate(name, afi, kind, attrs):
            if afi == 1 and kind == "announce":
                value = attrs[14][1]
                nh = bytes(8) + ipaddress.IPv4Address("10.111.0.2").packed
                attrs[14] = (0x80, value[:3] + bytes([12]) + nh + value[4 + value[3]:])
        with self.assertRaisesRegex(ValueError, "IPv6 next-hop length"):
            oracle.analyze(rows(fixture(mutate)))

    def test_notification_each_direction(self):
        for pair in oracle.DIRECTIONS:
            with self.subTest(pair=pair):
                data = fixture()
                data[pair].append(frame(3, b"\x06\x00"))
                with self.assertRaisesRegex(ValueError, "NOTIFICATION"):
                    oracle.analyze(rows(data))

    def test_missing_open_or_capability(self):
        for replacement in (frame(4), opening(oracle.SINK, families=(1,))):
            data = fixture()
            data[(oracle.SINK, oracle.RR_SINK)][0] = replacement
            with self.assertRaisesRegex(ValueError, "OPEN|family 2 absent"):
                oracle.analyze(rows(data))

    def test_tcp_gap_and_conflicting_retransmission(self):
        capture = rows(fixture())
        fields = capture[-1].split("\t")
        fields[-2] = str(int(fields[-2]) + 1)
        with self.assertRaisesRegex(ValueError, "TCP gap"):
            oracle.analyze(capture[:-1] + ["\t".join(fields)])
        fields = capture[-1].split("\t")
        fields[-1] = "00" + fields[-1][2:]
        with self.assertRaisesRegex(ValueError, "conflicting TCP overlap"):
            oracle.analyze(capture + ["\t".join(fields)])

    def test_missing_withdrawal_and_duplicate_announcement(self):
        pair = (oracle.RR_SINK, oracle.SINK)
        for duplicate in (False, True):
            data = fixture()
            if duplicate:
                data[pair].insert(3, data[pair][2])
            else:
                data[pair].pop()
            with self.assertRaisesRegex(ValueError, "expected one announcement and withdrawal"):
                oracle.analyze(rows(data))

    def test_withdrawal_before_announcement(self):
        data = fixture()
        pair = (oracle.RR_SINK, oracle.SINK)
        data[pair][2], data[pair][4] = data[pair][4], data[pair][2]
        with self.assertRaisesRegex(ValueError, "withdrawal precedes"):
            oracle.analyze(rows(data))

    def test_attribute_mutations(self):
        mutations = [
            ("Prefix-SID absent", lambda a: a.pop(40)),
            ("attribute 5 value differs", lambda a: a.update({5: (0x40, struct.pack("!I", 200))})),
            ("attribute 9 differs", lambda a: a.update({9: (0x80, bytes(4))})),
            ("attribute 10 absent", lambda a: a.pop(10)),
            ("attribute 40 flags differ", lambda a: a.update({40: (0xC1, a[40][1])})),
            ("attribute set differs", lambda a: a.update({99: (0xC0, b"x")})),
            ("next hop changed", lambda a: a.update({14: (0x80, a[14][1][:27] + b"\x03" + a[14][1][28:])})),
            ("VPN NLRI differs", lambda a: a.update({14: (0x80, a[14][1][:-1] + b"\x70")})),
            ("SID Structure differs", lambda a: a.update({40: (0xE0, prefix_sid(1, structure=bytes([40, 24, 16, 0, 15, 64])))})),
            ("endpoint behavior", lambda a: a.update({40: (0xE0, prefix_sid(1, behavior=0x12))})),
            ("outside configured locator", lambda a: a.update({40: (0xE0, prefix_sid(1, sid="2001:db8:111:2::"))})),
            ("transposed SID bits", lambda a: a.update({40: (0xE0, prefix_sid(1, sid="2001:db8:111:1:1::"))})),
            ("truncated SRv6 TLV", lambda a: a.update({40: (0xE0, a[40][1][:-1])})),
            ("attribute 40 value differs", lambda a: a.update({40: (0xE0, prefix_sid(1, sid="2001:db8:111:1::1"))})),
        ]
        for error, change in mutations:
            with self.subTest(error=error):
                def mutate(name, afi, kind, attrs):
                    if (name, afi, kind) == ("rr_to_sink", 1, "announce"):
                        change(attrs)
                with self.assertRaisesRegex(ValueError, error):
                    oracle.analyze(rows(fixture(mutate)))

    def test_changed_withdraw_label(self):
        def mutate(name, afi, kind, attrs):
            if (name, afi, kind) == ("rr_to_sink", 1, "withdraw"):
                value = attrs[15][1]
                attrs[15] = (0x80, value[:4] + bytes.fromhex("123401") + value[7:])
        with self.assertRaisesRegex(ValueError, "withdraw VPN NLRI changed"):
            oracle.analyze(rows(fixture(mutate)))


if __name__ == "__main__":
    unittest.main()
