#!/usr/bin/env python3
"""Generated raw TCP negatives for the exact M121 on-wire contract."""
from copy import deepcopy
from pathlib import Path
import ipaddress
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

from m121_all_active_wire import verify_pcap, verify_wire


MAC = '02:aa:bb:cc:dd:10'
IP = bytes([10, 211, 0, 2])
RD = b'\x00\x01' + IP + b'\x00\x64'
ESI = bytes.fromhex('03aabbccddeeff000001')
RT = bytes.fromhex('0002fde800000064')
ENCAP = bytes.fromhex('030c000000000008')
LABEL = bytes.fromhex('0fdcf0')
ES_LABEL = bytes.fromhex('0601000000') + LABEL
ES_IMPORT = bytes.fromhex('0602aabbccddeeff')
DF = bytes.fromhex('0606020000000064')
FRR_IP = bytes([10, 211, 0, 1])
PROXY = bytes.fromhex('0608040000000000')


def proxy_route():
    return [2, b'\x00\x01'+FRR_IP+b'\x00\x02'+announcements()[0][1][8:], [RT, ENCAP, PROXY]]


def announcements():
    return [
        [2, RD+ESI+b'\0\0\0\0\x30'+bytes.fromhex('02aabbccdd10')+b'\0\0\0\x64', [RT, ENCAP]],
        [1, RD+ESI+b'\xff\xff\xff\xff'+LABEL, [RT, ENCAP, ES_LABEL]],
        [1, RD+ESI+b'\0\0\0\0\0\0\x64', [RT, ENCAP]],
        [4, RD+ESI+b'\x20'+IP, [RT, ENCAP, ES_IMPORT, DF]],
    ]


def tcp_rows(routes=None, *, source='10.211.0.2', dest='10.211.0.3',
             family=b'\0\x19\x46', next_hop=IP, mp_flags=0x90, ec_flags=0xd0,
             stream='0', include_proxy=True):
    rows, sequence = [], 1000
    for kind, body, communities in routes if routes is not None else announcements():
        reach = family + bytes([len(next_hop)]) + next_hop + b'\0' + bytes([kind, len(body)]) + body
        attrs = b''
        for flags, code, value in ((mp_flags, 14, reach), (ec_flags, 16, b''.join(communities))):
            length_size = 2 if flags & 0x10 else 1
            attrs += bytes([flags, code]) + len(value).to_bytes(length_size, 'big') + value
        update = b'\0\0' + len(attrs).to_bytes(2, 'big') + attrs
        message = b'\xff'*16 + (19+len(update)).to_bytes(2, 'big') + b'\x02' + update
        rows.append(f'{stream}\t{source}\t{dest}\t{sequence}\t{message.hex()}')
        sequence += len(message)
    if include_proxy:
        rows += proxy_rows()
    return rows


def proxy_rows(routes=None, **options):
    args = dict(source='10.211.0.1', dest='10.211.0.2', next_hop=FRR_IP,
                stream='1', include_proxy=False)
    args.update(options)
    return tcp_rows([proxy_route()] if routes is None else routes, **args)


class WireTests(unittest.TestCase):
    def check_bad(self, routes):
        with self.assertRaises(ValueError):
            verify_wire(tcp_rows(routes), MAC, 100)

    def test_all_route_kinds_and_repeated_advertisement(self):
        self.assertEqual(verify_wire(tcp_rows(), MAC, 100),
                         dict(type2=1, ead_per_es=1, ead_per_evi=1, type4=1, frr_proxy_type2=1))
        routes = announcements()
        routes.append(deepcopy(routes[0]))
        self.assertEqual(verify_wire(tcp_rows(routes), MAC, 100)['type2'], 2)

    def test_type1_and_type4_reject_any_unexpected_community(self):
        # The Type 2 proxy marker and an unrelated route target-like value.
        for extra in (PROXY, bytes.fromhex('0002fde800000065'), bytes.fromhex('8001000000000000')):
            for index, kind in ((1, 'per-ES'), (2, 'per-EVI'), (3, 'Type 4')):
                with self.subTest(route=kind, extra=extra.hex()):
                    routes = announcements()
                    routes[index][2].append(extra)
                    self.check_bad(routes)

    def test_valid_short_and_extended_attribute_lengths(self):
        for mp_flags in (0x80, 0x90):
            for ec_flags in (0xc0, 0xd0):
                with self.subTest(mp_flags=mp_flags, ec_flags=ec_flags):
                    self.assertEqual(verify_wire(tcp_rows(mp_flags=mp_flags, ec_flags=ec_flags), MAC, 100),
                                     dict(type2=1, ead_per_es=1, ead_per_evi=1, type4=1, frr_proxy_type2=1))

    def test_invalid_extended_community_flags(self):
        for name, flags in (('nontransitive', 0x80), ('missing_optional', 0x40),
                            ('partial', 0xe0), ('reserved', 0xc1)):
            for length_flag in (0, 0x10):
                with self.subTest(reason=name, extended=bool(length_flag)), self.assertRaisesRegex(
                        ValueError, 'extended communities flags'):
                    verify_wire(tcp_rows(ec_flags=flags | length_flag), MAC, 100)

    def test_invalid_mp_reach_flags(self):
        for name, flags in (('transitive', 0xc0), ('partial', 0xa0),
                            ('missing_optional', 0), ('reserved', 0x81)):
            for length_flag in (0, 0x10):
                with self.subTest(reason=name, extended=bool(length_flag)), self.assertRaisesRegex(
                        ValueError, 'MP_REACH flags'):
                    verify_wire(tcp_rows(mp_flags=flags | length_flag), MAC, 100)

    def test_pcap_extraction_timeout_default_and_override(self):
        for options, expected in (({}, 60), ({'timeout': 0.25}, 0.25)):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                with patch('m121_all_active_wire.subprocess.run') as run:
                    run.return_value.stdout = '\n'.join(tcp_rows())
                    result = verify_pcap(Path(directory) / 'capture.pcap', MAC, 100, **options)
                self.assertEqual(run.call_args.kwargs['timeout'], expected)
                self.assertEqual(result['frr_proxy_type2'], 1)

    @unittest.skipUnless(shutil.which('tshark'), 'tshark is not installed')
    def test_real_tshark_extracts_raw_vni_and_reserved_bytes(self):
        data = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        for index, row in enumerate(tcp_rows()):
            _, source, destination, sequence, payload = row.split('\t')
            tcp = struct.pack('!HHIIBBHHH', 20000, 179, int(sequence), 1,
                              0x50, 0x18, 65535, 0, 0) + bytes.fromhex(payload)
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(tcp), index, 0,
                             64, 6, 0, ipaddress.IPv4Address(source).packed,
                             ipaddress.IPv4Address(destination).packed)
            frame = bytes.fromhex('0200000000030200000000020800') + ip + tcp
            data += struct.pack('<IIII', index+1, 0, len(frame), len(frame)) + frame
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic.pcap'
            path.write_bytes(data)
            self.assertEqual(verify_pcap(path, MAC, 100),
                             dict(type2=1, ead_per_es=1, ead_per_evi=1, type4=1, frr_proxy_type2=1))
            self.assertTrue(Path(str(path)+'.payloads.tsv').read_text())

    def test_rust_original_cannot_carry_proxy_community(self):
        routes = announcements()
        routes[0][2].append(PROXY)
        self.check_bad(routes)

    def test_missing_proxy_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'proxy'):
            verify_wire(tcp_rows(include_proxy=False), MAC, 100)

    def check_proxy_bad(self, rows):
        with self.assertRaises(ValueError):
            verify_wire(tcp_rows(include_proxy=False)+rows, MAC, 100)

    def test_proxy_exact_nlri(self):
        for offset in (7, 17, 21, 22, 29, 32):
            with self.subTest(offset=offset):
                route = proxy_route()
                body = bytearray(route[1])
                body[offset] ^= 1
                route[1] = bytes(body)
                self.check_proxy_bad(proxy_rows([route]))
        route = proxy_route()
        route[1] += b'\0\0\x64'
        self.check_proxy_bad(proxy_rows([route]))
        # A different MAC cannot stand in for the required witness.
        route = proxy_route()
        route[1] = route[1][:28]+b'\x11'+route[1][29:]
        self.check_proxy_bad(proxy_rows([route]))

    def test_proxy_exact_communities(self):
        for index in range(3):
            for change in ('missing', 'duplicate', 'wrong'):
                with self.subTest(index=index, change=change):
                    route = proxy_route()
                    if change == 'missing':
                        route[2].pop(index)
                    elif change == 'duplicate':
                        route[2].append(route[2][index])
                    else:
                        raw = bytearray(route[2][index])
                        raw[-1] ^= 1
                        route[2][index] = bytes(raw)
                    self.check_proxy_bad(proxy_rows([route]))
        route = proxy_route()
        route[2].append(DF)
        self.check_proxy_bad(proxy_rows([route]))

    def test_proxy_flags_and_mp_header(self):
        for mp in (0x80, 0x90):
            for ec in (0xc0, 0xd0):
                self.assertEqual(verify_wire(tcp_rows(include_proxy=False)+proxy_rows(
                    mp_flags=mp, ec_flags=ec), MAC, 100)['frr_proxy_type2'], 1)
        for flag in (0x80, 0x40, 0xe0, 0xc1):
            for length in (0, 0x10):
                self.check_proxy_bad(proxy_rows(ec_flags=flag | length))
        for flag in (0xc0, 0xa0, 0, 0x81):
            for length in (0, 0x10):
                self.check_proxy_bad(proxy_rows(mp_flags=flag | length))
        for options in (dict(family=b'\0\x01\x46'), dict(family=b'\0\x19\x01'),
                        dict(next_hop=IP), dict(next_hop=FRR_IP+FRR_IP)):
            self.check_proxy_bad(proxy_rows(**options))
        rows = proxy_rows()
        columns = rows[0].split('\t')
        raw = bytearray.fromhex(columns[-1])
        raw[35] = 1  # MP_REACH reserved byte.
        columns[-1] = raw.hex()
        self.check_proxy_bad(['\t'.join(columns)])

    def test_proxy_origin_and_stream_are_unique(self):
        self.check_proxy_bad(proxy_rows(source='10.211.0.9'))
        self.check_proxy_bad(proxy_rows(dest='10.211.0.3'))
        self.check_proxy_bad(proxy_rows()+proxy_rows(source='10.211.0.9', stream='2'))
        self.check_proxy_bad(proxy_rows()+proxy_rows(stream='2'))
        self.assertEqual(verify_wire(tcp_rows(include_proxy=False)+proxy_rows(
            [proxy_route(), proxy_route()]), MAC, 100)['frr_proxy_type2'], 2)

    def test_truncated_peer_type2_is_not_hidden_by_valid_proxy(self):
        for length in (0, 28, 29, 32):
            with self.subTest(length=length):
                route = proxy_route()
                route[1] = route[1][:length]
                self.check_proxy_bad(proxy_rows([proxy_route(), route]))
        # A complete unrelated MAC remains outside this witness's scope.
        route = proxy_route()
        route[1] = route[1][:28]+b'\x11'+route[1][29:]
        self.assertEqual(verify_wire(tcp_rows(include_proxy=False)+proxy_rows(
            [proxy_route(), route]), MAC, 100)['frr_proxy_type2'], 1)

    def test_later_invalid_proxy_is_not_hidden(self):
        route = proxy_route()
        route[2].pop()
        self.check_proxy_bad(proxy_rows([proxy_route(), route]))

    def test_missing_kind(self):
        for index in range(4):
            routes = announcements()
            routes.pop(index)
            self.check_bad(routes)

    def test_wrong_direction_or_family_or_nexthop(self):
        for options in (dict(source='10.211.0.1'), dict(dest='10.211.0.1'),
                        dict(source='10.211.0.3', dest='10.211.0.2'),
                        dict(family=b'\0\x01\x46'), dict(family=b'\0\x19\x01'),
                        dict(next_hop=bytes([10, 211, 0, 1])), dict(next_hop=IP+IP)):
            with self.subTest(options=options), self.assertRaises(ValueError):
                verify_wire(tcp_rows(**options), MAC, 100)

    def test_wrong_rd_esi_rt_encapsulation_for_every_kind(self):
        for index in range(4):
            for offset in (7, 17):
                routes = announcements()
                body = bytearray(routes[index][1])
                body[offset] ^= 1
                routes[index][1] = bytes(body)
                self.check_bad(routes)
            for offset in (0, 1):
                routes = announcements()
                bad = bytearray(routes[index][2][offset])
                bad[-1] ^= 1
                routes[index][2][offset] = bytes(bad)
                self.check_bad(routes)

    def test_missing_duplicate_and_conflicting_communities(self):
        for index in range(4):
            for extra in (RT, bytes.fromhex('0002fde800000065'),
                          ENCAP, bytes.fromhex('030c000000000009')):
                routes = announcements()
                routes[index][2].append(extra)
                self.check_bad(routes)
            routes = announcements()
            routes[index][2].pop(1)
            self.check_bad(routes)

    def test_type2_tag_mac_length_mac_ip_length_and_vni(self):
        for offset in (21, 22, 28, 29, 32):
            routes = announcements()
            body = bytearray(routes[0][1])
            body[offset] ^= 1
            routes[0][1] = bytes(body)
            self.check_bad(routes)
        routes = announcements()
        routes[0][1] += b'\0\0\x64'
        self.check_bad(routes)

    def test_ead_tags_vni_and_matching_all_active_label(self):
        for index, offset in ((1, 21), (1, 24), (2, 21), (2, 24)):
            routes = announcements()
            body = bytearray(routes[index][1])
            body[offset] ^= 1
            routes[index][1] = bytes(body)
            self.check_bad(routes)
        for label in (bytes.fromhex('0601010000')+LABEL, b'\x06\x01'+b'\0'*6):
            routes = announcements()
            routes[1][2][-1] = label
            self.check_bad(routes)
        routes = announcements()
        routes[2][2].append(ES_LABEL)
        self.check_bad(routes)

    def test_type4_originator_es_import_df_alg_and_preference(self):
        for offset in (18, 22):
            routes = announcements()
            body = bytearray(routes[3][1])
            body[offset] ^= 1
            routes[3][1] = bytes(body)
            self.check_bad(routes)
        for index, offset in ((2, 7), (3, 2), (3, 3), (3, 7)):
            routes = announcements()
            ec = bytearray(routes[3][2][index])
            ec[offset] ^= 1
            routes[3][2][index] = bytes(ec)
            self.check_bad(routes)
        routes = announcements()
        routes[3][2][-1] = bytes.fromhex('060602000000012c')
        self.assertEqual(verify_wire(tcp_rows(routes), MAC, 100, 300)['type4'], 1)

    def test_later_bad_advertisement_is_not_hidden(self):
        routes = announcements()
        bad = deepcopy(routes[0])
        bad[2].pop()
        routes.append(bad)
        self.check_bad(routes)

    def test_tcp_gap_conflict_truncation_and_retransmission(self):
        rows = tcp_rows()
        self.assertEqual(verify_wire(rows+[rows[0]], MAC, 100)['type2'], 1)
        for index in (0, 1, -1):
            broken = list(rows)
            columns = broken[index].split('\t')
            columns[-1] = columns[-1][:-2]
            broken[index] = '\t'.join(columns)
            with self.assertRaises(ValueError):
                verify_wire(broken, MAC, 100)
        columns = rows[0].split('\t')
        columns[-1] = columns[-1][:-2] + 'ff'
        with self.assertRaises(ValueError):
            verify_wire(rows + ['\t'.join(columns)], MAC, 100)
        second = rows[0].split('\t')
        second[0] = '1'
        with self.assertRaises(ValueError):
            verify_wire(rows + ['\t'.join(second)], MAC, 100)

    def test_truncated_nlri_and_extended_community(self):
        rows = tcp_rows()
        columns = rows[0].split('\t')
        raw = bytearray.fromhex(columns[-1])
        raw[37] += 1  # MP_REACH's first NLRI length byte.
        columns[-1] = raw.hex()
        rows[0] = '\t'.join(columns)
        with self.assertRaises(ValueError):
            verify_wire(rows, MAC, 100)
        routes = announcements()
        routes[0][2].append(b'\0')
        self.check_bad(routes)

    def test_duplicate_attribute_and_notification(self):
        rows = tcp_rows()
        columns = rows[0].split('\t')
        raw = bytes.fromhex(columns[-1])
        duplicate = raw[23:27+int.from_bytes(raw[25:27], 'big')]
        raw = raw[:16]+(len(raw)+len(duplicate)).to_bytes(2, 'big')+raw[18:21]+(len(raw)-23+len(duplicate)).to_bytes(2, 'big')+raw[23:]+duplicate
        columns[-1] = raw.hex()
        with self.assertRaises(ValueError):
            verify_wire(['\t'.join(columns)], MAC, 100)
        columns = rows[0].split('\t')
        raw = bytearray.fromhex(columns[-1])
        raw[18] = 3
        columns[-1] = raw.hex()
        with self.assertRaises(ValueError):
            verify_wire(['\t'.join(columns)], MAC, 100)


if __name__ == '__main__':
    unittest.main()
