#!/usr/bin/env python3
"""Positive fixtures and plausible broken evidence for the M121 oracles."""
from copy import deepcopy
import json
from pathlib import Path
import struct
import tempfile
import unittest

from m121_all_active_oracle import (
    ESI, FRR, RUST, verify_bum, verify_discovery, verify_frr_es_routes, verify_frr_originated,
    verify_frr_peer_originated,
    verify_local_originated, verify_nhg, verify_unicast, verify_frr_synced_mac,
    checksum, frame, make_frame, packet_identities, verify_identities,
)


MAC = '02:aa:bb:cc:dd:10'
VNI = 100


class IdentityTests(unittest.TestCase):
    def frame(self, seed=10, copy=0):
        return make_frame(seed, copy, MAC, '02:aa:bb:cc:dd:99')

    def pcap(self, packets, endian='<'):
        data = struct.pack(endian+'IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        for packet in packets:
            data += struct.pack(endian+'IIII', 1, 0, len(packet), len(packet)) + packet
        return data

    def parse(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcap'
            path.write_bytes(data)
            return packet_identities(path)

    def identities(self):
        a = [(10, 160+copy) for copy in range(10)]
        b = [(11, 176+copy) for copy in range(10)]
        return {'p-a-vx100': a.copy(), 'p-b-vx100': b.copy(),
                'p-ce-cea': a.copy(), 'p-ce-ceb': b.copy(),
                'p-ce-bond0': a+b, 'p-hr-eth0': a+b}

    def test_unique_ids_preserve_flow_payload_and_checksum(self):
        original = frame(10, MAC, '02:aa:bb:cc:dd:99')
        for copy in range(10):
            packet = self.frame(copy=copy)
            self.assertEqual(packet[:18], original[:18])
            self.assertEqual(packet[20:24], original[20:24])
            self.assertEqual(packet[26:], original[26:])
            self.assertEqual(checksum(packet[14:34]), 0)
            self.assertEqual(struct.unpack_from('!H', packet, 18)[0], 160+copy)
        self.assertEqual(struct.unpack_from('!H', self.frame(4095, 9), 18)[0], 65529)
        for seed, copy in ((4096, 0), (-1, 0), (10, 10), (10, -1)):
            with self.assertRaises(AssertionError):
                self.frame(seed, copy)

    def test_packet_identities_endian_padding_background(self):
        for endian in ('<', '>'):
            packets = [self.frame(10, 0), b'background', self.frame(10, 9)+b'\0'*5]
            self.assertEqual(self.parse(self.pcap(packets, endian)), [(10, 160), (10, 169)])

    def test_packet_identities_reject_truncation_and_wrong_linktype(self):
        data = self.pcap([self.frame()])
        for broken in (data[:23], data[:30], data[:-1], data+b'\0', b'bad!'+data[4:]):
            with self.assertRaises(AssertionError):
                self.parse(broken)
        broken = bytearray(data)
        struct.pack_into('<I', broken, 20, 113)
        with self.assertRaises(AssertionError):
            self.parse(broken)
        broken = bytearray(data)
        struct.pack_into('<I', broken, 36, len(self.frame())+1)
        with self.assertRaises(AssertionError):
            self.parse(broken)

    def test_packet_identities_reject_wrong_tagged_shape(self):
        for offset, value in ((12, 0x86), (14, 0x46), (17, 255), (20, 0x20),
                              (23, 6), (24, 0), (26, 0), (30, 0), (35, 0), (37, 0), (39, 0)):
            with self.subTest(offset=offset):
                packet = bytearray(self.frame())
                packet[offset] = value
                if offset != 24:
                    packet[24:26] = b'\0\0'
                    struct.pack_into('!H', packet, 24, checksum(bytes(packet[14:34])))
                with self.assertRaises(AssertionError):
                    self.parse(self.pcap([packet]))
        packet = bytearray(self.frame())
        packet[-1] = ord('x')
        with self.assertRaises(AssertionError):
            self.parse(self.pcap([packet]))

    def test_unicast_exact_identities_and_json_lists(self):
        self.assertTrue(verify_identities(self.identities(), 'p', [10, 11], 10))
        self.assertTrue(verify_identities(json.loads(json.dumps(self.identities())), 'p', [10, 11], 10))
        for node, other in (('a', 'b'), ('b', 'a')):
            identities = self.identities()
            identities[f'p-{node}-vx100'] += identities[f'p-{other}-vx100']
            identities[f'p-ce-ce{node}'] += identities[f'p-ce-ce{other}']
            identities[f'p-{other}-vx100'] = []
            identities[f'p-ce-ce{other}'] = []
            self.assertTrue(verify_identities(identities, 'p', [10, 11], 10))

    def test_balanced_loss_and_duplicate_pass_seed_counts_but_fail_identities(self):
        identities = self.identities()
        for key, packets in identities.items():
            identities[key] = [(seed, 160 if identity == 169 else identity)
                               for seed, identity in packets]
        projected = {key: [seed for seed, _ in packets] for key, packets in identities.items()}
        self.assertTrue(verify_unicast(projected, 'p', [10, 11], 'remote-to-ce'))
        with self.assertRaises(AssertionError):
            verify_identities(identities, 'p', [10, 11], 10)

    def test_missing_duplicate_wrong_copy_and_swapped_path(self):
        for key in self.identities():
            for duplicate in (False, True):
                identities = self.identities()
                if duplicate:
                    identities[key].append(identities[key][0])
                else:
                    identities[key].pop()
                with self.assertRaises(AssertionError):
                    verify_identities(identities, 'p', [10, 11], 10)
        identities = self.identities()
        identities['p-ce-cea'], identities['p-ce-ceb'] = identities['p-ce-ceb'], identities['p-ce-cea']
        with self.assertRaises(AssertionError):
            verify_identities(identities, 'p', [10, 11], 10)
        identities = self.identities()
        del identities['p-hr-eth0']
        with self.assertRaises(AssertionError):
            verify_identities(identities, 'p', [10, 11], 10)

    def test_bum_winners_and_drop_need_exact_ingress_and_host(self):
        expected = [(10, 160)]
        for winner in ('a', 'b', None):
            identities = {'p-a-vx100': expected.copy(), 'p-b-vx100': expected.copy(),
                          'p-ce-cea': expected.copy() if winner == 'a' else [],
                          'p-ce-ceb': expected.copy() if winner == 'b' else [],
                          'p-ce-bond0': expected.copy() if winner is not None else [],
                          'p-hr-eth0': expected.copy()}
            self.assertTrue(verify_identities(identities, 'p', [10], 1, winner))
            for key in identities:
                broken = deepcopy(identities)
                broken[key] = [] if broken[key] else expected.copy()
                with self.assertRaises(AssertionError):
                    verify_identities(broken, 'p', [10], 1, winner)


def frr_routes():
    """The nested paths and prefix keys match FRR 10.7.1 route JSON."""
    routes = {}

    def add(rd, prefix, route_type, peer, community, **fields):
        table = routes.setdefault(rd, {'rd': rd})
        path = dict(valid=True, routeType=route_type, peerId=peer,
                    extendedCommunity={'string': community},
                    nexthops=[dict(ip=peer, afi='ipv4', used=True)], **fields)
        table[prefix] = dict(prefix=prefix, paths=[[path]], pathCount=1)

    for peer in (RUST, FRR):
        service_rd = f'{peer}:100' if peer == RUST else f'{peer}:2'
        es_rd = f'{peer}:100' if peer == RUST else f'{peer}:3'
        add(service_rd, f'[1]:[0]:[{ESI}]:[32]:[0.0.0.0]:[0]', 1,
            peer, 'RT:65000:100 ET:8')
        add(es_rd, f'[1]:[4294967295]:[{ESI}]:[32]:[0.0.0.0]:[0]', 1,
            peer, 'RT:65000:100 ET:8 ESI-label-Rt:AA')
        add(es_rd, f'[4]:[{ESI}]:[32]:[{peer}]', 4, peer,
            'ET:8 ES-Import-Rt:aa:bb:cc:dd:ee:ff DF: (alg: 2, pref: 100)')
    add(f'{RUST}:100', f'[2]:[0]:[48]:[{MAC}]', 2, RUST,
        'RT:65000:100 ET:8', mac=MAC, ethTag=0, macLen=48, esi=ESI)
    add(f'{FRR}:2', f'[2]:[0]:[48]:[{MAC}]', 2, FRR,
        'RT:65000:100 ET:8 ND:Proxy', mac=MAC, ethTag=0, macLen=48, esi=ESI)
    routes['numPrefix'] = 8
    return routes


class NextHopTests(unittest.TestCase):
    def setUp(self):
        self.rows = [dict(mac=MAC, ifname='vx100', nhid=30, flags=['self']),
                     dict(mac=MAC, ifname='vx100', master='br100')]
        self.nhs = [dict(id=30, group=[dict(id=10), dict(id=20)], fdb=None),
                    dict(id=10, gateway=FRR, fdb=None),
                    dict(id=20, gateway=RUST, fdb=None)]

    def test_two_endpoints_and_singleton_forms(self):
        self.assertTrue(verify_nhg(self.rows, self.nhs, MAC, [FRR, RUST]))
        self.nhs[0]['group'].pop()
        self.assertTrue(verify_nhg(self.rows, self.nhs, MAC, [FRR]))
        self.rows[0].pop('nhid')
        self.rows[0]['dst'] = FRR
        self.assertTrue(verify_nhg(self.rows, self.nhs, MAC, [FRR]))

    def test_reject_broken_group(self):
        mutations = [
            lambda rows, nhs: rows[0].update(nhid=31),
            lambda rows, nhs: nhs.pop(),
            lambda rows, nhs: nhs[0]['group'].append(dict(id=20)),
            lambda rows, nhs: nhs[2].update(gateway=FRR),
            lambda rows, nhs: nhs[2].update(gateway='10.211.0.99'),
            lambda rows, nhs: nhs[0].update(group=[dict(id=10)]),
            lambda rows, nhs: nhs.append(deepcopy(nhs[1])),
            lambda rows, nhs: rows.append(deepcopy(rows[0])),
            lambda rows, nhs: rows[0].update(dst=FRR),
            lambda rows, nhs: nhs[1].pop('fdb'),
            lambda rows, nhs: nhs[0].update(fdb=False),
            lambda rows, nhs: nhs[1].update(fdb=False),
            lambda rows, nhs: rows[0].update(ifname='vx200'),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                rows, nhs = deepcopy(self.rows), deepcopy(self.nhs)
                mutation(rows, nhs)
                with self.assertRaises(AssertionError):
                    verify_nhg(rows, nhs, MAC, [FRR, RUST])

    def test_stale_group_fails_singleton_expectation(self):
        with self.assertRaises(AssertionError):
            verify_nhg(self.rows, self.nhs, MAC, [FRR])


class PacketTests(unittest.TestCase):
    def bum(self, winner):
        return {'p-a-vx100': [17], 'p-b-vx100': [17],
                'p-ce-cea': [17] if winner == 'a' else [],
                'p-ce-ceb': [17] if winner == 'b' else [],
                'p-ce-bond0': [17] if winner else []}

    def test_bum_winners_and_drop(self):
        for winner in ('a', 'b', None):
            self.assertTrue(verify_bum(self.bum(winner), 'p', 17, winner))

    def test_bum_missing_duplicate_wrong_link_or_seed(self):
        for key, value in [('p-a-vx100', []), ('p-b-vx100', []),
                           ('p-a-vx100', [17, 17]), ('p-ce-cea', [17, 17]),
                           ('p-ce-cea', [18]), ('p-ce-ceb', [17]),
                           ('p-ce-bond0', [])]:
            with self.subTest(key=key, value=value):
                data = self.bum('a')
                data[key] = value
                with self.assertRaises(AssertionError):
                    verify_bum(data, 'p', 17, 'a')
        data = self.bum(None)
        del data['p-ce-ceb']
        with self.assertRaises(AssertionError):
            verify_bum(data, 'p', 17, None)

    def unicast(self):
        return {'p-a-vx100': [10]*10, 'p-b-vx100': [11]*10,
                'p-ce-cea': [10]*10, 'p-ce-ceb': [11]*10,
                'p-ce-bond0': [10]*10+[11]*10, 'p-hr-eth0': [10]*10+[11]*10}

    def test_unicast_both_directions(self):
        for direction in ('remote-to-ce', 'ce-to-remote'):
            self.assertTrue(verify_unicast(self.unicast(), 'p', [10, 11], direction))

    def discovery(self):
        return {'p-a-vx100': [12, 10], 'p-b-vx100': [11],
                'p-ce-cea': [12, 10], 'p-ce-ceb': [11],
                'p-ce-bond0': [10, 11, 12], 'p-hr-eth0': [10, 11, 12]}

    def test_discovery_returns_both_sorted_paths(self):
        self.assertEqual(verify_discovery(self.discovery(), 'p', [10, 11, 12]),
                         {'a': [10, 12], 'b': [11]})

    def test_discovery_rejects_empty_path_missing_duplicate_or_swapped_member(self):
        mutations = [
            lambda p: p.update({'p-a-vx100': [], 'p-ce-cea': [],
                                'p-b-vx100': [10, 11, 12], 'p-ce-ceb': [10, 11, 12]}),
            lambda p: p.update({'p-b-vx100': [], 'p-ce-ceb': [],
                                'p-a-vx100': [10, 11, 12], 'p-ce-cea': [10, 11, 12]}),
            lambda p: p['p-a-vx100'].append(10),
            lambda p: p['p-ce-ceb'].append(11),
            lambda p: p['p-ce-bond0'].pop(),
            lambda p: p['p-hr-eth0'].pop(),
            lambda p: p['p-b-vx100'].clear(),
            lambda p: p.pop('p-ce-cea'),
            lambda p: p.update({'p-ce-cea': [10, 11], 'p-ce-ceb': [12]}),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                packets = self.discovery()
                mutation(packets)
                with self.assertRaises(AssertionError):
                    verify_discovery(packets, 'p', [10, 11, 12])

    def test_unicast_rejects_split_flow_and_only_one_exercised_path(self):
        paths = [([10]*5, [10]*5+[11]*10),
                 ([10]*10+[11]*10, []),
                 ([], [10]*10+[11]*10)]
        for direction in ('remote-to-ce', 'ce-to-remote'):
            for path_a, path_b in paths:
                with self.subTest(direction=direction, path_a=path_a, path_b=path_b):
                    packets = self.unicast()
                    packets.update({'p-a-vx100': path_a, 'p-ce-cea': path_a,
                                    'p-b-vx100': path_b, 'p-ce-ceb': path_b})
                    with self.assertRaises(AssertionError):
                        verify_unicast(packets, 'p', [10, 11], direction)

    def test_unicast_missing_duplicate_reversed_and_equal_total(self):
        mutations = [lambda p: p['p-hr-eth0'].pop(),
                     lambda p: p['p-ce-ceb'].append(11),
                     lambda p: p.update({'p-ce-cea': [11]*10, 'p-ce-ceb': [10]*10}),
                     lambda p: p.update({'p-hr-eth0': [10]*20}),
                     lambda p: p.pop('p-ce-bond0')]
        for direction in ('remote-to-ce', 'ce-to-remote'):
            for mutation in mutations:
                with self.subTest(direction=direction, mutation=mutation):
                    packets = self.unicast()
                    mutation(packets)
                    with self.assertRaises(AssertionError):
                        verify_unicast(packets, 'p', [10, 11], direction)


class FrrRouteTests(unittest.TestCase):
    def setUp(self):
        self.routes = frr_routes()
        self.table = self.routes[f'{RUST}:100']
        self.prefix = f'[2]:[0]:[48]:[{MAC}]'
        self.path = self.table[self.prefix]['paths'][0][0]

    def test_originated_string_and_object(self):
        self.assertTrue(verify_frr_originated(self.routes, MAC, VNI))
        self.assertTrue(verify_frr_originated(json.dumps(self.routes), MAC, VNI))

    def frr_peer_route(self):
        route = self.table.pop(self.prefix)
        self.routes[f'{FRR}:2'][self.prefix] = route
        self.path.update(peerId=FRR, nexthops=[dict(ip=FRR, afi='ipv4', used=True)])

    def test_frr_peer_surviving_origin(self):
        self.frr_peer_route()
        self.assertTrue(verify_frr_peer_originated(self.routes, MAC, VNI))
        self.assertTrue(verify_frr_peer_originated(json.dumps(self.routes), MAC, VNI))

    def test_frr_peer_missing_or_competing_stale_rust_origin(self):
        stale = deepcopy(self.table[self.prefix])
        self.frr_peer_route()
        self.table[self.prefix] = stale
        with self.assertRaises(AssertionError):
            verify_frr_peer_originated(self.routes, MAC, VNI)
        del self.table[self.prefix]
        del self.routes[f'{FRR}:2'][self.prefix]
        with self.assertRaises(AssertionError):
            verify_frr_peer_originated(self.routes, MAC, VNI)

    def test_frr_peer_wrong_peer_rd_or_nexthop(self):
        self.frr_peer_route()
        for field, bad in [('peerId', RUST),
                           ('nexthops', [dict(ip=RUST, afi='ipv4', used=True)])]:
            with self.subTest(field=field):
                original = self.path[field]
                self.path[field] = bad
                with self.assertRaises(AssertionError):
                    verify_frr_peer_originated(self.routes, MAC, VNI)
                self.path[field] = original
        route = self.routes[f'{FRR}:2'].pop(self.prefix)
        self.routes[f'{FRR}:3'][self.prefix] = route
        with self.assertRaises(AssertionError):
            verify_frr_peer_originated(self.routes, MAC, VNI)

    def test_reject_type2_fields(self):
        for field, bad in [('esi', ESI[:-1]+'2'), ('ethTag', 1), ('macLen', 47),
                           ('valid', False), ('peerId', FRR), ('mac', '02:00:00:00:00:00')]:
            with self.subTest(field=field):
                original = self.path[field]
                self.path[field] = bad
                with self.assertRaises(AssertionError):
                    verify_frr_originated(self.routes, MAC, VNI)
                self.path[field] = original

    def test_reject_community_substrings_and_wrong_encapsulation(self):
        for bad in ('RT:65000:1000 ET:8', 'RT:65000:100 ET:80', 'ET:8',
                    'RT:65000:100', 'RT:65000:100 RT:65000:100 ET:8'):
            with self.subTest(community=bad):
                self.path['extendedCommunity']['string'] = bad
                with self.assertRaises(AssertionError):
                    verify_frr_originated(self.routes, MAC, VNI)

    def test_reject_nexthop_and_foreign_rd(self):
        original = deepcopy(self.path['nexthops'])
        for bad in ([], original*2, [dict(ip=FRR, afi='ipv4', used=True)],
                    [dict(ip=RUST, afi='ipv6', used=True)],
                    [dict(ip=RUST, afi='ipv4', used=False)]):
            self.path['nexthops'] = bad
            with self.assertRaises(AssertionError):
                verify_frr_originated(self.routes, MAC, VNI)
        self.path['nexthops'] = original
        self.routes[f'{RUST}:101'] = self.routes.pop(f'{RUST}:100')
        self.table['rd'] = f'{RUST}:101'
        with self.assertRaises(AssertionError):
            verify_frr_originated(self.routes, MAC, VNI)

    def test_reject_second_path_and_competing_frr_origin(self):
        self.table[self.prefix]['paths'].append([deepcopy(self.path)])
        with self.assertRaises(AssertionError):
            verify_frr_originated(self.routes, MAC, VNI)
        self.table[self.prefix]['paths'].pop()
        competing = deepcopy(self.table[self.prefix])
        competing['paths'][0][0]['peerId'] = FRR
        self.routes[f'{FRR}:2'][self.prefix] = competing
        with self.assertRaises(AssertionError):
            verify_frr_originated(self.routes, MAC, VNI)

    def test_proxy_pair_missing_duplicate_and_unmarked(self):
        original = deepcopy(self.routes)
        for peer in (RUST, FRR):
            with self.subTest(missing=peer):
                routes = deepcopy(original)
                del routes[f'{peer}:100' if peer == RUST else f'{peer}:2'][self.prefix]
                with self.assertRaises(AssertionError):
                    verify_frr_originated(routes, MAC, VNI)
        proxy = self.routes[f'{FRR}:2'][self.prefix]['paths'][0][0]
        for field, bad in [('peerId', RUST), ('esi', ESI[:-1]+'2'), ('ethTag', 1),
                           ('macLen', 47), ('valid', False),
                           ('nexthops', [dict(ip=RUST, afi='ipv4', used=True)]),
                           ('extendedCommunity', {'string': 'RT:65000:100 ET:8'}),
                           ('extendedCommunity', {'string': 'RT:65000:100 ET:8 ND:Proxy ND:Proxy'}),
                           ('extendedCommunity', {'string': 'RT:65000:100 ET:8 ND:Proxy R:1'}),
                           ('extendedCommunity', {'string': 'RT:65000:100 ET:8 ND:Proxyy'})]:
            with self.subTest(field=field, bad=bad):
                saved = proxy[field]
                proxy[field] = bad
                with self.assertRaises(AssertionError):
                    verify_frr_originated(self.routes, MAC, VNI)
                proxy[field] = saved
        self.routes[f'{FRR}:2'][self.prefix]['paths'].append([deepcopy(proxy)])
        with self.assertRaises(AssertionError):
            verify_frr_originated(self.routes, MAC, VNI)

    def test_es_present_and_withdrawn(self):
        self.assertTrue(verify_frr_es_routes(self.routes, True, VNI))
        for prefix in list(self.table):
            if prefix.startswith(('[1]', '[4]')):
                del self.table[prefix]
        self.assertTrue(verify_frr_es_routes(self.routes, False, VNI))
        with self.assertRaises(AssertionError):
            verify_frr_es_routes(self.routes, True, VNI)
        del self.routes[f'{FRR}:3']
        with self.assertRaises(AssertionError):
            verify_frr_es_routes(self.routes, False, VNI)

    def test_es_stale_wrong_esi_or_missing_ead(self):
        with self.assertRaises(AssertionError):
            verify_frr_es_routes(self.routes, False, VNI)
        prefix = f'[1]:[0]:[{ESI}]:[32]:[0.0.0.0]:[0]'
        route = self.table.pop(prefix)
        with self.assertRaises(AssertionError):
            verify_frr_es_routes(self.routes, True, VNI)
        wrong = prefix.replace(ESI, ESI[:-1]+'2')
        route['prefix'] = wrong
        self.table[wrong] = route
        with self.assertRaises(AssertionError):
            verify_frr_es_routes(self.routes, True, VNI)

    def test_es_later_path_wrong_peer_is_not_ignored(self):
        prefix = f'[4]:[{ESI}]:[32]:[{RUST}]'
        route = self.table[prefix]
        path = deepcopy(route['paths'][0][0])
        path['peerId'] = FRR
        route['paths'].append([path])
        with self.assertRaises(AssertionError):
            verify_frr_es_routes(self.routes, True, VNI)


class LocalRouteTests(unittest.TestCase):
    def setUp(self):
        self.route = dict(route_type=2, mac=MAC, peer='0.0.0.0', rd=f'{RUST}:100',
                          label=100, label2=0, esi=ESI, ethernet_tag='0', next_hop=RUST,
                          tunnel_type=8, ip='',
                          extended_communities=[842122827661412, 219550481834311688])
        self.proxy = dict(self.route, peer=FRR, rd=f'{FRR}:2', next_hop=FRR,
                          extended_communities=[842122827661412, 219550481834311688,
                                                434601762087763968])

    def test_retained_hosted_proxy_shape(self):
        fixture = json.loads((Path(__file__).resolve().parents[2] /
                              'fixtures/m121-frr-synchronized-proxy.json').read_text())
        self.assertTrue(verify_local_originated(fixture['rust_routes'], fixture['mac'], fixture['vni']))
        self.assertTrue(verify_frr_originated(fixture['frr_routes'], fixture['mac'], fixture['vni']))

    def test_local_label(self):
        self.assertTrue(verify_local_originated([self.route, self.proxy], MAC, VNI))

    def test_proxy_exact_fields_and_flags(self):
        for field, bad in [('label', 101), ('label2', 100), ('peer', '10.211.0.3'),
                           ('rd', f'{FRR}:3'), ('esi', ESI[:-1]+'2'), ('ethernet_tag', '1'),
                           ('next_hop', RUST), ('ip', '192.0.2.1'), ('tunnel_type', 0)]:
            with self.subTest(field=field):
                with self.assertRaises(AssertionError):
                    verify_local_originated([self.route, dict(self.proxy, **{field: bad})], MAC, VNI)
        for communities in (self.proxy['extended_communities'][:2],
                            self.proxy['extended_communities']*2,
                            [842122827661412, 219550481834311688, 0x0608040000000001],
                            [842122827661412, 219550481834311688, 0x0608060000000000],
                            [842122827661413, 219550481834311688, 0x0608040000000000],
                            [842122827661412, 219550481834311689, 0x0608040000000000]):
            with self.subTest(communities=communities):
                with self.assertRaises(AssertionError):
                    verify_local_originated([self.route, dict(self.proxy, extended_communities=communities)], MAC, VNI)
        for routes in ([self.route], [self.proxy], [self.route, self.route],
                       [self.proxy, self.proxy], [self.route, self.proxy, self.proxy]):
            with self.assertRaises(AssertionError):
                verify_local_originated(routes, MAC, VNI)
        with self.assertRaises(AssertionError):
            verify_local_originated([dict(self.route, extended_communities=self.proxy['extended_communities']),
                                     self.proxy], MAC, VNI)

    def test_wrong_label_peer_esi_rt_or_encapsulation(self):
        for field, bad in [('label', 101), ('label2', 100), ('peer', FRR),
                           ('esi', ESI[:-1]+'2'), ('rd', f'{RUST}:101'),
                           ('next_hop', FRR), ('ethernet_tag', '1'),
                           ('tunnel_type', 0), ('extended_communities', []),
                           ('extended_communities', [842122827661412]),
                           ('extended_communities', [219550481834311688])]:
            with self.subTest(field=field, bad=bad):
                route = dict(self.route, **{field: bad})
                with self.assertRaises(AssertionError):
                    verify_local_originated([route, self.proxy], MAC, VNI)
        with self.assertRaises(AssertionError):
            verify_local_originated([self.route, self.route], MAC, VNI)


class FrrSyncStateTests(unittest.TestCase):
    def test_source_derived_sync_state(self):
        state = {MAC: dict(type='local', intf='es0', esi=ESI, localInactive=True, peerActive=True)}
        self.assertTrue(verify_frr_synced_mac(state, MAC))
        self.assertTrue(verify_frr_synced_mac({MAC: dict(state[MAC], peerProxy=False)}, MAC))
        for field, bad in [('type', 'remote'), ('intf', 'vx100'), ('esi', ESI[:-1]+'2'),
                           ('localInactive', False), ('localInactive', 1),
                           ('peerActive', False), ('peerActive', 1), ('peerProxy', True)]:
            with self.subTest(field=field, bad=bad):
                with self.assertRaises(AssertionError):
                    verify_frr_synced_mac({MAC: dict(state[MAC], **{field: bad})}, MAC)
        for missing in ('localInactive', 'peerActive'):
            bad = deepcopy(state)
            del bad[MAC][missing]
            with self.assertRaises(AssertionError):
                verify_frr_synced_mac(bad, MAC)
        for bad in ({}, {**state, '02:00:00:00:00:00': state[MAC]}):
            with self.assertRaises(AssertionError):
                verify_frr_synced_mac(bad, MAC)


if __name__ == '__main__':
    unittest.main()
