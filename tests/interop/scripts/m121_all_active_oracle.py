#!/usr/bin/env python3
"""Pure, fail-closed checks for the bounded M121 FRR all-active topology."""
from collections import Counter
import json
from pathlib import Path
import struct

from evpn_frr_peer_sync import checksum, frame


ESI = '03:aa:bb:cc:dd:ee:ff:00:00:01'
RUST = '10.211.0.2'
FRR = '10.211.0.1'


def make_frame(seed, copy, destination, source):
    """Give each copy a unique IPv4 ID without changing its flow or payload."""
    assert 0 <= seed <= 4095 and 0 <= copy < 10, (seed, copy)
    packet = bytearray(frame(seed, destination, source))
    struct.pack_into('!H', packet, 18, seed * 16 + copy)
    packet[24:26] = b'\0\0'
    struct.pack_into('!H', packet, 24, checksum(bytes(packet[14:34])))
    return bytes(packet)


def packet_identities(path):
    """Read only this lab's tagged Ethernet/IPv4/UDP frames from classic PCAP."""
    data = Path(path).read_bytes()
    byte_orders = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
                   b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
    assert len(data) >= 24 and data[:4] in byte_orders, 'invalid classic PCAP header'
    endian = byte_orders[data[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack_from(endian+'HHIIII', data, 4)
    assert (major, minor, linktype) == (2, 4, 1) and snaplen > 0, 'expected Ethernet PCAP'
    cursor, identities = 24, []
    marker = b'PEER-SYNC:'
    while cursor < len(data):
        assert cursor + 16 <= len(data), 'truncated PCAP record header'
        _, _, captured, original = struct.unpack_from(endian+'IIII', data, cursor)
        cursor += 16
        assert captured <= original and captured <= snaplen, 'invalid PCAP record length'
        assert cursor + captured <= len(data), 'truncated PCAP record'
        packet = data[cursor:cursor+captured]
        cursor += captured
        if marker not in packet:
            continue
        assert captured == original and len(packet) >= 42, 'truncated tagged frame'
        assert packet[12:14] == b'\x08\x00' and packet[14] == 0x45, 'expected untagged IPv4 without options'
        total, identity, fragment = struct.unpack_from('!HHH', packet, 16)
        assert total >= 28 and 14 + total <= len(packet), 'truncated tagged IPv4 packet'
        assert fragment & 0x3fff == 0 and packet[23] == 17, 'expected unfragmented UDP'
        assert checksum(packet[14:34]) == 0, 'invalid tagged IPv4 checksum'
        source_port, destination_port, udp_length, _ = struct.unpack_from('!HHHH', packet, 34)
        assert destination_port == 45000 and udp_length == total - 20, 'wrong tagged UDP shape'
        payload = packet[42:14+total]
        assert payload.startswith(marker), 'marker outside tagged UDP payload'
        text = payload[len(marker):]
        assert text and text.isdigit(), 'invalid tagged seed'
        seed = int(text)
        assert 0 <= seed <= 4095 and text == str(seed).encode(), 'invalid tagged seed encoding'
        assert source_port == 30000 + seed, 'wrong tagged UDP source port'
        assert packet[26:30] == bytes([198, 18, seed // 250, seed % 250 + 1]), 'wrong tagged source IP'
        assert packet[30:34] == bytes([192, 0, 2, 10]), 'wrong tagged destination IP'
        identities.append((seed, identity))
    return identities


def verify_identities(identities, phase, seeds, copies, bum_winner='unicast'):
    """Require every individual emitted packet exactly once at its expected sinks."""
    seeds = list(seeds)
    assert seeds and len(seeds) == len(set(seeds)), seeds
    assert 1 <= copies <= 10 and all(0 <= seed <= 4095 for seed in seeds), (seeds, copies)
    assert bum_winner in ('unicast', 'a', 'b', None), bum_winner
    expected = Counter((seed, seed * 16 + copy) for seed in seeds for copy in range(copies))
    counters = {}
    for suffix in ('a-vx100', 'b-vx100', 'ce-cea', 'ce-ceb', 'ce-bond0', 'hr-eth0'):
        key = f'{phase}-{suffix}'
        assert key in identities, f'missing identity capture: {key}'
        counters[suffix] = Counter(tuple(identity) for identity in identities[key])
    assert counters['hr-eth0'] == expected, ('hr-eth0', counters)
    if bum_winner == 'unicast':
        assert counters['a-vx100'] + counters['b-vx100'] == expected, counters
        assert counters['ce-cea'] + counters['ce-ceb'] == expected, counters
        for node in ('a', 'b'):
            assert counters[f'{node}-vx100'] == counters[f'ce-ce{node}'], counters
        assert counters['ce-bond0'] == expected, counters
    else:
        for node in ('a', 'b'):
            assert counters[f'{node}-vx100'] == expected, counters
            assert counters[f'ce-ce{node}'] == (expected if bum_winner == node else Counter()), counters
        assert counters['ce-bond0'] == (expected if bum_winner is not None else Counter()), counters
    return True


def verify_nhg(fdb, nexthops, mac, expected_vteps):
    """Resolve the target VXLAN FDB row through its actual kernel NHG."""
    expected = list(expected_vteps)
    assert expected and len(expected) == len(set(expected)), expected
    rows = [row for row in fdb if row.get('mac') == mac
            and row.get('ifname') == 'vx100'
            and ('self' in row.get('flags', []) or 'nhid' in row or 'dst' in row)]
    assert len(rows) == 1, f'target VXLAN rows: {rows}'
    row = rows[0]
    assert ('nhid' in row) != ('dst' in row), row
    if 'dst' in row:
        assert len(expected) == 1 and row['dst'] == expected[0], row
        return True

    def lookup(nhid):
        found = [nh for nh in nexthops if nh.get('id') == nhid]
        assert len(found) == 1, f'nexthop {nhid}: {found}'
        return found[0]

    group = lookup(row['nhid'])
    assert 'fdb' in group and group['fdb'] is None and 'gateway' not in group, group
    members = group.get('group', [])
    ids = [member['id'] for member in members]
    assert len(ids) == len(expected) and len(ids) == len(set(ids)), members
    endpoints = []
    for nhid in ids:
        nh = lookup(nhid)
        assert 'fdb' in nh and nh['fdb'] is None and 'group' not in nh and 'gateway' in nh, nh
        endpoints.append(nh['gateway'])
    assert len(endpoints) == len(set(endpoints)), endpoints
    assert set(endpoints) == set(expected), (endpoints, expected)
    return True


def verify_bum(packets, phase, seed, winner):
    """Require ingress on both VTEPs and exactly one CE delivery, or a drop."""
    assert winner in ('a', 'b', None), winner
    for node in ('a', 'b'):
        key = f'{phase}-{node}-vx100'
        assert packets.get(key) == [seed], (key, packets.get(key))
        key = f'{phase}-ce-ce{node}'
        assert packets.get(key) == ([seed] if winner == node else []), (key, packets.get(key))
    key = f'{phase}-ce-bond0'
    assert packets.get(key) == ([seed] if winner is not None else []), (key, packets.get(key))
    return True


def _verify_flow_paths(packets, phase, seeds, copies):
    seeds = list(seeds)
    assert seeds and len(seeds) == len(set(seeds)), seeds
    expected = Counter({seed: copies for seed in seeds})
    counters = {}
    for suffix in ('a-vx100', 'b-vx100', 'ce-cea', 'ce-ceb', 'ce-bond0', 'hr-eth0'):
        key = f'{phase}-{suffix}'
        assert key in packets, f'missing capture: {key}'
        counters[suffix] = Counter(packets[key])
    assert counters['a-vx100'] + counters['b-vx100'] == expected, counters
    assert counters['ce-cea'] + counters['ce-ceb'] == expected, counters
    for node in ('a', 'b'):
        assert counters[f'{node}-vx100'] == counters[f'ce-ce{node}'], counters
        assert counters[f'{node}-vx100'], f'{phase}: PE {node} was not exercised'
    for seed in seeds:
        counts = (counters['a-vx100'][seed], counters['b-vx100'][seed])
        assert counts in ((copies, 0), (0, copies)), (phase, seed, counts)
    assert counters['ce-bond0'] == expected and counters['hr-eth0'] == expected, counters
    return {node: sorted(counters[f'{node}-vx100']) for node in ('a', 'b')}


def verify_discovery(packets, phase, seeds):
    """Discover each flow's sole PE path, requiring both PEs and full delivery."""
    return _verify_flow_paths(packets, phase, seeds, 1)


def verify_unicast(packets, phase, seeds, direction):
    """Require stable per-flow paths, both PEs used, and ten copies end-to-end."""
    assert direction in ('remote-to-ce', 'ce-to-remote'), direction
    _verify_flow_paths(packets, phase, seeds, 10)
    return True


def _flatten_paths(paths):
    assert isinstance(paths, list), paths
    for path in paths:
        if isinstance(path, list):
            yield from _flatten_paths(path)
        else:
            assert isinstance(path, dict), path
            yield path


def _route_paths(routes):
    if isinstance(routes, str):
        routes = json.loads(routes)
    assert isinstance(routes, dict), routes
    for rd, table in routes.items():
        if not isinstance(table, dict):
            continue
        assert table.get('rd') == rd, (rd, table)
        for prefix, route in table.items():
            if not isinstance(route, dict):
                continue
            assert route.get('prefix') == prefix, (prefix, route)
            for path in _flatten_paths(route.get('paths', [])):
                yield rd, prefix, path


def _verify_path(path, peer, communities):
    assert path.get('valid') is True and path.get('peerId') == peer, path
    nexthops = path.get('nexthops', [])
    assert len(nexthops) == 1, nexthops
    nh = nexthops[0]
    assert nh.get('ip') == peer and nh.get('afi') == 'ipv4' and nh.get('used') is True, nh
    actual = path.get('extendedCommunity', {}).get('string', '').split()
    for community in communities:
        assert actual.count(community) == 1, (community, actual)


def _verify_originated(routes, mac, vni, peer, expected_rd):
    matches = [(rd, prefix, path) for rd, prefix, path in _route_paths(routes)
               if path.get('routeType') == 2
               and (path.get('mac') == mac or f'[{mac}]' in prefix)]
    assert len(matches) == 1, f'Type 2 origins: {matches}'
    rd, prefix, path = matches[0]
    assert rd == expected_rd and prefix == f'[2]:[0]:[48]:[{mac}]', (rd, prefix)
    assert path.get('mac') == mac and path.get('ethTag') == 0 and path.get('macLen') == 48, path
    assert path.get('esi') == ESI, path
    _verify_path(path, peer, (f'RT:65000:{vni}', 'ET:8'))
    return True


def verify_frr_originated(routes, mac, vni):
    """Require one rustbgpd MAC route and no competing origin at the remote FRR."""
    return _verify_originated(routes, mac, vni, RUST, f'{RUST}:{vni}')


def verify_frr_peer_originated(routes, mac, vni):
    """Require FRR A's sole surviving MAC route after rustbgpd withdrawal."""
    return _verify_originated(routes, mac, vni, FRR, f'{FRR}:2')


def verify_frr_es_routes(routes, present, vni):
    """Check rustbgpd ES withdrawal/recovery while retaining FRR's ES routes."""
    paths = list(_route_paths(routes))
    for peer in (RUST, FRR):
        expected = {
            f'[1]:[0]:[{ESI}]:[32]:[0.0.0.0]:[0]':
                (f'{peer}:{vni}' if peer == RUST else f'{peer}:2', 1,
                 (f'RT:65000:{vni}', 'ET:8')),
            f'[1]:[4294967295]:[{ESI}]:[32]:[0.0.0.0]:[0]':
                (f'{peer}:{vni}' if peer == RUST else f'{peer}:3', 1,
                 (f'RT:65000:{vni}', 'ET:8', 'ESI-label-Rt:AA')),
            f'[4]:[{ESI}]:[32]:[{peer}]':
                (f'{peer}:{vni}' if peer == RUST else f'{peer}:3', 4,
                 ('ET:8', 'ES-Import-Rt:aa:bb:cc:dd:ee:ff')),
        }
        candidates = [(rd, prefix, path) for rd, prefix, path in paths
                      if path.get('routeType') in (1, 4)
                      and (path.get('peerId') == peer or rd.startswith(peer + ':'))]
        if peer == RUST and not present:
            assert not candidates, f'stale rustbgpd ES routes: {candidates}'
            continue
        assert len(candidates) == len(expected), (peer, candidates)
        seen = []
        for rd, prefix, path in candidates:
            assert prefix in expected, (rd, prefix)
            expected_rd, route_type, communities = expected[prefix]
            assert rd == expected_rd and path.get('routeType') == route_type, (rd, path)
            _verify_path(path, peer, communities)
            seen.append(prefix)
        assert len(set(seen)) == len(expected), seen
    return True


def verify_local_originated(rbgp_routes, mac, vni):
    """Pin the local Type 2 label that FRR's route JSON does not expose."""
    matches = [route for route in rbgp_routes
               if route.get('route_type') == 2 and route.get('mac') == mac]
    assert len(matches) == 1, matches
    route = matches[0]
    expected = dict(peer='0.0.0.0', rd=f'{RUST}:{vni}', label=vni, label2=0,
                    esi=ESI, ethernet_tag='0', next_hop=RUST, tunnel_type=8, ip='')
    for key, value in expected.items():
        assert route.get(key) == value, (key, route)
    rt = int.from_bytes(bytes.fromhex('0002fde8') + vni.to_bytes(4, 'big'), 'big')
    encap = int.from_bytes(bytes.fromhex('030c000000000008'), 'big')
    communities = route.get('extended_communities', [])
    assert communities.count(rt) == 1 and communities.count(encap) == 1, communities
    return True
