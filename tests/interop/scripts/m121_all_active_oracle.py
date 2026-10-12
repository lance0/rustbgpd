#!/usr/bin/env python3
"""Pure, fail-closed checks for the bounded M121 FRR all-active topology."""
from collections import Counter
import json
from pathlib import Path
import re
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
        _verify_bum_links({key: counters[key] for key in ('ce-cea', 'ce-ceb', 'ce-bond0')},
                          expected, Counter(), bum_winner)
    return True


NON_ENFORCEMENT_WITNESS = (
    'stock-FRR non-enforcement witness turned red: non-DF FRR no longer floods BUM '
    'to the CE, so FRR now enforces non-DF on Linux; requalify M121 and its docs')


def _verify_bum_links(links, one, none, winner):
    """Pin per-member CE delivery for one BUM frame.

    FRR 10.7.1's Linux netlink provider never applies its non-DF bridge-port
    update, so FRR's member floods whether or not FRR is DF. rustbgpd's member
    floods only as DF. With rustbgpd as DF the CE bond therefore sees two copies.
    """
    assert winner in ('a', 'b', None), winner
    assert links['ce-cea'] == one, (links if winner == 'a' else (NON_ENFORCEMENT_WITNESS, links))
    assert links['ce-ceb'] == (one if winner == 'b' else none), ('rustbgpd member', links)
    assert links['ce-bond0'] == one + (one if winner == 'b' else none), links


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
    """Require ingress on both VTEPs, then FRR-member and rustbgpd-member delivery.

    `winner` is the DF PE: 'a' (FRR), 'b' (rustbgpd) or None (both non-DF).
    """
    for node in ('a', 'b'):
        key = f'{phase}-{node}-vx100'
        assert packets.get(key) == [seed], (key, packets.get(key))
    links = {}
    for suffix in ('ce-cea', 'ce-ceb', 'ce-bond0'):
        assert f'{phase}-{suffix}' in packets, f'missing capture: {phase}-{suffix}'
        links[suffix] = Counter(packets[f'{phase}-{suffix}'])
    _verify_bum_links(links, Counter([seed]), Counter(), winner)
    return True


FLOOD_FLAGS = ('flood', 'mcast_flood', 'bcast_flood')


def verify_bridge_flood(port, enabled):
    """Require every Linux bridge-port flood flag to be on (DF) or off (non-DF)."""
    for key in FLOOD_FLAGS:
        assert port.get(key) is enabled, (key, port)
    return True


def verify_frr_non_enforcement(es_detail, port):
    """Pin FRR reporting non-DF while its ES bridge port still floods BUM."""
    assert re.search(r'^\s*DF status:\s*non-df\s*$', es_detail, re.MULTILINE), es_detail
    assert port.get('ifname') == 'es0', port
    flags = {key: port.get(key) for key in FLOOD_FLAGS}
    assert all(value is True for value in flags.values()), (NON_ENFORCEMENT_WITNESS, flags)
    return flags


def verify_modulo_fallback(segment, rust_routes, frr_es_detail, vni):
    """Record RFC 8584 algorithm disagreement and rustbgpd's modulo non-DF role."""
    assert segment.get('df_algorithm') == 'default-modulo', segment
    members = [member for member in segment.get('members', []) if member.get('vni') == vni]
    assert len(members) == 1, segment
    # Modulo orders candidates by originator IP; VNI mod 2 selects the DF.
    assigned = sorted([FRR, RUST], key=lambda ip: tuple(map(int, ip.split('.'))))[vni % 2]
    expected = ('df', 'allow') if assigned == RUST else ('nondf', 'suppress')
    assert (members[0].get('df_role'), members[0].get('bum_forwarding_action')) == expected, members
    # FRR's Type 4 carries the RFC 8584 DF Election EC with algorithm 2 (preference).
    es = [route for route in rust_routes if route.get('route_type') == 4 and route.get('peer') == FRR]
    assert len(es) == 1, es
    elections = [ec for ec in es[0].get('extended_communities', []) if ec >> 48 == 0x0606]
    assert len(elections) == 1 and (elections[0] >> 40) & 0x1f == 2, es
    # FRR sees rustbgpd's non-preference algorithm and stays non-DF on every VNI.
    vteps = re.findall(r'^\s*' + re.escape(RUST) + r'\s+df_alg:\s*(\S+)', frr_es_detail, re.MULTILINE)
    assert len(vteps) == 1 and vteps[0] != 'preference', frr_es_detail
    assert re.search(r'^\s*DF status:\s*non-df\s*$', frr_es_detail, re.MULTILINE), frr_es_detail
    return dict(rust_df_algorithm='default-modulo', frr_df_algorithm='preference',
                frr_view_of_rust_df_algorithm=vteps[0], modulo_assigned=assigned,
                rust_role=expected[0], rust_bum_forwarding_action=expected[1], frr_df_status='non-df')


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
    """Require the Rust original and FRR's synchronized proxy, with no other origin."""
    matches = [(rd, prefix, path) for rd, prefix, path in _route_paths(routes)
               if path.get('routeType') == 2
               and (path.get('mac') == mac or f'[{mac}]' in prefix)]
    assert len(matches) == 2, f'Type 2 original and proxy: {matches}'
    seen = []
    for rd, prefix, path in matches:
        peer = path.get('peerId')
        assert peer in (RUST, FRR), path
        assert rd == (f'{RUST}:{vni}' if peer == RUST else f'{FRR}:2'), rd
        assert prefix == f'[2]:[0]:[48]:[{mac}]', prefix
        assert path.get('mac') == mac and path.get('ethTag') == 0 and path.get('macLen') == 48, path
        assert path.get('esi') == ESI, path
        communities = [f'RT:65000:{vni}', 'ET:8'] + (['ND:Proxy'] if peer == FRR else [])
        _verify_path(path, peer, communities)
        assert sorted(path['extendedCommunity']['string'].split()) == sorted(communities), path
        seen.append(peer)
    assert sorted(seen) == sorted([RUST, FRR]), seen
    return True


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
    """Pin the Rust original and exact FRR proxy bytes, including both VNI labels."""
    matches = [route for route in rbgp_routes
               if route.get('route_type') == 2 and route.get('mac') == mac]
    assert len(matches) == 2, matches
    rt = int.from_bytes(bytes.fromhex('0002fde8') + vni.to_bytes(4, 'big'), 'big')
    encap = int.from_bytes(bytes.fromhex('030c000000000008'), 'big')
    proxy = int.from_bytes(bytes.fromhex('0608040000000000'), 'big')
    seen = []
    for route in matches:
        peer = route.get('peer')
        assert peer in ('0.0.0.0', FRR), route
        original = peer == '0.0.0.0'
        expected = dict(rd=f'{RUST}:{vni}' if original else f'{FRR}:2', label=vni, label2=0,
                        esi=ESI, ethernet_tag='0', next_hop=RUST if original else FRR,
                        tunnel_type=8, ip='')
        for key, value in expected.items():
            assert route.get(key) == value, (key, route)
        communities = [rt, encap] + ([] if original else [proxy])
        assert sorted(route.get('extended_communities', [])) == sorted(communities), route
        seen.append(peer)
    assert sorted(seen) == sorted(['0.0.0.0', FRR]), seen
    return True


def verify_frr_synced_mac(state, mac):
    """Require FRR's inactive local MAC synchronized from its active ES peer."""
    # FRR 10.7.1 zebra/zebra_evpn_mac.c:674-690 emits only true sync flags.
    assert set(state) == {mac}, state
    row = state[mac]
    for key, expected in dict(type='local', intf='es0', esi=ESI,
                              localInactive=True, peerActive=True).items():
        assert type(row.get(key)) is type(expected) and row[key] == expected, (key, row)
    assert row.get('peerProxy', False) is False, row
    return True
