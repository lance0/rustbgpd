#!/usr/bin/env python3
"""Verify M121 wire advertisements from captured raw TCP payloads.

Usage: m121_all_active_wire.py CAPTURE.pcap MAC VNI [DF_PREFERENCE]
Tshark extracts TCP bytes only. Existing strict reassembly and BGP framing
helpers preserve every attribute byte, including reserved bytes and VNI labels
that a PDML dissection can omit or render as masked MPLS labels.
"""
from collections import defaultdict
import ipaddress
import json
from pathlib import Path
import subprocess
import sys

from m105_capture_oracle import messages, need, reassemble, update
from m121_all_active_oracle import ESI, RUST


REMOTE = '10.211.0.3'


def verify_wire(rows, mac, vni, df_preference=100):
    """Check five-field TCP TSV rows and require all four originated route kinds."""
    streams = defaultdict(list)
    for row in rows:
        columns = row.rstrip('\n').split('\t')
        need(len(columns) == 5, 'expected stream, source, destination, sequence, payload')
        stream, source, destination, sequence, payload = columns
        if source == RUST and destination == REMOTE and payload:
            streams[stream].append((int(sequence), bytes.fromhex(payload.replace(':', ''))))
    need(len(streams) == 1, 'missing or multiple rustbgpd-to-FRR TCP streams')
    decoded = messages(reassemble(next(iter(streams.values()))))
    ip = ipaddress.IPv4Address(RUST).packed
    rd = b'\x00\x01' + ip + vni.to_bytes(2, 'big')
    esi = bytes.fromhex(ESI.replace(':', ''))
    target_mac = bytes.fromhex(mac.replace(':', ''))
    rt = bytes.fromhex('0002fde8') + vni.to_bytes(4, 'big')
    encap = bytes.fromhex('030c000000000008')
    es_import = bytes.fromhex('0602aabbccddeeff')
    df = bytes.fromhex('060602000000') + df_preference.to_bytes(2, 'big')
    seen = dict(type2=0, ead_per_es=0, ead_per_evi=0, type4=0)
    for kind, body in decoded:
        need(kind != 3, 'rustbgpd sent a NOTIFICATION')
        if kind != 2:
            continue
        withdrawn, attrs, announced = update(body)
        need(not withdrawn and not announced, 'unexpected unicast NLRI')
        if 14 not in attrs:
            continue
        need(attrs[14][0] & ~0x10 == 0x80, 'wrong MP_REACH flags')
        reach = attrs[14][1]
        need(len(reach) >= 5, 'truncated MP_REACH')
        # This session advertises EVPN only; another family cannot prove it.
        need(reach[:4] == bytes([0, 25, 70, 4]), 'wrong AFI/SAFI/next-hop length')
        need(len(reach) >= 9 and reach[4:8] == ip and reach[8] == 0,
             'wrong MP_REACH next hop or reserved byte')
        ext = [attrs[16][1]] if 16 in attrs else []
        need(len(ext) == 1 and len(ext[0]) % 8 == 0, 'missing/duplicate/truncated extended communities')
        need(attrs[16][0] & ~0x10 == 0xc0, 'wrong extended communities flags')
        communities = [ext[0][i:i+8] for i in range(0, len(ext[0]), 8)]
        cursor = 9
        while cursor < len(reach):
            need(cursor + 2 <= len(reach), 'truncated EVPN NLRI header')
            route_type, length = reach[cursor:cursor+2]
            cursor += 2
            need(cursor + length <= len(reach), 'truncated EVPN NLRI body')
            body = reach[cursor:cursor+length]
            cursor += length
            if route_type not in (1, 2, 4):
                continue
            need(body[:8] == rd, 'foreign route distinguisher')
            need(body[8:18] == esi, 'wrong ESI')
            need(communities.count(rt) == 1 and communities.count(encap) == 1,
                 'missing/duplicate RT or VXLAN encapsulation')
            route_targets = [c for c in communities if c[0] in (0, 1, 2) and c[1] == 2]
            encapsulations = [c for c in communities if c[:2] == b'\x03\x0c']
            need(route_targets == [rt] and encapsulations == [encap], 'conflicting RT or encapsulation')
            if route_type == 2:
                need(length == 33 and body[18:23] == b'\0\0\0\0\x30'
                     and body[23:29] == target_mac and body[29] == 0,
                     'wrong MAC-only Type 2 shape, tag or MAC')
                need(int.from_bytes(body[30:33], 'big') == vni, 'wrong Type 2 VNI label')
                seen['type2'] += 1
            elif route_type == 1:
                need(length == 25, 'wrong EAD length')
                tag = int.from_bytes(body[18:22], 'big')
                label = int.from_bytes(body[22:25], 'big')
                labels = [c for c in communities if c[:2] == b'\x06\x01']
                if tag == 0xffffffff:
                    need(label != 0 and labels == [b'\x06\x01\0\0\0' + body[22:25]],
                         'EAD per-ES lacks matching all-active ESI label')
                    seen['ead_per_es'] += 1
                else:
                    need(tag == 0 and label == vni and not labels,
                         'wrong EAD per-EVI tag, VNI or ESI-label community')
                    seen['ead_per_evi'] += 1
            else:
                need(length == 23 and body[18] == 32 and body[19:23] == ip,
                     'wrong Type 4 originator')
                need([c for c in communities if c[:2] == b'\x06\x02'] == [es_import],
                     'wrong ES-Import community')
                need([c for c in communities if c[:2] == b'\x06\x06'] == [df],
                     'wrong DF algorithm, preference or capabilities')
                seen['type4'] += 1

    need(all(seen.values()), f'missing originated route kinds: {seen}')
    return seen


def verify_pcap(path, mac, vni, df_preference=100):
    """Extract and retain the raw TCP witness beside its source capture."""
    fields = ('tcp.stream', 'ip.src', 'ip.dst', 'tcp.seq_raw', 'tcp.payload')
    command = ['tshark', '-r', str(path), '-Y', 'tcp.len > 0 && tcp.port == 179',
               '-T', 'fields', '-E', 'separator=/t']
    command += [arg for field in fields for arg in ('-e', field)]
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=60)
    Path(str(path) + '.payloads.tsv').write_text(result.stdout)
    return verify_wire(result.stdout.splitlines(), mac, vni, df_preference)


if __name__ == '__main__':
    try:
        path, mac, vni, *preference = sys.argv[1:]
        print(json.dumps(verify_pcap(path, mac, int(vni),
                                     int(preference[0]) if preference else 100), sort_keys=True))
    except (ValueError, IndexError, subprocess.SubprocessError) as error:
        print(f'M121 wire assertion failed: {error}', file=sys.stderr)
        sys.exit(1)
