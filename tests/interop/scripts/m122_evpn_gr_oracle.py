#!/usr/bin/env python3
"""Exact EVPN Types 1–5 state and raw OPEN/EoR witnesses for M122."""

import ipaddress
import struct
from collections import defaultdict

from m105_capture_oracle import capabilities, messages, need, reassemble, update

SOURCE = "10.0.122.2"
RR = "10.0.122.1"
RR_CLIENT = "10.0.123.1"
CLIENT = "10.0.123.2"
RT = int.from_bytes(struct.pack("!BBHI", 0, 2, 65001, 122), "big")
VXLAN = int.from_bytes(bytes.fromhex("030c000000000008"), "big")
LLGR_STALE = 0xFFFF0006
LABEL = 10122


def esi(s):
    return bytes.fromhex("0000000000000000120" + str(s))


def nlri(route_type, s):
    rd = struct.pack("!HHI", 0, 65001, route_type * 10 + s)
    tag = bytes(4)
    label = LABEL.to_bytes(3, "big")
    originator = ipaddress.IPv4Address(SOURCE).packed
    if route_type == 1:
        body = rd + esi(s) + tag + label
    elif route_type == 2:
        body = rd + bytes(10) + tag + b"\x30" + bytes.fromhex("02000000120" + str(s))
        body += b"\x20" + ipaddress.IPv4Address(f"192.0.2.{s}").packed + label
    elif route_type == 3:
        body = rd + tag + b"\x20" + originator
    elif route_type == 4:
        body = rd + esi(s) + b"\x20" + originator
    elif route_type == 5:
        body = rd + bytes(10) + tag + b"\x20"
        body += ipaddress.IPv4Address(f"203.0.113.{s}").packed + bytes(4) + label
    else:
        raise ValueError("M122 only admits Types 1–5")
    return bytes([route_type, len(body)]) + body


def expected_nlri(sets):
    return {nlri(t, s).hex() for s in sets for t in range(1, 6)}


def client_key(t, s):
    rd = f"[rd:65001:{t}{s}]"
    e = f"ESI_ARBITRARY | 00:00:00:00:00:00:00:12:0{s}"
    return {
        1: f"[type:A-D]{rd}[esi:{e}][etag:0]",
        2: f"[type:macadv]{rd}[etag:0][mac:02:00:00:00:12:0{s}][ip:192.0.2.{s}]",
        3: f"[type:multicast]{rd}[etag:0][ip:{SOURCE}]",
        4: f"[type:esi]{rd}[esi:{e}][ip:{SOURCE}]",
        5: f"[type:Prefix]{rd}[etag:0][prefix:203.0.113.{s}/32]",
    }[t]


def check_client(rows, sets, llgr=False):
    need(isinstance(rows, dict), "client RIB is not an object")
    want = {client_key(t, s) for s in sets for t in range(1, 6)}
    need(set(rows) == want, f"client identities differ: {set(rows) ^ want}")
    for key, paths in rows.items():
        need(isinstance(paths, list) and len(paths) == 1, f"{key}: expected one path")
        attrs = paths[0]["attrs"]
        communities = [c for a in attrs if a["type"] == 8 for c in a["communities"]]
        need((LLGR_STALE in communities) == llgr, f"{key}: LLGR_STALE differs")


def check_rr(rows, sets, llgr=False):
    need(isinstance(rows, list), "RR RIB is not an array")
    want = {(t, f"65001:{t}{s}") for s in sets for t in range(1, 6)}
    got = {(r["route_type"], r["rd"]) for r in rows}
    need(got == want and len(rows) == len(want), f"RR identities differ: {got ^ want}")
    for row in rows:
        t, s = row["route_type"], int(row["rd"][-1])
        need(row["peer"] == SOURCE and row["next_hop"] == SOURCE, "RR source/next-hop differs")
        need(row["tunnel_type"] == 8, "RR VXLAN encapsulation differs")
        need(sorted(row["extended_communities"]) == sorted([RT, VXLAN]), "RR extended communities differ")
        need(("LLGR_STALE" in row["communities"]) == llgr, "RR LLGR_STALE differs")
        if t != 4:
            need(row["ethernet_tag"] == "0", "RR tag differs")
        if t in (1, 4):
            need(row["esi"] == ":".join(f"{b:02x}" for b in esi(s)), "RR ESI differs")
        if t in (1, 2, 5):
            need(row["label"] == LABEL, "RR VNI differs")
        if t == 2:
            need(row["mac"] == f"02:00:00:00:12:0{s}" and row["ip"] == f"192.0.2.{s}", "RR MAC/IP differs")
        if t in (3, 4):
            need(row["ip"] == SOURCE, "RR originator differs")
        if t == 5:
            need(row["prefix"] == f"203.0.113.{s}/32" and row["gateway"] == "0.0.0.0", "RR prefix/gateway differs")


def split_evpn(raw):
    result = []
    while raw:
        need(len(raw) >= 2 and len(raw) >= raw[1] + 2, "truncated EVPN NLRI")
        length = raw[1] + 2
        result.append(raw[:length].hex())
        raw = raw[length:]
    return result


def nlri_key(encoded):
    # Withdrawals reconstruct the key with non-key labels/GW/ESI zeroed.
    raw = bytes.fromhex(encoded)
    t, body = raw[0], raw[2:]
    lengths = {1: 25, 2: 37, 3: 17, 4: 23, 5: 34}
    need(t in lengths and raw[1] == lengths[t] and len(body) == lengths[t], "unexpected M122 NLRI shape")
    key = {1: body[:22], 2: body[:8] + body[18:34], 3: body, 4: body,
           5: body[:8] + body[18:27]}[t]
    return f"{t}:{key.hex()}"


def validate_attributes(attrs):
    for code in (14, 15):
        if code in attrs:
            need(attrs[code][0] in (0x80, 0x90), "MP attribute flags must be optional and nontransitive")
    if 8 in attrs:
        flags, value = attrs[8]
        # Partial and extended-length bits are legal for optional transitive
        # communities; reserved bits and malformed values are not.
        need(flags in (0xC0, 0xD0, 0xE0, 0xF0), "COMMUNITIES flags differ")
        need(bool(value) and len(value) % 4 == 0, "COMMUNITIES length must be a positive multiple of four")


def client_withdrawals(lines):
    parts = defaultdict(list)
    for line in lines:
        stream, src, dst, seq, payload = line.rstrip("\n").split("\t")
        if (src, dst) == (RR_CLIENT, CLIENT) and payload:
            parts[stream].append((int(seq), bytes.fromhex(payload.replace(":", ""))))
    need(bool(parts), "client TCP stream absent")
    found = set()
    for segments in parts.values():
        for typ, body in messages(reassemble(segments)):
            if typ == 2:
                _, attrs, _ = update(body)
                validate_attributes(attrs)
                if 15 in attrs:
                    raw = attrs[15][1]
                    need(raw[:3] == bytes.fromhex("001946"), "client withdrawal family differs")
                    found.update(nlri_key(n) for n in split_evpn(raw[3:]))
    return found


def admit_open(body):
    caps = capabilities(body)
    need(bytes.fromhex("00190046") in caps.get(1, []), "OPEN lacks EVPN MP25/70")
    gr = caps.get(64, [])
    need(len(gr) == 1 and len(gr[0]) >= 6 and (len(gr[0]) - 2) % 4 == 0, "invalid GR capability")
    flags_time = int.from_bytes(gr[0][:2], "big")
    need(flags_time & 0xFFF > 0, "GR restart time is zero")
    tuples = [gr[0][i:i + 4] for i in range(2, len(gr[0]), 4)]
    evpn = [v for v in tuples if v[:3] == bytes.fromhex("001946")]
    need(len(evpn) == 1, "GR lacks one EVPN tuple")
    llgr = caps.get(71, [])
    need(len(llgr) == 1 and len(llgr[0]) % 7 == 0, "invalid LLGR capability")
    lt = [llgr[0][i:i + 7] for i in range(0, len(llgr[0]), 7) if llgr[0][i:i + 3] == bytes.fromhex("001946")]
    need(len(lt) == 1 and int.from_bytes(lt[0][4:], "big") > 0, "LLGR lacks positive EVPN timer")
    return {"mp": "00190046", "gr": gr[0].hex(), "llgr": lt[0].hex(),
            "restart": bool(flags_time & 0x8000), "forwarding": bool(evpn[0][3] & 0x80)}


def completed_messages(segments):
    # Reuse the strict full-stream decoder, then attach the capture row at
    # which every byte through each message end had arrived. This includes
    # preceding gaps when segments arrive out of order or are retransmitted.
    data = reassemble([(sequence, payload) for sequence, payload, _ in segments])
    base = min(sequence for sequence, _, _ in segments)
    first_seen = [None] * len(data)
    for sequence, payload, ordinal in segments:
        for offset in range(sequence - base, sequence - base + len(payload)):
            if first_seen[offset] is None:
                first_seen[offset] = ordinal
    ready = 0
    for offset, ordinal in enumerate(first_seen):
        need(ordinal is not None, "TCP byte has no capture position")
        ready = max(ready, ordinal)
        first_seen[offset] = ready
    end = 0
    for typ, body in messages(data):
        end += len(body) + 19
        yield (first_seen[end - 1], end), typ, body


def check_client_order(events, eor_position):
    survivors = {nlri_key(n) for n in expected_nlri([1])}
    omitted = {nlri_key(n) for n in expected_nlri([2])}
    promoted, retired = set(), set()
    witness = {"source_eor_completion": eor_position, "omitted_withdrawals": [],
               "llgr_promotion_completion": None, "expiry_withdrawals": []}
    for position, announced, llgr, withdrawn in sorted(events, key=lambda event: event[0]):
        need(not llgr & withdrawn, "same UPDATE promotes and withdraws an EVPN key")
        need(not announced & retired, "client reannounces an EVPN key after its withdrawal")
        if withdrawn & omitted:
            need(position > eor_position, "omitted withdrawal precedes complete source EoR")
            witness["omitted_withdrawals"].append({"completion": position, "keys": sorted(withdrawn & omitted)})
        if withdrawn & survivors:
            need(promoted == survivors, "survivor withdrawal precedes all five LLGR promotions")
            witness["expiry_withdrawals"].append({"completion": position, "keys": sorted(withdrawn & survivors)})
        promoted.update(llgr)
        if promoted == survivors and witness["llgr_promotion_completion"] is None:
            witness["llgr_promotion_completion"] = position
        retired.update(withdrawn)
    return witness


def analyze_wire(lines):
    parts = defaultdict(list)
    for ordinal, line in enumerate(lines, 1):
        fields = line.rstrip("\n").split("\t")
        need(len(fields) == 5, "capture row must have five fields")
        stream, src, dst, seq, payload = fields
        if payload:
            parts[(stream, src, dst)].append((int(seq), bytes.fromhex(payload.replace(":", "")), ordinal))
    opens, announced, withdrawn, promoted, eors = [], defaultdict(set), defaultdict(set), set(), []
    client_events = []
    restarted = False
    initial_sources = []
    for (stream, src, dst), segments in parts.items():
        decoded = completed_messages(segments)
        stream_announced = set()
        is_restart = False
        source_opens = 0
        for position, typ, body in decoded:
            need(typ != 3, "captured BGP NOTIFICATION")
            if typ == 1:
                witness = admit_open(body)
                opens.append({"stream": stream, "source": src, "destination": dst, **witness})
                is_restart = src == SOURCE and dst == RR and witness["restart"]
                if (src, dst) == (SOURCE, RR):
                    source_opens += 1
                if is_restart:
                    need(witness["forwarding"], "restart OPEN lacks EVPN F bit")
                    restarted = True
            if typ != 2:
                continue
            old_withdraw, attrs, old_announce = update(body)
            need(not old_withdraw and not old_announce, "unexpected legacy NLRI")
            validate_attributes(attrs)
            event_announced, event_promoted, event_withdrawn = set(), set(), set()
            if 14 in attrs:
                reach = attrs[14][1]
                need(reach[:4] == bytes.fromhex("00194604") and reach[4:8] == ipaddress.IPv4Address(SOURCE).packed, "MP_REACH family/next-hop differs")
                need(reach[8] == 0, "MP_REACH reserved byte differs")
                routes = set(split_evpn(reach[9:]))
                need(routes <= expected_nlri([1, 2]), "unexpected EVPN NLRI")
                ext = attrs[16][1]
                need(len(ext) == 16 and {int.from_bytes(ext[i:i + 8], "big") for i in range(0, len(ext), 8)} == {RT, VXLAN}, "wire RT/VXLAN differs")
                if any(route.startswith("03") for route in routes):
                    need(attrs[22][1] == b"\x00\x06" + LABEL.to_bytes(3, "big") + ipaddress.IPv4Address(SOURCE).packed, "wire IMET PMSI differs")
                if src == RR_CLIENT and dst == CLIENT:
                    event_announced = {nlri_key(n) for n in routes}
                    need(attrs[9][1] == ipaddress.IPv4Address(SOURCE).packed and attrs[10][1] == ipaddress.IPv4Address(RR).packed, "reflection attributes differ")
                    if 8 in attrs and LLGR_STALE.to_bytes(4, "big") in [attrs[8][1][i:i + 4] for i in range(0, len(attrs[8][1]), 4)]:
                        promoted.update(routes)
                        event_promoted = event_announced
                announced[(src, dst)].update(routes)
                stream_announced.update(routes)
            if 15 in attrs:
                unreach = attrs[15][1]
                need(unreach[:3] == bytes.fromhex("001946"), "MP_UNREACH family differs")
                if len(unreach) == 3:
                    need(set(attrs) == {15}, "EoR carries extra attributes")
                    if is_restart:
                        need(stream_announced == expected_nlri([1]), "restart EoR precedes exactly the refreshed five")
                        eors.append({"stream": stream, "source": src, "mp_unreach": unreach.hex(),
                                     "update_body": body.hex(), "refreshed_nlri": sorted(stream_announced),
                                     "completion": position})
                else:
                    routes = split_evpn(unreach[3:])
                    withdrawn[(src, dst)].update(routes)
                    event_withdrawn = {nlri_key(n) for n in routes}
            if (src, dst) == (RR_CLIENT, CLIENT):
                client_events.append((position, event_announced, event_promoted, event_withdrawn))
        if (src, dst) == (SOURCE, RR):
            need(source_opens == 1, "source TCP stream must contain exactly one OPEN")
            if is_restart:
                need(stream_announced == expected_nlri([1]), "restart stream must announce exactly the refreshed five")
            else:
                initial_sources.append({"stream": stream, "nlri": sorted(stream_announced)})
    need(len(initial_sources) == 1, "expected one initial non-restarting source stream")
    need(set(initial_sources[0]["nlri"]) == expected_nlri([1, 2]), "initial source stream must announce all ten identities")
    need(restarted and len(eors) == 1, "missing unique source restart OPEN/EoR")
    for pair in [(SOURCE, RR), (RR_CLIENT, CLIENT)]:
        need(announced[pair] == expected_nlri([1, 2]), f"{pair}: initial ten raw identities differ")
    need(promoted == expected_nlri([1]), "client lacks five exact LLGR wire announcements")
    withdrawn_keys = {nlri_key(n) for n in withdrawn[(RR_CLIENT, CLIENT)]}
    need(withdrawn_keys == {nlri_key(n) for n in expected_nlri([1, 2])}, "client wire withdrawal keys differ")
    order = check_client_order(client_events, eors[0]["completion"])
    return {"opens": opens, "restart_eor": eors, "initial_source": initial_sources[0],
            "initial_nlri": initial_sources[0]["nlri"],
            "llgr_nlri": sorted(promoted), "withdrawn_keys": sorted(withdrawn_keys),
            "withdrawn_nlri": sorted(withdrawn[(RR_CLIENT, CLIENT)]), "client_order": order}
