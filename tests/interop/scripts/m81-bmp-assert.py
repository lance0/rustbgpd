#!/usr/bin/env python3
"""M81 byte-level BMP assertions over the raw-sink JSONL captures.

Each subcommand checks one wire property of the BMPv4 TLV framing
(draft-ietf-grow-bmp-tlv-20) or the Path Marking TLV
(draft-ietf-grow-bmp-path-marking-tlv-05) against the raw bytes
recorded by bmp-raw-sink.py, and exits 0 (pass) / 1 (fail) with a
one-line diagnostic. The v3 stream (port 11019) serves as the
byte-reference for the "v4 differs only in framing" comparisons.

These are offset-level checks against the drafts' wire figures — the
independent dissector oracle for the same bytes is tshark 4.4 (driven
from the test script); the semantic v3 oracles are pmacct and gobmp.
"""

import json
import sys

V3_FILE = "/tmp/bmp-raw-11019.jsonl"
V4_FILE = "/tmp/bmp-raw-11020.jsonl"

PER_PEER_LEN = 42
RM, STATS, PEER_DOWN, PEER_UP, INIT, TERM = 0, 1, 2, 3, 4, 5

TLV_BGP_MESSAGE = 7   # tlv-20 §5.2
TLV_PATH_MARKING = 5  # path-marking-05 §7
STATS_TLV_STATS = 1   # tlv-20 §5.4
STATUS_BEST = 0x2     # path-marking-05 §3.1
REASON_LOCAL_PREF = 0x0003  # path-marking-05 §3.2


def load(path):
    msgs = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    m = json.loads(line)
                    m["raw"] = bytes.fromhex(m["hex"])
                    msgs.append(m)
    except FileNotFoundError:
        pass
    return msgs


def u16(b, o):
    return (b[o] << 8) | b[o + 1]


def u32(b, o):
    return (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]


def peer_hdr(m):
    """(peer_type, flags, peer_ip_str) from the per-peer header."""
    b = m["raw"]
    ptype, flags = b[6], b[7]
    addr = b[16:32]
    if flags & 0x80:  # V flag: IPv6 address
        ip = ":".join(f"{u16(addr, i):x}" for i in range(0, 16, 2))
    else:
        ip = ".".join(str(x) for x in addr[12:16])
    return ptype, flags, ip


def walk_rm_tlvs(m):
    """[(type, index, value_bytes)] for a v4 RM message. Raises on
    malformed framing (walk must consume the message exactly)."""
    b = m["raw"]
    off = 6 + PER_PEER_LEN
    tlvs = []
    while off < len(b):
        t, ln = u16(b, off), u16(b, off + 2)
        idx = u16(b, off + 4)
        val = b[off + 6 : off + 6 + ln]
        if len(val) != ln:
            raise ValueError(f"truncated TLV type {t} at offset {off}")
        tlvs.append((t, idx, val))
        off += 6 + ln
    if off != len(b):
        raise ValueError(f"TLV walk overran message by {off - len(b)}")
    return tlvs


def rm_pdu(m):
    """The BGP UPDATE PDU bytes of an RM message (either version)."""
    if m["version"] == 4:
        for t, _idx, val in walk_rm_tlvs(m):
            if t == TLV_BGP_MESSAGE:
                return val
        raise ValueError("v4 RM without BGP Message TLV 7")
    return m["raw"][6 + PER_PEER_LEN :]


def pdu_kind(pdu):
    """'announce' | 'withdraw' | 'eor' for a BGP UPDATE PDU."""
    wlen = u16(pdu, 19)
    palen = u16(pdu, 21 + wlen)
    if wlen == 0 and palen == 0:
        return "eor"
    if wlen > 0:
        return "withdraw"
    # Walk path attributes for MP_REACH(14) / MP_UNREACH(15).
    off, end = 23 + wlen, 23 + wlen + palen
    kinds = set()
    while off < end:
        flags, atype = pdu[off], pdu[off + 1]
        if flags & 0x10:
            alen, off2 = u16(pdu, off + 2), off + 4
        else:
            alen, off2 = pdu[off + 2], off + 3
        if atype == 15:
            kinds.add("eor" if alen <= 3 else "withdraw")
        if atype == 14:
            kinds.add("announce")
        off = off2 + alen
    if "announce" in kinds:
        return "announce"
    if "withdraw" in kinds:
        return "withdraw"
    if "eor" in kinds:
        return "eor"
    return "announce" if len(pdu) > end else "eor"


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def ok(msg):
    print(f"OK: {msg}")
    sys.exit(0)


# ── subcommands ──────────────────────────────────────────────────────


def cmd_versions(port, expect):
    msgs = load(f"/tmp/bmp-raw-{port}.jsonl")
    if not msgs:
        fail(f"no messages on :{port}")
    bad = [m for m in msgs if m["version"] != int(expect)]
    if bad:
        fail(f":{port} has {len(bad)} messages with version != {expect}")
    types = {m["type"] for m in msgs}
    need = {RM, PEER_UP, INIT}
    if not need <= types:
        fail(f":{port} missing message types {need - types}")
    ok(f"all {len(msgs)} messages on :{port} carry version {expect} "
       f"(types seen: {sorted(types)})")


def _only_version_differs(a, b):
    return (
        len(a) == len(b)
        and a[0] == 3
        and b[0] == 4
        and a[1:] == b[1:]
    )


def cmd_init_equal():
    v3 = [m for m in load(V3_FILE) if m["type"] == INIT]
    v4 = [m for m in load(V4_FILE) if m["type"] == INIT]
    if not v3 or not v4:
        fail("missing Initiation on a sink port")
    if not _only_version_differs(v3[0]["raw"], v4[0]["raw"]):
        fail("v4 Initiation is not byte-identical-except-version to v3")
    ok(f"Initiation v3/v4 byte-identical except version byte "
       f"({len(v3[0]['raw'])} bytes)")


def cmd_peerup_equal(peer_ip):
    v3 = [m for m in load(V3_FILE) if m["type"] == PEER_UP and peer_hdr(m)[2] == peer_ip]
    v4 = [m for m in load(V4_FILE) if m["type"] == PEER_UP and peer_hdr(m)[2] == peer_ip]
    if not v3 or not v4:
        fail(f"missing PeerUp for {peer_ip} on a sink port")
    a, b = v3[0]["raw"], v4[0]["raw"]
    if not _only_version_differs(a, b):
        fail(f"v4 PeerUp for {peer_ip} not byte-identical-except-version "
             f"(v3 {len(a)}B vs v4 {len(b)}B)")
    ok(f"PeerUp for {peer_ip} v3/v4 byte-identical except version byte")


def cmd_rm_tlv7():
    msgs = [m for m in load(V4_FILE) if m["type"] == RM]
    if not msgs:
        fail("no v4 RM messages")
    for m in msgs:
        tlvs = walk_rm_tlvs(m)  # raises if the walk doesn't consume exactly
        bgp = [(i, t) for i, (t, _x, _v) in enumerate(tlvs) if t == TLV_BGP_MESSAGE]
        if len(bgp) != 1:
            fail(f"RM seq {m['seq']} conn {m['conn']}: {len(bgp)} BGP Message TLVs")
        t, idx, val = tlvs[bgp[0][0]]
        if idx != 0:
            fail(f"RM seq {m['seq']}: BGP Message TLV index {idx} != 0")
        pdu_len = u16(val, 16)
        if pdu_len != len(val):
            fail(f"RM seq {m['seq']}: TLV length {len(val)} != BGP PDU "
                 f"length field {pdu_len} (length must exclude the index)")
    ok(f"all {len(msgs)} v4 RM messages: exact TLV walk, single BGP Message "
       f"TLV type 7 index 0, TLV length == PDU length (excludes index)")


def cmd_rm_pdu_equality():
    def pdus(msgs, want):
        out = []
        for m in msgs:
            if m["type"] != RM:
                continue
            ptype, flags, _ip = peer_hdr(m)
            cat = "locrib" if ptype == 3 else ("ribout" if flags & 0x10 else "ribin")
            if cat == want:
                out.append(rm_pdu(m).hex())
        return sorted(set(out))

    v3, v4 = load(V3_FILE), load(V4_FILE)
    for cat in ("ribin", "ribout", "locrib"):
        a, b = pdus(v3, cat), pdus(v4, cat)
        if a != b:
            only3 = set(a) - set(b)
            only4 = set(b) - set(a)
            fail(f"{cat}: PDU sets differ between v3 and v4 streams "
                 f"(v3-only {len(only3)}, v4-only {len(only4)})")
    ok("rib-in / rib-out / loc-rib RM PDU sets are byte-equal across the "
       "v3 stream and the v4 BGP Message TLVs")


def cmd_stats_v4_wrap():
    v4 = [m for m in load(V4_FILE) if m["type"] == STATS]
    v3 = [m for m in load(V3_FILE) if m["type"] == STATS]
    if not v4 or not v3:
        fail(f"missing stats reports (v3 {len(v3)}, v4 {len(v4)})")
    v3_bodies = {m["raw"][6 + PER_PEER_LEN :] for m in v3}
    for m in v4:
        b = m["raw"]
        off = 6 + PER_PEER_LEN
        t, ln = u16(b, off), u16(b, off + 2)
        if t != STATS_TLV_STATS:
            fail(f"v4 stats seq {m['seq']}: first TLV type {t} != 1")
        val = b[off + 4 :]
        if len(val) != ln:
            fail(f"v4 stats seq {m['seq']}: Stats TLV length {ln} != "
                 f"remaining {len(val)}")
        if val not in v3_bodies:
            fail(f"v4 stats seq {m['seq']}: unwrapped Stats TLV value not "
                 f"found among v3 stats bodies")
    ok(f"all {len(v4)} v4 Stats Reports wrap Stats Count + data in Stats "
       f"TLV code 1; unwrapped values byte-match v3 stats bodies")


def _stat_types(body):
    """Stat type codes in an RFC 7854 stats body (count + TLVs)."""
    count = u32(body, 0)
    off, types = 4, []
    for _ in range(count):
        t, ln = u16(body, off), u16(body, off + 2)
        types.append(t)
        off += 4 + ln
    return types


def cmd_stats_locrib_counts():
    msgs = [m for m in load(V3_FILE) if m["type"] == STATS]
    loc = [m for m in msgs if peer_hdr(m)[0] == 3]
    peer = [m for m in msgs if peer_hdr(m)[0] == 0]
    if not loc:
        fail("no stats report for the Loc-RIB instance peer (type 3)")
    types = _stat_types(loc[-1]["raw"][6 + PER_PEER_LEN :])
    if 8 not in types or 10 not in types:
        fail(f"loc-rib stats types {types} missing 8 and/or 10")
    if not peer:
        fail("no stats report for a regular peer")
    ptypes = _stat_types(peer[-1]["raw"][6 + PER_PEER_LEN :])
    if 7 not in ptypes:
        fail(f"peer stats types {ptypes} missing 7 (Adj-RIB-In)")
    ok(f"stats: loc-rib peer carries types 8+10 ({types}); regular peer "
       f"carries type 7 ({ptypes})")


def _marking_tlvs(m):
    return [(idx, val) for t, idx, val in walk_rm_tlvs(m) if t == TLV_PATH_MARKING]


def cmd_locrib_marking():
    msgs = [m for m in load(V4_FILE) if m["type"] == RM]
    loc_ann = loc_wd = 0
    for m in msgs:
        ptype, _f, _ip = peer_hdr(m)
        kind = pdu_kind(rm_pdu(m))
        marks = _marking_tlvs(m)
        if ptype != 3:
            continue
        if kind == "announce":
            loc_ann += 1
            if len(marks) != 1:
                fail(f"loc-rib announce seq {m['seq']} conn {m['conn']}: "
                     f"{len(marks)} Path Marking TLVs (want 1)")
            _idx, val = marks[0]
            if len(val) not in (4, 6):
                fail(f"loc-rib announce seq {m['seq']}: marking value len "
                     f"{len(val)}")
            status = u32(val, 0)
            if not status & STATUS_BEST:
                fail(f"loc-rib announce seq {m['seq']}: status {status:#x} "
                     f"lacks Best (0x2)")
        elif marks:
            loc_wd += 1
            fail(f"loc-rib {kind} seq {m['seq']}: carries a Path Marking "
                 f"TLV but must not")
    if loc_ann == 0:
        fail("no loc-rib announces on the v4 stream")
    ok(f"all {loc_ann} v4 loc-rib announces carry exactly one Path Marking "
       f"TLV with Best set; withdraws/EoR carry none")


def cmd_reason_local_pref(prefix_hex):
    msgs = [m for m in load(V4_FILE) if m["type"] == RM]
    for m in msgs:
        if peer_hdr(m)[0] != 3:
            continue
        pdu = rm_pdu(m)
        if prefix_hex not in pdu.hex() or pdu_kind(pdu) != "announce":
            continue
        for _idx, val in _marking_tlvs(m):
            if len(val) == 6 and u16(val, 4) == REASON_LOCAL_PREF:
                ok(f"loc-rib announce for NLRI {prefix_hex} carries reason "
                   f"0x0003 (local preference), status {u32(val, 0):#x}")
    fail(f"no loc-rib announce for NLRI {prefix_hex} with reason 0x0003")


def cmd_no_marking_outside_locrib():
    msgs = [m for m in load(V4_FILE) if m["type"] == RM]
    n = 0
    for m in msgs:
        if peer_hdr(m)[0] == 3:
            continue
        n += 1
        tlv_types = [t for t, _i, _v in walk_rm_tlvs(m)]
        if tlv_types != [TLV_BGP_MESSAGE]:
            fail(f"non-loc-rib RM seq {m['seq']}: TLVs {tlv_types} != [7]")
    if n == 0:
        fail("no rib-in/rib-out RM messages on the v4 stream")
    ok(f"all {n} v4 rib-in/rib-out RM messages carry exactly the BGP "
       f"Message TLV and no Path Marking")


def cmd_dump(conn_arg):
    """Post-reconnect loc-rib dump on the v4 port: PeerUp, then
    status-only Best markings on every dump announce, closed by exactly
    4 End-of-RIB RMs (ipv4u/ipv6u/vpnv4/vpnv6)."""
    conn = int(conn_arg)
    msgs = [m for m in load(V4_FILE) if m["conn"] == conn]
    if not msgs:
        fail(f"no messages on v4 conn {conn}")
    if not any(m["type"] == PEER_UP and peer_hdr(m)[0] == 3 for m in msgs):
        fail(f"v4 conn {conn}: no loc-rib PeerUp in the reconnect dump")
    eor = 0
    dump_ann = 0
    for m in msgs:
        if m["type"] != RM or peer_hdr(m)[0] != 3:
            continue
        if eor >= 4:
            break  # live phase after the dump closed
        kind = pdu_kind(rm_pdu(m))
        if kind == "eor":
            eor += 1
            continue
        if kind != "announce":
            fail(f"v4 conn {conn} dump: unexpected {kind} before EoR #4")
        dump_ann += 1
        marks = _marking_tlvs(m)
        if len(marks) != 1 or len(marks[0][1]) != 4:
            fail(f"v4 conn {conn} dump announce seq {m['seq']}: want one "
                 f"status-only (4-byte) Path Marking TLV, got {marks}")
        if not u32(marks[0][1], 0) & STATUS_BEST:
            fail(f"v4 conn {conn} dump announce seq {m['seq']}: Best unset")
    if eor != 4:
        fail(f"v4 conn {conn} dump: {eor} End-of-RIB markers (want 4)")
    if dump_ann == 0:
        fail(f"v4 conn {conn} dump: no announces before EoR")
    ok(f"v4 conn {conn} reconnect dump: loc-rib PeerUp, {dump_ann} "
       f"status-only Best-marked announces, exactly 4 EoRs")


def cmd_term(port):
    msgs = load(f"/tmp/bmp-raw-{port}.jsonl")
    if not msgs or msgs[-1]["type"] != TERM:
        fail(f":{port} last message type is not Termination "
             f"({msgs[-1]['type'] if msgs else 'none'})")
    ok(f":{port} stream closed with a Termination message")


def cmd_locrib_peerdown_reason6(port):
    msgs = load(f"/tmp/bmp-raw-{port}.jsonl")
    for m in msgs:
        if m["type"] == PEER_DOWN and peer_hdr(m)[0] == 3:
            reason = m["raw"][6 + PER_PEER_LEN]
            if reason == 6:
                ok(f":{port} loc-rib instance PeerDown carries reason 6")
            fail(f":{port} loc-rib PeerDown reason {reason} != 6")
    fail(f":{port} no PeerDown for the loc-rib instance peer")


def main():
    cmds = {
        "versions": cmd_versions,
        "init_equal": cmd_init_equal,
        "peerup_equal": cmd_peerup_equal,
        "rm_tlv7": cmd_rm_tlv7,
        "rm_pdu_equality": cmd_rm_pdu_equality,
        "stats_v4_wrap": cmd_stats_v4_wrap,
        "stats_locrib_counts": cmd_stats_locrib_counts,
        "locrib_marking": cmd_locrib_marking,
        "reason_local_pref": cmd_reason_local_pref,
        "no_marking_outside_locrib": cmd_no_marking_outside_locrib,
        "dump": cmd_dump,
        "term": cmd_term,
        "locrib_peerdown_reason6": cmd_locrib_peerdown_reason6,
    }
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print(f"usage: {sys.argv[0]} <{'|'.join(cmds)}> [args]")
        sys.exit(2)
    try:
        cmds[sys.argv[1]](*sys.argv[2:])
    except Exception as e:  # malformed framing surfaces as a failure
        fail(f"{sys.argv[1]}: {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
