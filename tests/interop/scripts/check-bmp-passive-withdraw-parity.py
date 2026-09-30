#!/usr/bin/env python3
"""Compare peer-sent IPv4 withdrawals with passive Adj-RIB-In BMP bytes.

Input 1 is tshark TSV: ip.src, bgp.withdrawn_prefix (all occurrences).
Input 2 is the M81 raw sink's BMPv3 JSONL. Both are capture evidence,
not CLI command counts or collector state teardown.
"""

import collections
import ipaddress
import json
import sys
import tempfile

PEERS = ("10.0.0.2", "10.0.1.2")
EXPECTED = collections.Counter(
    (peer, f"198.18.{164 + i}.{n}/32")
    for i, peer in enumerate(PEERS)
    for n in range(1, 9)
    for _ in range(3)
)


def sent_withdrawals(path):
    counts = collections.Counter()
    with open(path, encoding="utf-8") as stream:
        for line in stream:
            peer, prefixes = line.rstrip("\n").split("\t", 1)
            if peer not in PEERS:
                raise ValueError(f"unexpected BGP sender {peer}")
            for prefix in prefixes.split(","):
                if prefix:
                    network = ipaddress.ip_network(prefix if "/" in prefix else prefix + "/32")
                    if network.prefixlen != 32:
                        raise ValueError(f"unexpected test prefix {network}")
                    counts[peer, str(network)] += 1
    return counts


def withdrawn_prefixes(pdu):
    if len(pdu) < 23 or pdu[:16] != b"\xff" * 16:
        raise ValueError("invalid embedded BGP message")
    length = int.from_bytes(pdu[16:18], "big")
    if length != len(pdu) or pdu[18] != 2:
        raise ValueError("invalid embedded BGP UPDATE length/type")
    width = int.from_bytes(pdu[19:21], "big")
    if 21 + width + 2 > length:
        raise ValueError("truncated BGP withdrawn routes")
    withdrawn = pdu[21 : 21 + width]
    prefixes = []
    offset = 0
    while offset < len(withdrawn):
        bits = withdrawn[offset]
        size = (bits + 7) // 8
        if bits > 32 or offset + 1 + size > len(withdrawn):
            raise ValueError("invalid IPv4 withdrawn prefix")
        address = withdrawn[offset + 1 : offset + 1 + size].ljust(4, b"\0")
        prefixes.append(str(ipaddress.ip_network((ipaddress.IPv4Address(address), bits))))
        offset += 1 + size
    return prefixes


def bmp_counts(path):
    withdrawals = collections.Counter()
    peerdowns = collections.Counter()
    peerups = collections.Counter()
    with open(path, encoding="utf-8") as stream:
        for line in stream:
            item = json.loads(line)
            raw = bytes.fromhex(item["hex"])
            if len(raw) < 6 or raw[0] != 3 or int.from_bytes(raw[1:5], "big") != len(raw):
                raise ValueError("invalid BMPv3 framing")
            if raw[5] not in (0, 2, 3):
                continue
            # RFC 7854 V/L and RFC 8671 O must all be clear. A is the
            # independent two-byte-AS indicator, irrelevant to this view.
            if len(raw) < 48 or raw[6] != 0 or raw[7] & 0xd0:
                raise ValueError("expected global pre-policy Adj-RIB-In peer")
            peer = str(ipaddress.IPv4Address(raw[28:32]))
            if peer not in PEERS:
                raise ValueError(f"unexpected BMP peer {peer}")
            if raw[5] == 2:
                peerdowns[peer] += 1
            elif raw[5] == 3:
                peerups[peer] += 1
            else:
                for prefix in withdrawn_prefixes(raw[48:]):
                    withdrawals[peer, prefix] += 1
    return withdrawals, peerdowns, peerups


def compare(sent, received, peerdowns, peerups):
    if sent != EXPECTED:
        raise ValueError(
            f"incomplete BGP wire ledger: missing={dict(EXPECTED - sent)}, "
            f"extra={dict(sent - EXPECTED)}"
        )
    for peer in PEERS:
        if peerdowns[peer] < 2 or peerups[peer] < 3:
            raise ValueError(
                f"{peer}: insufficient flaps: PeerDown={peerdowns[peer]}, "
                f"PeerUp={peerups[peer]}"
            )
    if sent != received:
        missing = sent - received
        extra = received - sent
        raise ValueError(f"withdrawal mismatch: missing={dict(missing)}, extra={dict(extra)}")
    return {
        peer: {
            "bgp_sent_withdrawals": sum(n for (identity, _), n in sent.items() if identity == peer),
            "bmp_received_withdrawals": sum(n for (identity, _), n in received.items() if identity == peer),
            "bmp_peerdowns": peerdowns[peer],
            "bmp_peerups": peerups[peer],
        }
        for peer in PEERS
    }


def self_test():
    route = b"\x20\xc6\x12\xa4\x01"  # 198.18.164.1/32
    body = len(route).to_bytes(2, "big") + route + b"\0\0"
    pdu = b"\xff" * 16 + (19 + len(body)).to_bytes(2, "big") + b"\x02" + body
    assert withdrawn_prefixes(pdu) == ["198.18.164.1/32"]
    peer_header = bytearray(42)
    peer_header[22:26] = ipaddress.IPv4Address(PEERS[0]).packed
    peer_header[1] = 0x40  # L: wrong post-policy view
    length = 6 + len(peer_header) + len(pdu)
    raw = b"\x03" + length.to_bytes(4, "big") + b"\x00" + bytes(peer_header) + pdu
    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as fixture:
        fixture.write(json.dumps({"hex": raw.hex()}) + "\n")
        fixture.flush()
        try:
            bmp_counts(fixture.name)
        except ValueError as error:
            assert "pre-policy Adj-RIB-In" in str(error)
        else:
            raise AssertionError("post-policy raw BMP input passed")
        raw = raw[:7] + b"\0" + raw[8:]
        fixture.seek(0)
        fixture.truncate()
        fixture.write(json.dumps({"hex": raw.hex()}) + "\n")
        fixture.flush()
        withdrawals, _, _ = bmp_counts(fixture.name)
        assert withdrawals == {(PEERS[0], "198.18.164.1/32"): 1}
    sent = EXPECTED.copy()
    down = collections.Counter({p: 2 for p in PEERS})
    up = collections.Counter({p: 3 for p in PEERS})
    assert compare(sent, sent.copy(), down, up)
    both_lost = sent - collections.Counter({(PEERS[0], "198.18.164.1/32"): 1})
    try:
        compare(both_lost, both_lost.copy(), down, up)
    except ValueError as error:
        assert "incomplete BGP wire ledger" in str(error)
    else:
        raise AssertionError("matching incomplete captures passed")
    for broken in (
        sent - collections.Counter({(PEERS[0], "198.18.164.1/32"): 1}),
        sent - collections.Counter({(PEERS[0], "198.18.164.1/32"): 1})
        + collections.Counter({(PEERS[1], "198.18.164.1/32"): 1}),
    ):
        try:
            compare(sent, broken, down, up)
        except ValueError as error:
            assert "withdrawal mismatch" in str(error)
        else:
            raise AssertionError("dropped/mislabeled withdrawal passed")
    print("PASS: wrong BMP view, incomplete wire ledger, dropped and mislabeled withdrawals fail")


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--self-test"]:
            self_test()
        elif len(sys.argv) == 3:
            print(json.dumps(compare(sent_withdrawals(sys.argv[1]), *bmp_counts(sys.argv[2])), indent=2))
        else:
            sys.exit(f"usage: {sys.argv[0]} BGP_WITHDRAWS_TSV BMP_JSONL | --self-test")
    except (AssertionError, ValueError) as error:
        sys.exit(f"FAIL: {error}")
