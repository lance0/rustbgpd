"""Strict checker for the controlled Type 2/5 fixture, not a general BGP decoder.

Keep raw common attribute TLVs and full announcement NLRIs for paired parity.
Withdrawals use route identity: their non-key ESI/label fields may be rebuilt.
"""

from collections import defaultdict
import hashlib


def require(ok, message):
    if not ok:
        raise ValueError(message)


def integer(data):
    return int.from_bytes(data, "big")


def route(kind, origin, index):
    rd = bytes((0, 1, 240, 1, origin // 200, origin % 200 + 1, 0, 1))
    prefix = rd + bytes(14)
    idx = index.to_bytes(3, "big")
    if kind == 2:
        return prefix + b"\x30\x02\x00\x00" + idx + b"\x20\x0a" + idx + (10100).to_bytes(3, "big")
    return prefix + b"\x20\x64" + (index + 0x400000).to_bytes(3, "big") + bytes(4) + (50000).to_bytes(3, "big")


def nlris(data, clients, widths):
    cursor = 0
    while cursor < len(data):
        require(cursor + 2 <= len(data), "truncated NLRI header")
        kind, length = data[cursor:cursor + 2]
        cursor += 2
        require(kind in (2, 5) and length == {2: 37, 5: 34}[kind], "unexpected EVPN fixture NLRI")
        body = data[cursor:cursor + length]
        require(len(body) == length, "truncated NLRI")
        cursor += length
        require(body[:4] == bytes((0, 1, 240, 1)) and body[6:8] == b"\0\1"
                and 1 <= body[5] <= 200, "unknown route distinguisher")
        origin = body[4] * 200 + body[5] - 1
        require(origin < clients and body[18:22] == bytes(4), "unknown origin or Ethernet tag")
        if kind == 2:
            require(body[22:26] == b"\x30\x02\0\0" and body[29:31] == b"\x20\x0a",
                    "unexpected Type 2 key")
            index = integer(body[26:29])
            require(body[31:34] == body[26:29], "Type 2 MAC/IP identity mismatch")
        else:
            require(body[22:24] == b"\x20\x64", "unexpected Type 5 prefix")
            index = integer(body[24:27]) - 0x400000
        require(0 <= index < 2 * widths[kind], "route outside fixture pool")
        yield (kind, origin, index), body


def frames(data):
    cursor = 0
    while cursor < len(data):
        require(data[cursor:cursor + 16] == b"\xff" * 16 and cursor + 19 <= len(data),
                "invalid/truncated BGP header")
        length, kind = integer(data[cursor + 16:cursor + 18]), data[cursor + 18]
        require(kind == 2 and 23 <= length <= 4096 and cursor + length <= len(data),
                "invalid/truncated UPDATE")
        body = data[cursor + 19:cursor + length]
        require(body[:2] == bytes(2), "unexpected IPv4 withdrawal")
        size = integer(body[2:4])
        require(size == len(body) - 4, "unexpected IPv4 NLRI or attribute length")
        attrs, raw, offset = {}, [], 4
        while offset < len(body):
            require(offset + 3 <= len(body), "truncated attribute header")
            start = offset
            flags, code = body[offset:offset + 2]
            header = 4 if flags & 16 else 3
            require(offset + header <= len(body), "truncated extended attribute header")
            size = integer(body[offset + 2:offset + header])
            offset += header
            require(code not in attrs and offset + size <= len(body), "duplicate/truncated attribute")
            attrs[code] = (flags, body[offset:offset + size])
            offset += size
            if code not in (14, 15):
                raw.append(body[start:offset])
        yield attrs, b"".join(raw)
        cursor += length


class Receiver:
    def __init__(self, peer, clients, type2, type5):
        self.peer, self.clients = peer, clients
        self.widths = {2: type2, 5: type5}
        self.state = {}
        self.events = defaultdict(list)
        self.eors = 0
        self.coverage = None
        self.transition = None
        self.transitioned = set()

    def begin_policy(self, old, new):
        require(old != new and self.transition is None, "invalid policy transition")
        self.transition = old, new
        self.transitioned.clear()

    def end_policy(self):
        require(self.transition is not None, "policy transition not started")
        require(set(self.state) <= self.transitioned, "policy transition missing live keys")
        self.transition = None

    def expected(self, shifts, shift2, shift5):
        require(len(shifts) == self.clients, "missing origin shifts")
        return {(kind, origin, (shifts[origin] * step + index) % (2 * self.widths[kind]))
                for origin in range(self.clients) if origin != self.peer
                for kind, step in ((2, shift2), (5, shift5))
                for index in range(self.widths[kind])}

    def begin_replay(self):
        require(self.state and self.coverage is None, "invalid refresh coverage start")
        self.coverage = set(self.state)
        self.replay_seen = set()
        self.replay_eors = 0

    def end_replay(self):
        require(self.coverage is not None and self.replay_eors >= 1,
                "quiescent refresh missing completed EoR")
        self.coverage = None

    def consume(self, data, communities):
        for attrs, raw in frames(data):
            require(set(attrs) <= {1, 2, 5, 8, 9, 10, 14, 15, 16}, "unexpected path attribute")
            require(14 in attrs or 15 in attrs, "UPDATE without EVPN reachability")
            if 15 in attrs:
                flags, value = attrs[15]
                require(flags & ~16 == 128 and value[:3] == b"\0\x19\x46", "invalid MP_UNREACH")
                if len(value) == 3:
                    require(set(attrs) == {15}, "EoR mixed with routes/attributes")
                    if self.coverage is not None:
                        require(self.coverage <= self.replay_seen, "EoR precedes covered-route replay")
                        self.replay_eors += 1
                    self.eors += 1
                for key, _ in nlris(value[3:], self.clients, self.widths):
                    require(key in self.state, "unknown or duplicate withdrawal")
                    del self.state[key]
                    self.events[key].append(("withdraw",))
            if 14 in attrs:
                flags, value = attrs[14]
                require(flags & ~16 == 128 and len(value) >= 9 and value[:4] == b"\0\x19\x46\4"
                        and value[8] == 0, "invalid MP_REACH")
                nh = value[4:8]
                expected_codes = {1, 2, 5, 8, 9, 10, 14, 16} | ({15} if 15 in attrs else set())
                require(set(attrs) == expected_codes, "missing prepared attribute")
                for code, expected in {1: (64, b"\0"), 2: (64, b""), 5: (64, (100).to_bytes(4, "big")),
                                       10: (128, b"\x0a\0\0\1"),
                                       16: (192, bytes.fromhex("0002fc0000000064030c000000000008"))}.items():
                    require((attrs[code][0] & ~16, attrs[code][1]) == expected,
                            f"wrong prepared attribute {code}")
                community = attrs[8]
                require(community[0] & ~16 == 192 and len(community[1]) == 4
                        and integer(community[1][:2]) == 65400
                        and integer(community[1][2:]) in communities, "wrong export community")
                for key, body in nlris(value[9:], self.clients, self.widths):
                    kind, origin, index = key
                    require(origin != self.peer, "self reflection")
                    require(body == route(kind, origin, index), "altered announcement NLRI")
                    octets = bytes((origin // 200, origin % 200 + 1))
                    require(nh == b"\x0a\1" + octets
                            and (attrs[9][0] & ~16, attrs[9][1]) == (128, b"\xf0\1" + octets),
                            "wrong next hop or originator")
                    if self.transition is not None:
                        current = integer(community[1][2:])
                        old, new = self.transition
                        require(current in (old, new), "policy outside directional transition")
                        if current == new:
                            self.transitioned.add(key)
                        else:
                            require(key not in self.transitioned, "policy rolled back after replacement")
                    token = (body, raw, nh)
                    self.state[key] = token
                    self.events[key].append(("announce", *token))
                    if self.coverage is not None:
                        self.replay_seen.add(key)

    def boundary(self, shifts, shift2, shift5, community):
        require(set(self.state) == self.expected(shifts, shift2, shift5), "boundary route set differs")
        # Every live value must have the current export policy. consume() also
        # validates every transient value, so a later good value cannot hide it.
        encoded = (65400).to_bytes(2, "big") + community.to_bytes(2, "big")
        for _, raw, _ in self.state.values():
            require(b"\xc0\x08\x04" + encoded in raw, "boundary has stale export policy")
        checksum = hashlib.sha256()
        for key, value in sorted(self.state.items()):
            checksum.update(repr(key).encode())
            for item in value:
                checksum.update(len(item).to_bytes(4, "big") + item)
        return checksum.hexdigest()

    def ordered_digest(self):
        checksum = hashlib.sha256()
        for key, events in sorted(self.events.items()):
            checksum.update(repr((key, events)).encode())
        self.events.clear()
        return checksum.hexdigest()
