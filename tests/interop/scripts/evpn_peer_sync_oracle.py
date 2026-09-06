#!/usr/bin/env python3
"""Bounded Type-2 wire helpers for the controlled same-ESI peer proof.

Uses the existing independent BGP framing/attribute reader. This is a test
peer/oracle, not a second EVPN implementation or a general EVPN decoder.
RFC 7432 sections 7.2/7.7 define Type 2 and MAC Mobility; RFC 8365 section
5.1.3 puts the unshifted 24-bit VNI in the label field for VXLAN.
"""

from __future__ import annotations

import ipaddress
import math
import re
import struct
from dataclasses import asdict, dataclass

from m94_as4_oracle import BgpReader, parse_update, send_message

ESI = bytes.fromhex("00000000000000000001")
RT = bytes.fromhex("0002fde800000064")
VXLAN = bytes.fromhex("030c000000000008")
FAMILY = bytes.fromhex("001946")  # AFI 25, SAFI 70
COUNTERS = (
    "evpn_duplicate_mac_moves_total",
    "evpn_duplicate_mac_threshold_exceeded_total",
    "evpn_duplicate_ip_moves_total",
    "evpn_duplicate_ip_threshold_exceeded_total",
)


@dataclass(frozen=True)
class Route:
    rd: str
    mac: str
    ip: str = ""
    tag: int = 0
    esi: str = ESI.hex(":")
    vni: int = 100

    def key(self) -> tuple[str, int, str, str]:
        return self.rd, self.tag, self.mac, self.ip


def type2(route: Route) -> bytes:
    """Encode this lab's IPv4-admin RD and one-label VXLAN Type 2."""
    administrator, assigned = route.rd.split(":")
    rd = b"\x00\x01" + ipaddress.IPv4Address(administrator).packed
    rd += struct.pack("!H", int(assigned))
    mac = bytes.fromhex(route.mac.replace(":", ""))
    esi = bytes.fromhex(route.esi.replace(":", ""))
    if len(mac) != 6 or len(esi) != 10 or not 1 <= route.vni <= 0xFFFFFF:
        raise ValueError("invalid MAC, ESI, or VNI")
    ip = ipaddress.ip_address(route.ip).packed if route.ip else b""
    body = rd + esi + struct.pack("!I", route.tag) + b"\x30" + mac
    body += bytes([len(ip) * 8]) + ip + route.vni.to_bytes(3, "big")
    return bytes([2, len(body)]) + body


def attribute(code: int, value: bytes, flags: int = 0x80) -> bytes:
    if len(value) > 255:
        return bytes([flags | 0x10, code]) + struct.pack("!H", len(value)) + value
    return bytes([flags, code, len(value)]) + value


def announcement(routes: list[Route], sequence: int, *, next_hop: str,
                 route_target: bytes = RT) -> bytes:
    """Return an UPDATE body; only the source chooses the sequence."""
    if len(route_target) != 8:
        raise ValueError("route target must be eight bytes")
    mobility = b"\x06\x00\x00\x00" + struct.pack("!I", sequence)
    reach = FAMILY + b"\x04" + ipaddress.IPv4Address(next_hop).packed + b"\x00"
    reach += b"".join(type2(route) for route in routes)
    attrs = attribute(1, b"\x00", 0x40) + attribute(2, b"", 0x40)
    attrs += attribute(16, route_target + VXLAN + mobility, 0xC0)
    attrs += attribute(14, reach)
    if 23 + len(attrs) > 4096:
        raise ValueError("test UPDATE exceeds ordinary BGP frame size")
    return b"\x00\x00" + struct.pack("!H", len(attrs)) + attrs


def withdrawal(routes: list[Route]) -> bytes:
    attrs = attribute(15, FAMILY + b"".join(type2(route) for route in routes))
    if 23 + len(attrs) > 4096:
        raise ValueError("test UPDATE exceeds ordinary BGP frame size")
    return b"\x00\x00" + struct.pack("!H", len(attrs)) + attrs


def decode_type2s(nlri: bytes) -> list[Route]:
    """Frame every EVPN NLRI; decode only the proof's one-label Type 2s."""
    routes = []
    while nlri:
        if len(nlri) < 2 or len(nlri) < 2 + nlri[1]:
            raise ValueError("truncated EVPN NLRI")
        kind, length = nlri[:2]
        body, nlri = nlri[2:2 + length], nlri[2 + length:]
        if kind != 2:
            continue
        if len(body) < 33 or body[22] != 48 or body[29] not in (0, 32, 128):
            raise ValueError("invalid Type-2 MAC/IP lengths")
        ip_length = body[29] // 8
        if len(body) != 33 + ip_length or body[:2] != b"\x00\x01":
            raise ValueError("unexpected Type-2 length or RD encoding in proof")
        rd = f"{ipaddress.IPv4Address(body[2:6])}:{int.from_bytes(body[6:8], 'big')}"
        ip = str(ipaddress.ip_address(body[30:30 + ip_length])) if ip_length else ""
        routes.append(Route(rd, body[23:29].hex(":"), ip,
                            int.from_bytes(body[18:22], "big"), body[8:18].hex(":"),
                            int.from_bytes(body[-3:], "big")))
    return routes


class Oracle:
    """Track received wire state, retaining exact announcements for replay proof."""

    def __init__(self) -> None:
        self.live: dict[tuple[str, int, str, str], dict] = {}
        self.events: list[dict] = []

    def apply(self, body: bytes) -> None:
        update = parse_update(body)
        if update.nlri or update.withdrawn:
            raise ValueError("unexpected classic IPv4 NLRI on EVPN test session")
        changes = []
        for code in (15, 14):
            values = update.attrs.get(code, [])
            if len(values) > 1:
                raise ValueError("duplicate MP attribute")
            if not values:
                continue
            value = values[0]
            if value[:3] != FAMILY:
                raise ValueError("unexpected MP family")
            next_hop = ""
            if code == 14:
                if len(value) < 9 or value[3] != 4 or value[8] != 0:
                    raise ValueError("invalid test MP_REACH next hop/reserved byte")
                next_hop = str(ipaddress.IPv4Address(value[4:8]))
                value = value[9:]
            else:
                value = value[3:]
            for route in decode_type2s(value):
                changes.append((code, route, next_hop))
        # Validate the whole UPDATE before publishing any state from it.
        communities = update.attrs.get(16, [])
        if len(communities) > 1 or any(len(value) % 8 for value in communities):
            raise ValueError("malformed extended communities")
        ecs = [value[i:i + 8] for value in communities for i in range(0, len(value), 8)]
        mobility = [ec for ec in ecs if ec[:2] == b"\x06\x00"]
        if len(mobility) > 1:
            raise ValueError("ambiguous duplicate MAC Mobility community")
        sequence = int.from_bytes(mobility[0][4:], "big") if mobility else 0
        sticky = bool(mobility and mobility[0][2] & 1)
        for code, route, next_hop in changes:
            event = {"action": "announce" if code == 14 else "withdraw", **asdict(route)}
            if code == 14:
                event.update(sequence=sequence, sticky=sticky, next_hop=next_hop,
                             communities=[ec.hex() for ec in ecs])
                self.live[route.key()] = event
            else:
                self.live.pop(route.key(), None)
            self.events.append(event)

    def expect(self, routes: list[Route], sequence: int, *, next_hop: str) -> None:
        for route in routes:
            row = self.live.get(route.key())
            if row is None or any(row[name] != value for name, value in asdict(route).items()):
                raise AssertionError(f"missing or mismatched route: {route}")
            if (row["sequence"], row["sticky"], row["next_hop"]) != (sequence, False, next_hop):
                raise AssertionError(f"wrong mobility/next hop: {row}")
            mobility = [ec for ec in row["communities"] if ec.startswith("0600")]
            if mobility and mobility != ["06000000" + sequence.to_bytes(4, "big").hex()]:
                raise AssertionError(f"noncanonical MAC Mobility community: {row}")
            if RT.hex() not in row["communities"]:
                raise AssertionError(f"missing required RT community: {row}")
            # RFC 8365 sections 5.1.3/6 permit locally configured encapsulation
            # when this EC is absent. This proof fixes that profile to VXLAN.
            encapsulations = [ec for ec in row["communities"] if ec.startswith("030c")]
            if encapsulations and encapsulations != [VXLAN.hex()]:
                raise AssertionError(f"unexpected encapsulation for fixed VXLAN profile: {row}")

    def expect_owned_keys(self, routes: list[Route], *, rd: str) -> None:
        actual = {key for key in self.live if key[0] == rd}
        if actual != {route.key() for route in routes}:
            raise AssertionError(f"unexpected set of locally owned Type-2 keys: {actual}")

    def expect_absent(self, *, rd: str, mac: str) -> None:
        if any(row["rd"] == rd and row["mac"] == mac for row in self.live.values()):
            raise AssertionError(f"unexpected local ownership: {rd}/{mac}")

    def expect_transition(self, routes: list[Route], sequence: int, *, next_hop: str,
                          after: int) -> None:
        """Require fresh correct announcements, including intermediate wire states."""
        self.expect(routes, sequence, next_hop=next_hop)
        if not 0 <= after <= len(self.events):
            raise AssertionError("invalid event checkpoint")
        expected = {route.key(): route for route in routes}
        seen = set()
        for row in self.events[after:]:
            key = row["rd"], row["tag"], row["mac"], row["ip"]
            if key in expected and row["action"] == "announce":
                check = Oracle()
                check.live[key] = row
                check.expect([expected[key]], sequence, next_hop=next_hop)
                seen.add(key)
        if seen != expected.keys():
            raise AssertionError("missing fresh announcement after phase checkpoint")

    def expect_quiet(self, *, after: int, rd: str) -> None:
        if not 0 <= after <= len(self.events):
            raise AssertionError("invalid event checkpoint")
        if any(row["rd"] == rd for row in self.events[after:]):
            raise AssertionError("unexpected local route change during replay")

    def expect_never_owned(self, *, rd: str, mac: str) -> None:
        self.expect_absent(rd=rd, mac=mac)
        if any(row["rd"] == rd and row["mac"] == mac and row["action"] == "announce"
               for row in self.events):
            raise AssertionError("transient peer-only local ownership")

    def read(self, reader: BgpReader) -> None:
        kind, body = reader.read_message()
        if kind == 2:
            self.apply(body)
        elif kind != 4:
            raise ValueError(f"unexpected established BGP message type {kind}")


def send_announcement(connection, routes: list[Route], sequence: int, *, next_hop: str) -> None:
    send_message(connection, 2, announcement(routes, sequence, next_hop=next_hop))


def duplicate_totals(scrape: str) -> dict[str, dict]:
    """Aggregate all label sets. Missing lazy series is explicit, never NaN.

    Caller must obtain a complete successful scrape. A required process sample
    rejects empty/error bodies; HTTP failures must propagate before this call.
    """
    result = {}
    for family in ("process_start_time_seconds", *COUNTERS):
        values = []
        pattern = re.compile(r"^" + re.escape(family) + r"(?:\{[^}]*\})?\s+(\S+)(?:\s+[0-9]+)?$")
        for line in scrape.splitlines():
            match = pattern.fullmatch(line)
            if match:
                value = float(match[1])
                if not math.isfinite(value) or value < 0:
                    raise ValueError(f"invalid counter value for {family}")
                values.append(value)
            elif line.startswith((family + " ", family + "{")):
                raise ValueError(f"malformed sample for {family}")
        if family == "process_start_time_seconds":
            if len(values) != 1 or values[0] <= 0:
                raise ValueError("missing or ambiguous process identity in metrics scrape")
        else:
            result[family] = {"present": bool(values), "series": len(values), "total": sum(values)}
    return result
