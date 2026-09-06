#!/usr/bin/env python3
"""Passive, controlled M112 source; framing is shared with the M94 peer."""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import struct
import time
from pathlib import Path

from evpn_peer_sync_oracle import Route, attribute, type2
from m94_as4_oracle import BgpReader, send_message
from m105_capture_oracle import capabilities, need, update
from m112_capture_oracle import (
    FAMILY, PHASES, RD, RR_ID, RR_SOURCE, SID, SOURCE, SOURCE_ID, STRUCTURE,
    SURVIVOR, TARGET,
)

STATE = Path("/tmp/m112-source.json")
COMMAND = Path("/tmp/m112-command.json")


def prefix_sid(*, malformed: bool = False) -> bytes:
    # RFC 9252 sections 3/6.2.1; RFC 8986 End.DT2U is 0x0017.
    structure = struct.pack("!BH", 1, 7 if malformed else 6) + bytes(STRUCTURE)
    info = b"\0" + ipaddress.IPv6Address(SID).packed + b"\0\0\x17\0" + structure
    service = b"\0" + struct.pack("!BH", 1, len(info)) + info
    return struct.pack("!BH", 6, len(service)) + service


def nlri(mac: str) -> bytes:
    # The shared helper copies this integer into all 24 label bits. Here it
    # is RFC 9252 implicit-null 0x000030, not a VXLAN VNI.
    return type2(Route(RD, mac, esi=bytes(10).hex(":"), vni=0x30))


def announcement(mac: str, *, malformed: bool = False) -> bytes:
    reach = FAMILY + b"\x10" + ipaddress.IPv6Address(SOURCE).packed + b"\0" + nlri(mac)
    attrs = attribute(1, b"\0", 0x40) + attribute(2, b"", 0x40)
    attrs += attribute(5, struct.pack("!I", 100), 0x40)
    attrs += attribute(16, bytes.fromhex("0002fde900000070"), 0xC0)
    attrs += attribute(14, reach) + attribute(40, prefix_sid(malformed=malformed), 0xC0)
    return b"\0\0" + struct.pack("!H", len(attrs)) + attrs


def withdrawal(mac: str) -> bytes:
    attrs = attribute(15, FAMILY + nlri(mac))
    return b"\0\0" + struct.pack("!H", len(attrs)) + attrs


def phase_updates(phase: str) -> list[bytes]:
    return {
        "baseline": [announcement(TARGET), announcement(SURVIVOR)],
        "malformed": [announcement(TARGET, malformed=True)],
        "recovery": [announcement(TARGET)],
        "withdraw": [withdrawal(TARGET)],
        "cleanup": [withdrawal(SURVIVOR)],
    }[phase]


def open_body() -> bytes:
    caps = b"\x01\x04\x00\x19\x00\x46\x41\x04" + struct.pack("!I", 65001)
    optional = bytes([2, len(caps)]) + caps
    return struct.pack("!BHH4sB", 4, 65001, 90, ipaddress.IPv4Address(SOURCE_ID).packed,
                       len(optional)) + optional


def save(state: dict) -> None:
    temporary = STATE.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, sort_keys=True) + "\n")
    temporary.replace(STATE)


def serve() -> None:
    need(not STATE.exists() and not COMMAND.exists(), "stale M112 source state")
    state = {"listening": False, "established": False, "phase": "", "sent": [],
             "received": [], "error": ""}
    try:
        with socket.socket(socket.AF_INET6) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((SOURCE, 179))
            listener.listen(1)
            listener.settimeout(90)
            state["listening"] = True
            save(state)
            connection, address = listener.accept()
            with connection:
                need(address[0] == RR_SOURCE, "unexpected BGP connection source")
                connection.settimeout(20)
                reader = BgpReader(connection)
                send_message(connection, 1, open_body())
                kind, body = reader.read_message()
                need(kind == 1, "expected OPEN")
                caps = capabilities(body)
                need(len(body) == 10 + body[9] and body[1:3] == struct.pack("!H", 65001)
                     and body[5:9] == ipaddress.IPv4Address(RR_ID).packed,
                     "RR OPEN identity differs")
                need(bytes.fromhex("00190046") in caps.get(1, [])
                     and caps.get(65) == [struct.pack("!I", 65001)],
                     "RR EVPN/AS4 capability missing")
                state["received"].append({"type": kind, "body": body.hex()})
                send_message(connection, 4)
                need(reader.read_message() == (4, b""), "expected KEEPALIVE")
                state["established"] = True
                save(state)
                connection.settimeout(0.2)
                deadline = time.monotonic() + 600
                last_send = last_receive = time.monotonic()
                phase_index = 0
                while time.monotonic() < deadline:
                    if COMMAND.exists():
                        phase = json.loads(COMMAND.read_text())["phase"]
                        if phase != state["phase"]:
                            need(phase_index < len(PHASES) and phase == PHASES[phase_index],
                                 "nonsequential source command")
                            for payload in phase_updates(phase):
                                send_message(connection, 2, payload)
                                state["sent"].append({"phase": phase, "body": payload.hex()})
                            phase_index += 1
                            state["phase"] = phase
                    try:
                        kind, body = reader.read_message()
                        state["received"].append({"type": kind, "body": body.hex()})
                        last_receive = time.monotonic()
                        if kind == 2:
                            withdrawn, attrs, announced = update(body)
                            need(not withdrawn and not announced
                                 and attrs == {15: (0x80, FAMILY)},
                                 "unexpected reverse UPDATE (only EVPN EOR is allowed)")
                        else:
                            need((kind, body) == (4, b""), "unexpected established BGP message")
                    except socket.timeout:
                        pass
                    now = time.monotonic()
                    need(now - last_receive < 90, "RR hold-time expired")
                    if now - last_send >= 15:
                        send_message(connection, 4)
                        last_send = now
                    state["last_receive_age_seconds"] = now - last_receive
                    save(state)
                raise TimeoutError("M112 source lifetime exceeded")
    except Exception as error:
        state["error"] = str(error)
        state["established"] = False
        save(state)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("serve", "command"))
    parser.add_argument("phase", nargs="?", choices=PHASES)
    args = parser.parse_args()
    if args.mode == "serve":
        serve()
    else:
        need(args.phase is not None, "command requires phase")
        temporary = COMMAND.with_suffix(".tmp")
        temporary.write_text(json.dumps({"phase": args.phase}) + "\n")
        temporary.replace(COMMAND)


if __name__ == "__main__":
    main()
