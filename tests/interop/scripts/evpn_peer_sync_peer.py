#!/usr/bin/env python3
"""Controlled EVPN source and independent wire receiver for one bounded proof."""

import argparse
import ipaddress
import json
import socket
import struct
import time
from pathlib import Path

from evpn_peer_sync_oracle import FAMILY, Oracle, Route, announcement, withdrawal
from m94_as4_oracle import BgpReader, parse_open, send_message, write_receipt

DUT = "10.99.0.1"
SOURCE = "10.99.0.2"
DUT_RD = DUT + ":100"
SOURCE_RD = SOURCE + ":100"
MACS = {name: "02:aa:bb:cc:dd:" + suffix for name, suffix in
        zip("abcdef", ("11", "22", "33", "44", "55", "66"), strict=True)}
IPS = {"b": ("192.0.2.22", "2001:db8::22"), "c": ("192.0.2.33", "2001:db8::33")}
LOCAL = [Route(DUT_RD, MACS["a"])] + [
    Route(DUT_RD, MACS[name], ip) for name in ("b", "c") for ip in IPS[name]]
CONTROLS = [Route(DUT_RD, MACS[name]) for name in ("e", "f")]
SOURCES = [Route(SOURCE_RD, MACS["a"]), Route(SOURCE_RD, MACS["b"]),
           Route(SOURCE_RD, MACS["c"], IPS["c"][0]),
           # Peer-only D shares B's IPs: it must not become a local IP owner.
           *(Route(SOURCE_RD, MACS["d"], ip) for ip in IPS["b"]),
           Route(SOURCE_RD, MACS["f"], tag=1)]


def command_updates(sequence: int | None) -> list[bytes]:
    """The fixed proof supports two announcement values and a complete withdrawal."""
    wrong_rt = [Route(SOURCE_RD, MACS["e"])]
    if sequence is None:
        return [withdrawal(SOURCES + wrong_rt)]
    if sequence not in (3, 9):
        raise ValueError("unsupported proof sequence")
    return [announcement(routes, sequence, next_hop=SOURCE, route_target=rt)
            for routes, rt in ((SOURCES, bytes.fromhex("0002fde800000064")),
                               (wrong_rt, bytes.fromhex("0002fde8000000c8")))]


def open_body() -> bytes:
    caps = b"\x01\x04\x00\x19\x00\x46\x41\x04" + struct.pack("!I", 65000)
    optional = bytes([2, len(caps)]) + caps
    return struct.pack("!BHH4sB", 4, 65000, 30, ipaddress.IPv4Address(SOURCE).packed,
                       len(optional)) + optional


def validate_open(body: bytes) -> None:
    parsed = parse_open(body)
    if (parsed["my_as"], parsed["router_id"], parsed["hold_time"],
            parsed["advertised_as4"]) != (65000, DUT, 30, True):
        raise ValueError(f"unexpected DUT OPEN: {parsed}")
    if len(body) != 10 + body[9]:
        raise ValueError("trailing OPEN bytes")
    optional, found = body[10:], False
    while optional:
        if len(optional) < 2 or len(optional) < 2 + optional[1]:
            raise ValueError("truncated OPEN parameter")
        kind, size = optional[:2]
        value, optional = optional[2:2 + size], optional[2 + size:]
        if kind != 2:
            continue
        while value:
            if len(value) < 2 or len(value) < 2 + value[1]:
                raise ValueError("truncated OPEN capability")
            code, size = value[:2]
            capability, value = value[2:2 + size], value[2 + size:]
            found |= code == 1 and capability == FAMILY[:2] + b"\0" + FAMILY[2:]
    if not found:
        raise ValueError("DUT did not negotiate EVPN")


def serve(directory: Path, run_id: str) -> None:
    receipt = {"run_id": run_id, "established": False, "ack": 0, "checkpoint": 0,
               "events": [], "live": [], "sent": [], "received": []}
    path = str(directory / "peer.json")
    try:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((SOURCE, 179))
            listener.listen(1)
            listener.settimeout(45)
            connection, address = listener.accept()
            with connection:
                if address[0] != DUT:
                    raise ValueError(f"unexpected source: {address}")
                connection.settimeout(10)
                reader, oracle = BgpReader(connection), Oracle()
                send_message(connection, 1, open_body())
                kind, body = reader.read_message()
                if kind != 1:
                    raise ValueError("expected OPEN")
                validate_open(body)
                send_message(connection, 4)
                if reader.read_message() != (4, b""):
                    raise ValueError("expected initial KEEPALIVE")
                receipt["established"] = True
                connection.settimeout(0.2)
                deadline, last_send, last_receive = time.monotonic() + 240, time.monotonic(), time.monotonic()
                while time.monotonic() < deadline:
                    command_path = directory / "command.json"
                    if command_path.exists():
                        command = json.loads(command_path.read_text())
                        if command["run_id"] != run_id:
                            raise ValueError("command belongs to another run")
                        if command["id"] > receipt["ack"]:
                            if command["id"] != receipt["ack"] + 1:
                                raise ValueError("nonsequential command")
                            receipt["checkpoint"] = len(oracle.events)
                            for update in command_updates(command["sequence"]):
                                send_message(connection, 2, update)
                                receipt["sent"].append({"command": command["id"], "body": update.hex()})
                            receipt["ack"] = command["id"]
                    try:
                        kind, body = reader.read_message()
                        receipt["received"].append({"type": kind, "body": body.hex()})
                        if kind == 2:
                            oracle.apply(body)
                        elif (kind, body) != (4, b""):
                            raise ValueError(f"unexpected established BGP message: {kind}")
                        last_receive = time.monotonic()
                    except socket.timeout:
                        pass
                    if time.monotonic() - last_receive > 30:
                        raise TimeoutError("DUT hold timer expired")
                    if time.monotonic() - last_send > 10:
                        send_message(connection, 4)
                        last_send = time.monotonic()
                    receipt.update(events=oracle.events, live=list(oracle.live.values()),
                                   heartbeat=time.time())
                    write_receipt(path, receipt)
                raise TimeoutError("proof exceeded bounded peer lifetime")
    except Exception as error:
        receipt.update(established=False, error=str(error), heartbeat=time.time())
        write_receipt(path, receipt)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("run_id")
    args = parser.parse_args()
    serve(args.directory, args.run_id)
