#!/usr/bin/env python3
"""Raw eBGP peer for the M100 Partial-flag receiver differential."""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MARKER = b"\xff" * 16
TYPE_OPEN = 1
TYPE_UPDATE = 2
TYPE_NOTIFICATION = 3
TYPE_KEEPALIVE = 4
CAP_MULTIPROTOCOL = 1
CAP_BGP_ROLE = 9
CAP_FOUR_OCTET_AS = 65
ROLE_ROUTE_SERVER = 1
ROLE_ROUTE_SERVER_CLIENT = 2
ATTR_OPTIONAL = 0x80
ATTR_TRANSITIVE = 0x40
ATTR_PARTIAL = 0x20
ATTR_ORIGIN = 1
ATTR_AS_PATH = 2
ATTR_NEXT_HOP = 3
LOCAL_AS = 64512
OBSERVER_AS = 64513
RAW_ADDR = "10.105.0.10"
OBSERVER_ADDR = "10.105.0.11"
CANDIDATE = "198.51.100.0/24"
SURVIVOR = "198.51.101.0/24"
EVENTS = Path("/tmp/m100-events.jsonl")
READY = Path("/tmp/m100-ready")
STOP = Path("/tmp/m100-stop")
CASES = ("med", "originator_id", "cluster_list", "mp_reach", "mp_unreach")
EXPECTED = {
    "10.105.0.1": ("rustbgpd", 65001),
    "10.105.0.2": ("bird", 65002),
    "10.105.0.3": ("openbgpd", 65003),
    "10.105.0.5": ("frr", 65005),
}
EXPECTED_BAD_HEX = {
    "med": "a0040400000064",
    "originator_id": "a00904c0000209",
    "cluster_list": "a00a04c000020a",
    "mp_reach": "a00e0d000101040a69000a0018c63364",
    "mp_unreach": "a00f0700010118c63364",
}
EXPECTED_OUTCOMES = {
    ("rustbgpd", "med"): "accepted",
    ("rustbgpd", "originator_id"): "accepted",
    ("rustbgpd", "cluster_list"): "accepted",
    ("rustbgpd", "mp_reach"): "reset",
    ("rustbgpd", "mp_unreach"): "reset",
    ("bird", "med"): "accepted",
    ("bird", "originator_id"): "accepted",
    ("bird", "cluster_list"): "accepted",
    ("bird", "mp_reach"): "accepted",
    ("bird", "mp_unreach"): "same_session_withdrawal",
    ("openbgpd", "med"): "reset",
    ("openbgpd", "originator_id"): "reset",
    ("openbgpd", "cluster_list"): "reset",
    ("openbgpd", "mp_reach"): "reset",
    ("openbgpd", "mp_unreach"): "reset",
    ("frr", "med"): "treat_as_withdraw",
    ("frr", "originator_id"): "treat_as_withdraw",
    ("frr", "cluster_list"): "treat_as_withdraw",
    ("frr", "mp_reach"): "reset",
    ("frr", "mp_unreach"): "reset",
}

event_lock = threading.Lock()
session_condition = threading.Condition()
sessions: dict[tuple[str, str], "Session"] = {}
epochs: dict[tuple[str, str], int] = {}
errors: list[str] = []
stop_event = threading.Event()
phase_lock = threading.Lock()
active_case: str | None = None
active_phase: str | None = None


def emit(peer: str, event: str, **fields: Any) -> None:
    row = {"peer": peer, "event": event, **fields}
    with event_lock:
        with EVENTS.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def message(message_type: int, body: bytes = b"") -> bytes:
    return MARKER + struct.pack("!HB", 19 + len(body), message_type) + body


def capability(code: int, value: bytes) -> bytes:
    return bytes([code, len(value)]) + value


def open_message(local_addr: str, local_as: int) -> bytes:
    capabilities = b"".join(
        (
            capability(CAP_MULTIPROTOCOL, struct.pack("!HBB", 1, 0, 1)),
            capability(CAP_FOUR_OCTET_AS, struct.pack("!I", local_as)),
            capability(CAP_BGP_ROLE, bytes([ROLE_ROUTE_SERVER_CLIENT])),
        )
    )
    optional = bytes([2, len(capabilities)]) + capabilities
    body = struct.pack(
        "!BHHIB", 4, local_as, 90, int(ipaddress.IPv4Address(local_addr)), len(optional)
    )
    return message(TYPE_OPEN, body + optional)


def recvn(stream: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise EOFError("peer closed the TCP stream")
        data.extend(chunk)
    return bytes(data)


def read_message(stream: socket.socket) -> tuple[int, bytes]:
    header = recvn(stream, 19)
    if header[:16] != MARKER:
        raise RuntimeError("BGP marker mismatch")
    length, message_type = struct.unpack("!HB", header[16:19])
    if not 19 <= length <= 4096:
        raise RuntimeError(f"invalid BGP message length {length}")
    return message_type, recvn(stream, length - 19)


def parse_capabilities(body: bytes, expected_as: int) -> None:
    if len(body) < 10 or body[0] != 4:
        raise RuntimeError("invalid receiver OPEN")
    if int.from_bytes(body[1:3], "big") != expected_as:
        raise RuntimeError("receiver OPEN AS mismatch")
    optional_length = body[9]
    optional = body[10 : 10 + optional_length]
    if len(optional) != optional_length:
        raise RuntimeError("truncated receiver OPEN parameters")
    capabilities: dict[int, list[bytes]] = {}
    cursor = 0
    while cursor < len(optional):
        if cursor + 2 > len(optional) or optional[cursor] != 2:
            raise RuntimeError("unexpected receiver OPEN parameter")
        length = optional[cursor + 1]
        value = optional[cursor + 2 : cursor + 2 + length]
        if len(value) != length:
            raise RuntimeError("truncated receiver capability parameter")
        cursor += 2 + length
        cap_cursor = 0
        while cap_cursor < len(value):
            if cap_cursor + 2 > len(value):
                raise RuntimeError("truncated receiver capability")
            code = value[cap_cursor]
            cap_length = value[cap_cursor + 1]
            cap_value = value[cap_cursor + 2 : cap_cursor + 2 + cap_length]
            if len(cap_value) != cap_length:
                raise RuntimeError("truncated receiver capability value")
            capabilities.setdefault(code, []).append(cap_value)
            cap_cursor += 2 + cap_length
    if capabilities.get(CAP_FOUR_OCTET_AS) != [expected_as.to_bytes(4, "big")]:
        raise RuntimeError("receiver four-octet-AS capability mismatch")
    if struct.pack("!HBB", 1, 0, 1) not in capabilities.get(CAP_MULTIPROTOCOL, []):
        raise RuntimeError("receiver did not advertise IPv4 unicast")
    roles = capabilities.get(CAP_BGP_ROLE, [])
    if roles and roles != [bytes([ROLE_ROUTE_SERVER])]:
        raise RuntimeError(f"receiver advertised incompatible BGP Role {roles!r}")


def nlri(prefix: str) -> bytes:
    network = ipaddress.IPv4Network(prefix)
    octets = (network.prefixlen + 7) // 8
    return bytes([network.prefixlen]) + network.network_address.packed[:octets]


def attribute(flags: int, code: int, value: bytes) -> bytes:
    if len(value) > 255:
        raise ValueError("M100 attributes use one-octet lengths")
    return bytes([flags, code, len(value)]) + value


def common_attributes() -> bytes:
    return b"".join(
        (
            attribute(ATTR_TRANSITIVE, ATTR_ORIGIN, b"\x00"),
            attribute(ATTR_TRANSITIVE, ATTR_AS_PATH, b"\x02\x01" + struct.pack("!I", LOCAL_AS)),
            attribute(
                ATTR_TRANSITIVE,
                ATTR_NEXT_HOP,
                ipaddress.IPv4Address(RAW_ADDR).packed,
            ),
        )
    )


def special_attribute(case: str, flags: int) -> bytes:
    values = {
        "med": (4, struct.pack("!I", 100)),
        "originator_id": (9, ipaddress.IPv4Address("192.0.2.9").packed),
        "cluster_list": (10, ipaddress.IPv4Address("192.0.2.10").packed),
        "mp_reach": (
            14,
            struct.pack("!HBB", 1, 1, 4)
            + ipaddress.IPv4Address(RAW_ADDR).packed
            + b"\x00"
            + nlri(CANDIDATE),
        ),
        "mp_unreach": (15, struct.pack("!HB", 1, 1) + nlri(CANDIDATE)),
    }
    code, value = values[case]
    return attribute(flags, code, value)


def update(attributes: bytes, announced: str | None = None) -> bytes:
    body = b"\x00\x00" + len(attributes).to_bytes(2, "big") + attributes
    if announced is not None:
        body += nlri(announced)
    return message(TYPE_UPDATE, body)


def withdrawal() -> bytes:
    withdrawn = nlri(CANDIDATE) + nlri(SURVIVOR)
    return message(TYPE_UPDATE, len(withdrawn).to_bytes(2, "big") + withdrawn + b"\x00\x00")


def parse_nlri(data: bytes) -> list[str]:
    prefixes: list[str] = []
    cursor = 0
    while cursor < len(data):
        prefix_length = data[cursor]
        cursor += 1
        if prefix_length > 32:
            raise RuntimeError(f"invalid IPv4 prefix length {prefix_length}")
        octet_count = (prefix_length + 7) // 8
        encoded = data[cursor : cursor + octet_count]
        if len(encoded) != octet_count:
            raise RuntimeError("truncated IPv4 NLRI")
        cursor += octet_count
        address = ipaddress.IPv4Address(encoded + b"\x00" * (4 - octet_count))
        prefixes.append(str(ipaddress.IPv4Network((address, prefix_length), strict=False)))
    return prefixes


def parse_update(body: bytes) -> dict[str, Any]:
    if len(body) < 4:
        raise RuntimeError("truncated receiver UPDATE")
    withdrawn_length = int.from_bytes(body[:2], "big")
    withdrawn_end = 2 + withdrawn_length
    if withdrawn_end + 2 > len(body):
        raise RuntimeError("truncated receiver withdrawn-routes field")
    withdrawn = parse_nlri(body[2:withdrawn_end])
    attributes_length = int.from_bytes(body[withdrawn_end : withdrawn_end + 2], "big")
    attributes_start = withdrawn_end + 2
    attributes_end = attributes_start + attributes_length
    if attributes_end > len(body):
        raise RuntimeError("truncated receiver path-attributes field")
    attributes: list[dict[str, Any]] = []
    cursor = attributes_start
    while cursor < attributes_end:
        if cursor + 3 > attributes_end:
            raise RuntimeError("truncated receiver path attribute")
        flags = body[cursor]
        code = body[cursor + 1]
        cursor += 2
        if flags & 0x10:
            if cursor + 2 > attributes_end:
                raise RuntimeError("truncated extended path-attribute length")
            length = int.from_bytes(body[cursor : cursor + 2], "big")
            cursor += 2
        else:
            length = body[cursor]
            cursor += 1
        if cursor + length > attributes_end:
            raise RuntimeError("path-attribute value crosses the attribute boundary")
        value = body[cursor : cursor + length]
        if len(value) != length:
            raise RuntimeError("truncated receiver path-attribute value")
        cursor += length
        attributes.append({"flags": flags, "code": code, "value": value.hex()})
        if code == 15 and len(value) >= 3:
            afi = int.from_bytes(value[:2], "big")
            safi = value[2]
            if afi == 1 and safi == 1:
                withdrawn.extend(parse_nlri(value[3:]))
    announced = parse_nlri(body[attributes_end:])
    for item in attributes:
        if item["code"] != 14:
            continue
        value = bytes.fromhex(item["value"])
        if len(value) < 5:
            continue
        afi = int.from_bytes(value[:2], "big")
        safi = value[2]
        next_hop_length = value[3]
        nlri_start = 5 + next_hop_length
        if afi == 1 and safi == 1 and nlri_start <= len(value):
            announced.extend(parse_nlri(value[nlri_start:]))
    return {"announced": announced, "withdrawn": withdrawn, "attributes": attributes}


def baseline_update(case: str) -> bytes:
    attributes = common_attributes()
    if case in {"med", "originator_id", "cluster_list"}:
        attributes += special_attribute(case, ATTR_OPTIONAL)
    return update(attributes, CANDIDATE)


def malformed_update(case: str) -> tuple[bytes, str]:
    malformed = special_attribute(case, ATTR_OPTIONAL | ATTR_PARTIAL)
    if case == "mp_unreach":
        payload = update(malformed)
    elif case == "mp_reach":
        payload = update(common_attributes() + malformed)
    else:
        payload = update(common_attributes() + malformed, CANDIDATE)
    return payload, malformed.hex()


@dataclass
class Session:
    peer: str
    channel: str
    epoch: int
    stream: socket.socket
    lock: threading.Lock = field(default_factory=threading.Lock)
    alive: bool = True

    def send(self, payload: bytes) -> None:
        with self.lock:
            self.stream.sendall(payload)


def handle_connection(stream: socket.socket, remote: str) -> None:
    peer, expected_as = EXPECTED[remote]
    local = stream.getsockname()[0]
    if local == RAW_ADDR:
        channel = "source"
        local_as = LOCAL_AS
    elif local == OBSERVER_ADDR:
        channel = "observer"
        local_as = OBSERVER_AS
    else:
        raise RuntimeError(f"connection used unexpected local address {local}")
    session_key = (peer, channel)
    session: Session | None = None
    try:
        stream.settimeout(1)
        stream.sendall(open_message(local, local_as))
        saw_open = False
        saw_keepalive = False
        sent_keepalive = False
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (saw_open and saw_keepalive):
            try:
                message_type, body = read_message(stream)
            except TimeoutError:
                continue
            if message_type == TYPE_OPEN:
                parse_capabilities(body, expected_as)
                saw_open = True
                if not sent_keepalive:
                    stream.sendall(message(TYPE_KEEPALIVE))
                    sent_keepalive = True
            elif message_type == TYPE_KEEPALIVE:
                saw_keepalive = True
            elif message_type == TYPE_NOTIFICATION:
                raise RuntimeError("receiver sent a notification during handshake")
        if not (saw_open and saw_keepalive):
            raise RuntimeError("receiver handshake did not complete")
        with session_condition:
            epoch = epochs.get(session_key, 0) + 1
            epochs[session_key] = epoch
            session = Session(peer=peer, channel=channel, epoch=epoch, stream=stream)
            sessions[session_key] = session
            session_condition.notify_all()
        with phase_lock:
            case = active_case
            phase = active_phase
        emit(
            peer,
            "established",
            channel=channel,
            epoch=epoch,
            remote=remote,
            local=local,
            case=case,
            phase=phase,
        )
        while not stop_event.is_set():
            try:
                message_type, body = read_message(stream)
            except TimeoutError:
                continue
            if message_type == TYPE_NOTIFICATION:
                with phase_lock:
                    case = active_case
                    phase = active_phase
                emit(
                    peer,
                    "notification",
                    channel=channel,
                    epoch=epoch,
                    case=case,
                    phase=phase,
                    code=body[0] if body else None,
                    subcode=body[1] if len(body) > 1 else None,
                    data=body[2:].hex(),
                )
            elif message_type == TYPE_UPDATE:
                parsed = parse_update(body)
                with phase_lock:
                    case = active_case
                    phase = active_phase
                emit(
                    peer,
                    "reverse_update",
                    channel=channel,
                    epoch=epoch,
                    case=case,
                    phase=phase,
                    length=len(body),
                    body_hex=body.hex(),
                    **parsed,
                )
    except (EOFError, ConnectionResetError, OSError):
        with phase_lock:
            case = active_case
            phase = active_phase
        emit(
            peer,
            "closed",
            channel=channel,
            epoch=session.epoch if session is not None else None,
            case=case,
            phase=phase,
        )
    except Exception as error:  # noqa: BLE001 - retained as fixture evidence.
        epoch = session.epoch if session is not None else None
        emit(peer, "reader_error", channel=channel, epoch=epoch, detail=str(error))
        with session_condition:
            errors.append(f"{peer}: {error}")
    finally:
        with session_condition:
            if session is not None and sessions.get(session_key) is session:
                session.alive = False
            session_condition.notify_all()
        try:
            stream.close()
        except OSError:
            pass


def live_sessions(timeout: float = 120) -> list[Session]:
    deadline = time.monotonic() + timeout
    with session_condition:
        while time.monotonic() < deadline:
            current = [
                sessions.get((name, channel))
                for name, _ in sorted(EXPECTED.values())
                for channel in ("source", "observer")
            ]
            if all(item is not None and item.alive for item in current):
                return [item for item in current if item is not None]
            session_condition.wait(timeout=min(0.5, deadline - time.monotonic()))
    raise RuntimeError("receiver set did not become fully established")


def current_sessions() -> list[Session]:
    with session_condition:
        return [session for session in sessions.values() if session.alive]


def send_maintenance_keepalives() -> None:
    for session in current_sessions():
        try:
            session.send(message(TYPE_KEEPALIVE))
        except OSError:
            # The reader owns closure/epoch evidence. A concurrent reset can
            # close the socket after the live snapshot; maintenance traffic
            # must not stop the accept loop before the replacement connects.
            pass


def send_to_all(payload: bytes, phase: str, case: str, attribute_hex: str | None = None) -> None:
    global active_case, active_phase
    with phase_lock:
        active_case = case
        active_phase = phase
    for session in live_sessions():
        if session.channel != "source":
            continue
        session.send(payload)
        emit(
            session.peer,
            "send",
            channel=session.channel,
            epoch=session.epoch,
            phase=phase,
            case=case,
            attribute_hex=attribute_hex,
            bytes=len(payload),
        )


def wait_trigger(path: Path) -> None:
    next_keepalive = time.monotonic()
    while not path.exists():
        if STOP.exists():
            raise RuntimeError(f"stopped before trigger {path.name}")
        if time.monotonic() >= next_keepalive:
            send_maintenance_keepalives()
            next_keepalive = time.monotonic() + 15
        time.sleep(0.1)


def controller() -> None:
    try:
        live_sessions()
        READY.write_text("ready\n", encoding="utf-8")
        emit("fixture", "ready", peers=sorted(EXPECTED.values()), sessions=8)
        for case in CASES:
            prepare = Path(f"/tmp/m100-{case}-prepare")
            malformed = Path(f"/tmp/m100-{case}-malformed")
            wait_trigger(prepare)
            send_to_all(withdrawal(), "baseline", case)
            time.sleep(0.5)
            send_to_all(baseline_update(case), "baseline", case)
            send_to_all(update(common_attributes(), SURVIVOR), "baseline", case)
            Path(f"{prepare}.sent").write_text("sent\n", encoding="utf-8")
            wait_trigger(malformed)
            payload, attribute_hex = malformed_update(case)
            if attribute_hex != EXPECTED_BAD_HEX[case]:
                raise RuntimeError(f"{case} malformed attribute hex drifted: {attribute_hex}")
            send_to_all(payload, "malformed", case, attribute_hex)
            Path(f"{malformed}.sent").write_text("sent\n", encoding="utf-8")
        while not STOP.exists():
            send_maintenance_keepalives()
            time.sleep(5)
        emit("fixture", "stopped")
    except Exception as error:  # noqa: BLE001 - retained as fixture evidence.
        emit("fixture", "fatal", detail=str(error))
        with session_condition:
            errors.append(str(error))
    finally:
        stop_event.set()


def validate_exact_attribute(case: str, encoded: str) -> None:
    if encoded != EXPECTED_BAD_HEX[case]:
        raise RuntimeError(f"{case} attribute bytes differ from the frozen corpus")
    raw = bytes.fromhex(encoded)
    if not raw or raw[0] != ATTR_OPTIONAL | ATTR_PARTIAL:
        raise RuntimeError(f"{case} does not carry exact flags 0xa0")


def parse_json_lines(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            raise RuntimeError(f"{path}:{line_number}: empty JSONL row")
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError(f"{path}:{line_number}: row is not an object")
        rows.append(value)
    return rows


def assert_expected_outcomes(rows: list[dict[str, Any]]) -> None:
    if len(rows) != len(EXPECTED_OUTCOMES):
        raise RuntimeError(f"expected 20 outcome rows, got {len(rows)}")
    actual: dict[tuple[str, str], str] = {}
    for row in rows:
        key = (str(row.get("receiver")), str(row.get("case")))
        if key in actual:
            raise RuntimeError(f"duplicate outcome row {key[0]}/{key[1]}")
        actual[key] = str(row.get("outcome"))
    if actual != EXPECTED_OUTCOMES:
        raise RuntimeError(f"observed outcome matrix drifted: {actual}")


def candidate_from_snapshot(receiver: str, text: str, case: str) -> bool:
    if not text.strip():
        raise RuntimeError(f"{receiver} returned empty status output")
    if receiver == "bird":
        if "BIRD 2.19.2 ready." not in text:
            raise RuntimeError("BIRD status output lacks the exact runtime banner")
        present = CANDIDATE in text
        if not present and "Network not found" not in text:
            raise RuntimeError("BIRD status output is neither a route nor an explicit absence")
        if case == "med" and present and not any(
            marker in text for marker in ("BGP.med: 100", "bgp_med: 100")
        ):
            raise RuntimeError("BIRD MED observation is not 100")
        return present
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{receiver} returned invalid JSON") from error
    if receiver == "rustbgpd":
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise RuntimeError("rustbgpd route status is not an array of objects")
        matches = [item for item in value if item.get("prefix") == CANDIDATE]
        if case == "med" and matches and matches[0].get("med") != 100:
            raise RuntimeError("rustbgpd MED observation is not 100")
        return bool(matches)
    if receiver == "openbgpd":
        if value == {}:
            return False
        if not isinstance(value, dict) or not isinstance(value.get("rib"), list):
            raise RuntimeError("OpenBGPD route status lacks a rib array")
        matches = [item for item in value["rib"] if item.get("prefix") == CANDIDATE]
        if case == "med" and matches and matches[0].get("metric") != 100:
            raise RuntimeError("OpenBGPD MED observation is not 100")
        return bool(matches)
    if receiver == "frr":
        if value == {}:
            return False
        if not isinstance(value, dict) or not isinstance(value.get("paths"), list):
            raise RuntimeError("FRR route status lacks a paths array")
        if case == "med" and value["paths"] and value["paths"][0].get("metric") != 100:
            raise RuntimeError("FRR MED observation is not 100")
        return bool(value["paths"])
    raise RuntimeError(f"unknown snapshot receiver {receiver}")


def validate_snapshot(receiver: str, path: Path, case: str, expected_present: bool) -> int:
    present = candidate_from_snapshot(receiver, path.read_text(encoding="utf-8"), case)
    if present != expected_present:
        raise RuntimeError(
            f"{receiver}/{case} snapshot presence drifted: expected {expected_present}, got {present}"
        )
    print(f"validated {receiver}/{case} snapshot")
    return 0


def attribute_map(event: dict[str, Any]) -> dict[int, list[dict[str, Any]]]:
    mapped: dict[int, list[dict[str, Any]]] = {}
    for item in event.get("attributes", []):
        mapped.setdefault(int(item["code"]), []).append(item)
    return mapped


def observer_state(
    events: list[dict[str, Any]], receiver: str, case: str, phases: set[str]
) -> tuple[bool, bool]:
    state = {CANDIDATE: False, SURVIVOR: False}
    for event in events:
        if (
            event.get("peer") != receiver
            or event.get("channel") != "observer"
            or event.get("case") != case
            or event.get("phase") not in phases
        ):
            continue
        if event.get("event") == "closed":
            state = {CANDIDATE: False, SURVIVOR: False}
            continue
        if event.get("event") != "reverse_update":
            continue
        for prefix in event.get("withdrawn", []):
            if prefix in state:
                state[prefix] = False
        for prefix in event.get("announced", []):
            if prefix in state:
                state[prefix] = True
    return state[CANDIDATE], state[SURVIVOR]


def verify_results(outcomes_path: Path, events_path: Path) -> int:
    rows = parse_json_lines(outcomes_path)
    events = parse_json_lines(events_path)
    assert_expected_outcomes(rows)
    by_key = {(row["receiver"], row["case"]): row for row in rows}
    indexed_events = list(enumerate(events))
    for key, expected_outcome in EXPECTED_OUTCOMES.items():
        row = by_key[key]
        before = int(row["epoch_before"])
        after = int(row["epoch_after"])
        notification = row["notification"]
        if expected_outcome == "reset":
            expected_hex = EXPECTED_BAD_HEX[key[1]]
            if (
                notification.get("code") != 3
                or notification.get("subcode") != 4
                or notification.get("data") != expected_hex
            ):
                raise RuntimeError(f"{key[0]}/{key[1]} notification evidence drifted")
            notifications = [
                index
                for index, event in indexed_events
                if event.get("peer") == key[0]
                and event.get("channel") == "source"
                and event.get("event") == "notification"
                and event.get("phase") == "malformed"
                and event.get("case") == key[1]
                and int(event.get("epoch", 0)) == before
            ]
            closes = [
                index
                for index, event in indexed_events
                if event.get("peer") == key[0]
                and event.get("channel") == "source"
                and event.get("event") == "closed"
                and event.get("phase") == "malformed"
                and event.get("case") == key[1]
                and int(event.get("epoch", 0)) == before
            ]
            reconnects = [
                index
                for index, event in indexed_events
                if event.get("peer") == key[0]
                and event.get("channel") == "source"
                and event.get("event") == "established"
                and event.get("phase") == "malformed"
                and event.get("case") == key[1]
                and int(event.get("epoch", 0)) == before + 1
            ]
            if not (
                len(notifications) == len(closes) == len(reconnects) == 1
                and notifications[0] < closes[0] < reconnects[0]
            ):
                raise RuntimeError(
                    f"{key[0]}/{key[1]} lacks one ordered notification/close/reconnect chain"
                )
            if row["candidate_present"] or row["survivor_present"]:
                raise RuntimeError(f"{key[0]}/{key[1]} reset row retained route state")
        else:
            if notification != {} or after != before:
                raise RuntimeError(f"{key[0]}/{key[1]} changed epoch or recorded a notification")
            if not row["survivor_present"]:
                raise RuntimeError(f"{key[0]}/{key[1]} lost the survivor")
            expected_candidate = expected_outcome == "accepted"
            if bool(row["candidate_present"]) != expected_candidate:
                raise RuntimeError(f"{key[0]}/{key[1]} candidate state drifted")
            disruptive_events = [
                event
                for event in events
                if event.get("peer") == key[0]
                and event.get("channel") == "source"
                and event.get("phase") == "malformed"
                and event.get("case") == key[1]
                and event.get("event") in {"notification", "closed", "established"}
            ]
            if disruptive_events:
                raise RuntimeError(f"{key[0]}/{key[1]} changed its source session")

        sends = [
            event
            for event in events
            if event.get("peer") == key[0]
            and event.get("channel") == "source"
            and event.get("event") == "send"
            and event.get("phase") == "malformed"
            and event.get("case") == key[1]
        ]
        if len(sends) != 1 or sends[0].get("attribute_hex") != EXPECTED_BAD_HEX[key[1]]:
            raise RuntimeError(f"{key[0]}/{key[1]} exact send evidence drifted")

        baseline = [
            event
            for event in events
            if event.get("peer") == key[0]
            and event.get("channel") == "observer"
            and event.get("event") == "reverse_update"
            and event.get("phase") == "baseline"
            and event.get("case") == key[1]
            and CANDIDATE in event.get("announced", [])
        ]
        if not baseline:
            raise RuntimeError(f"{key[0]}/{key[1]} lacks the baseline observer announcement")
        baseline_candidate, baseline_survivor = observer_state(
            events, key[0], key[1], {"baseline"}
        )
        if not (baseline_candidate and baseline_survivor):
            raise RuntimeError(f"{key[0]}/{key[1]} observer baseline is incomplete")
        final_candidate, final_survivor = observer_state(
            events, key[0], key[1], {"baseline", "malformed"}
        )
        expected_final = {
            "accepted": (True, True),
            "treat_as_withdraw": (False, True),
            "same_session_withdrawal": (False, True),
            "reset": (False, False),
        }[expected_outcome]
        if (final_candidate, final_survivor) != expected_final:
            raise RuntimeError(
                f"{key[0]}/{key[1]} observer final state drifted: "
                f"expected {expected_final}, got {(final_candidate, final_survivor)}"
            )
        baseline_attributes = attribute_map(baseline[-1])
        if key[1] == "med":
            med = baseline_attributes.get(4, [])
            if len(med) != 1 or med[0].get("value") != "00000064":
                raise RuntimeError(f"{key[0]}/med observer value drifted")
        if key[1] in {"originator_id", "cluster_list"}:
            forbidden_code = 9 if key[1] == "originator_id" else 10
            if forbidden_code in baseline_attributes:
                raise RuntimeError(f"{key[0]}/{key[1]} unexpectedly crossed the observer boundary")

    bird_med = [
        event
        for event in events
        if event.get("peer") == "bird"
        and event.get("channel") == "observer"
        and event.get("event") == "reverse_update"
        and event.get("phase") == "malformed"
        and event.get("case") == "med"
        and CANDIDATE in event.get("announced", [])
    ]
    if not bird_med:
        raise RuntimeError("BIRD MED case lacks an observer reannouncement")
    med = attribute_map(bird_med[-1]).get(4, [])
    if len(med) != 1 or med[0] != {"flags": 160, "code": 4, "value": "00000064"}:
        raise RuntimeError("BIRD MED observer bytes drifted")
    for event in events:
        if (
            event.get("channel") == "observer"
            and event.get("phase") == "malformed"
            and event.get("case") in {"originator_id", "cluster_list"}
        ):
            forbidden_code = 9 if event["case"] == "originator_id" else 10
            if forbidden_code in attribute_map(event):
                raise RuntimeError(
                    f"{event.get('peer')}/{event['case']} unexpectedly crossed the observer boundary"
                )
    if any(event.get("event") in {"fatal", "reader_error"} for event in events):
        raise RuntimeError("raw fixture recorded an internal error")
    print("M100 exact 20-cell contract verified")
    return 0


def self_test() -> int:
    actual = {case: malformed_update(case)[1] for case in CASES}
    if actual != EXPECTED_BAD_HEX:
        raise RuntimeError(f"M100 exact-hex self-test failed: {actual}")
    for case, encoded in actual.items():
        validate_exact_attribute(case, encoded)
        raw = bytearray.fromhex(encoded)
        for replacement in (ATTR_OPTIONAL, ATTR_OPTIONAL | ATTR_TRANSITIVE | ATTR_PARTIAL):
            altered = bytearray(raw)
            altered[0] = replacement
            try:
                validate_exact_attribute(case, altered.hex())
            except RuntimeError:
                pass
            else:
                raise RuntimeError(f"{case} negative flag mutation was accepted")
    rows = [
        {"receiver": receiver, "case": case, "outcome": outcome}
        for (receiver, case), outcome in EXPECTED_OUTCOMES.items()
    ]
    assert_expected_outcomes(rows)
    rows[0]["outcome"] = "reset" if rows[0]["outcome"] != "reset" else "accepted"
    try:
        assert_expected_outcomes(rows)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("inverted outcome negative test was accepted")
    malformed_snapshots = {
        "rustbgpd": "{}",
        "bird": "Network not found",
        "openbgpd": '{"unexpected":true}',
        "frr": '{"unexpected":true}',
    }
    for receiver, text in malformed_snapshots.items():
        try:
            candidate_from_snapshot(receiver, text, "originator_id")
        except RuntimeError:
            pass
        else:
            raise RuntimeError(f"{receiver} malformed snapshot negative test was accepted")
    print(json.dumps(actual, sort_keys=True, separators=(",", ":")))
    return 0


def main() -> int:
    if os.sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(os.sys.argv) == 6 and os.sys.argv[1] == "--validate-snapshot":
        return validate_snapshot(
            os.sys.argv[2],
            Path(os.sys.argv[3]),
            os.sys.argv[4],
            os.sys.argv[5] == "true",
        )
    if len(os.sys.argv) == 4 and os.sys.argv[1] == "--verify-results":
        return verify_results(Path(os.sys.argv[2]), Path(os.sys.argv[3]))
    if os.sys.argv[1:]:
        raise RuntimeError(f"unsupported arguments: {os.sys.argv[1:]}")
    paths = [EVENTS, READY, STOP]
    for case in CASES:
        paths.extend(
            (
                Path(f"/tmp/m100-{case}-prepare"),
                Path(f"/tmp/m100-{case}-prepare.sent"),
                Path(f"/tmp/m100-{case}-malformed"),
                Path(f"/tmp/m100-{case}-malformed.sent"),
            )
        )
    for path in paths:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", 179))
    listener.listen(16)
    listener.settimeout(0.5)
    emit("fixture", "listening", address=RAW_ADDR, receivers=len(EXPECTED))
    controller_thread = threading.Thread(target=controller, name="m100-controller", daemon=True)
    controller_thread.start()
    try:
        while not stop_event.is_set():
            try:
                stream, address = listener.accept()
            except TimeoutError:
                continue
            remote = address[0]
            if remote not in EXPECTED:
                stream.close()
                emit("fixture", "unexpected_connection", remote=remote)
                continue
            threading.Thread(
                target=handle_connection,
                args=(stream, remote),
                name=f"m100-{EXPECTED[remote][0]}",
                daemon=True,
            ).start()
        controller_thread.join(timeout=5)
        with session_condition:
            captured_errors = list(errors)
        if captured_errors:
            raise RuntimeError("; ".join(captured_errors))
        return 0
    finally:
        stop_event.set()
        listener.close()
        with session_condition:
            current = list(sessions.values())
        for session in current:
            try:
                session.stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            session.stream.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # noqa: BLE001 - stderr is retained as evidence.
        emit("fixture", "fatal", detail=str(error))
        print(f"M100 raw peer failed: {error}", file=os.sys.stderr)
        raise
