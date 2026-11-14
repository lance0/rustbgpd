"""Connection-local FSM evidence for the M122 collision oracle.

Packet ordering and TCP ACKs cannot show when an actor consumed KEEPALIVE.
The GoBGP lab trace follows net.Conn, not the owning peer's other connection.
"""
import ipaddress
import json

from m105_capture_oracle import need


def endpoint(value):
    need(isinstance(value, str), "FSM trace lacks TCP endpoint")
    address, port = value.rsplit(":", 1)
    address = str(ipaddress.IPv4Address(address))
    port = int(port)
    need(0 < port < 65536, "invalid FSM trace TCP port")
    return address, port


def parse_logs(logs):
    """Normalize JSON daemon logs, retaining file/line provenance and local order."""
    events = []
    for name, text in logs.items():
        lines = text.splitlines()
        version, banner_end = None, 0
        for ordinal, line in enumerate(lines, 1):
            if ordinal <= banner_end:
                continue
            # Like M69, admit only print_startup_banner's complete topology
            # block, tied to the preceding structured startup version.
            if name == "rr.log" and version is not None:
                banner = [
                    "", f"  rustbgpd {version} | AS 65001 | router-id 10.0.122.1",
                    "  |- 2 peers (2 iBGP)",
                    "  |- grpc: tcp://0.0.0.0:50051 (token auth)",
                    "  |- grpc: unix:///var/lib/rustbgpd/grpc.sock",
                    "  |- metrics: http://0.0.0.0:9179/metrics", "",
                ]
                if lines[ordinal - 1:ordinal - 1 + len(banner)] == banner:
                    banner_end = ordinal + len(banner) - 1
                    version = None
                    continue
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{name}:{ordinal}: incomplete/non-JSON daemon log") from error
            need(isinstance(row, dict), f"{name}:{ordinal}: daemon log record is not an object")
            fields = row.get("fields", {})
            need(isinstance(fields, dict), f"{name}:{ordinal}: daemon log fields are not an object")
            message = fields.get("message")
            if row.get("target") == "rustbgpd" and message == "starting rustbgpd":
                version = fields.get("version")
            event = None
            if row.get("msg") == "M122 FSM trace":
                fields = row
                event = fields["event"]
                owner = [name, "gobgp", fields["process_id"], fields["connection_id"]]
                state = fields["state"]
                sequence = fields["sequence"]
            else:
                if message == "FSM event" and fields.get("event") == "KeepaliveReceived":
                    event, state = "keepalive_received", fields["state"]
                elif message == "session state changed":
                    state = fields["to"]
                    if state == "open_sent":
                        event = "connection_open"
                    elif state == "established":
                        event = "established"
                    elif state == "open_confirm":
                        event = "open_confirm"
                elif message == "BGP NOTIFICATION" and fields.get("direction") == "sent" and (fields.get("code"), fields.get("subcode")) == (6, 7):
                    event, state = "collision_close", fields.get("collision_state")
                if event is None:
                    continue
                # Idle/start events without a socket cannot identify a connection.
                if event != "collision_close" and not fields.get("tcp_local"):
                    continue
                owner = [name, "rustbgpd", fields["session_id"]]
                sequence = None
            local, remote = endpoint(fields.get("tcp_local")), endpoint(fields.get("tcp_remote"))
            events.append({"owner": owner, "connection": [*local, *remote], "event": event,
                           "state": state, "sequence": sequence, "log": name, "line": ordinal})
    return events


def collision_witness(events, connection):
    """Require positive evidence for this closing TCP tuple; ambiguity fails closed."""
    rows = [event for event in events if tuple(event["connection"]) == connection]
    need(rows, "closing FSM trace missing for TCP tuple")
    owners = {tuple(row["owner"]) for row in rows}
    need(len(owners) == 1, "closing TCP tuple reused by multiple FSM connections")
    implementation = rows[0]["owner"][1]
    starts = [row for row in rows if row["event"] == "connection_open"]
    closes = [row for row in rows if row["event"] == "collision_close"]
    need(len(starts) == 1 and rows[0] == starts[0], "closing FSM trace lacks unique connection start")
    need(len(closes) == 1, "closing FSM trace lacks unique collision close")
    close = closes[0]
    before = rows[:rows.index(close)]
    consumed = [row for row in before if row["event"] == "keepalive_received"]
    established = [row for row in before if row["event"] == "established"]
    if implementation == "gobgp":
        need(rows[0]["owner"][2] > 0 and rows[0]["owner"][3] > 0, "unknown GoBGP connection identity")
        need([row["sequence"] for row in rows] == list(range(1, len(rows) + 1)), "GoBGP FSM trace has missing/duplicate sequence")
        need(rows[0]["state"] == "pre_established", "GoBGP connection start state differs")
        need(all(row["event"] in {"connection_open", "keepalive_received", "collision_close", "connection_closed"} for row in rows), "unknown GoBGP trace event")
        need(len(consumed) <= 1 and all(row["state"] == "established" for row in consumed), "invalid GoBGP KEEPALIVE transition")
        expected_events = ["connection_open"] + (["keepalive_received"] if consumed else [])
        expected_events += ["collision_close", "connection_closed"]
        need([row["event"] for row in rows] == expected_events,
             "GoBGP collision trace lacks ordered lifecycle/terminal close")
        expected = "established" if consumed else "pre_established"
        need(close["state"] == expected and rows[-1]["state"] == expected, "contradictory GoBGP connection state")
    else:
        need(implementation == "rustbgpd", "unknown closing FSM implementation")
        need(close["state"] in {"open_sent", "open_confirm", "established"}, "missing pre-close Rust collision state")
        need(rows[-1] == close, "Rust FSM events follow collision close")
        if consumed or established:
            need(close["state"] == "established", "contradictory Rust KEEPALIVE/close state")
        else:
            expected_events = ["connection_open"]
            if close["state"] == "open_confirm":
                expected_events.append("open_confirm")
            expected_events.append("collision_close")
            need([row["event"] for row in rows] == expected_events,
                 "Rust collision trace lacks ordered pre-Established lifecycle")
    need(close["state"] != "established", "collision Cease after local KEEPALIVE receive (Established)")
    need(not consumed and not established, "collision Cease after local Established witness")
    return {"state": "pre_established", "connection": list(connection), "owner": close["owner"],
            "log": close["log"], "close_line": close["line"]}
