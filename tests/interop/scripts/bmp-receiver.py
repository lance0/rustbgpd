#!/usr/bin/env python3
"""Minimal BMP receiver for interop testing.

Listens on TCP port 11019, accepts one connection from rustbgpd,
parses BMP message headers, and logs message types to a JSON file
for the test script to verify.

BMP message format (RFC 7854):
  Version (1 byte) = 3
  Length  (4 bytes, big-endian, includes header)
  Type    (1 byte): 0=RouteMonitoring, 1=StatsReport, 2=PeerDown,
                     3=PeerUp, 4=Initiation, 5=Termination
"""

import json
import socket
import struct
import sys
import time

BMP_HDR_LEN = 6  # version(1) + length(4) + type(1)
OUTPUT_FILE = "/tmp/bmp-messages.json"
LISTEN_PORT = 11019

TYPE_NAMES = {
    0: "RouteMonitoring",
    1: "StatsReport",
    2: "PeerDown",
    3: "PeerUp",
    4: "Initiation",
    5: "Termination",
}


def recv_exact(sock, n):
    """Receive exactly n bytes."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def main():
    messages = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT))
    srv.listen(1)
    srv.settimeout(120)  # 2 minute timeout for test

    print(f"BMP receiver listening on :{LISTEN_PORT}", flush=True)

    try:
        conn, addr = srv.accept()
        print(f"Connection from {addr}", flush=True)
        conn.settimeout(60)

        while True:
            hdr = recv_exact(conn, BMP_HDR_LEN)
            if hdr is None:
                print("Connection closed", flush=True)
                break

            version, length, msg_type = struct.unpack("!BIB", hdr)
            if version != 3:
                print(f"Bad BMP version: {version}", flush=True)
                break

            # Read the rest of the message body
            body_len = length - BMP_HDR_LEN
            if body_len > 0:
                body = recv_exact(conn, body_len)
                if body is None:
                    print("Connection closed mid-message", flush=True)
                    break
            else:
                body = b""

            type_name = TYPE_NAMES.get(msg_type, f"Unknown({msg_type})")
            entry = {
                "type": msg_type,
                "type_name": type_name,
                "length": length,
                "timestamp": time.time(),
            }
            messages.append(entry)
            print(f"BMP: {type_name} ({length} bytes)", flush=True)

            # Write after each message so the test script can check progress
            with open(OUTPUT_FILE, "w") as f:
                json.dump({"messages": messages}, f)

    except socket.timeout:
        print("Timeout waiting for BMP data", flush=True)
    except Exception as e:
        print(f"Error: {e}", flush=True)
    finally:
        # Final write
        with open(OUTPUT_FILE, "w") as f:
            json.dump({"messages": messages}, f)
        print(f"Wrote {len(messages)} messages to {OUTPUT_FILE}", flush=True)


if __name__ == "__main__":
    main()
