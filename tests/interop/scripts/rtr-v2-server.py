#!/usr/bin/env python3
"""Minimal RTR v2 server for ASPA interop testing.

Listens on TCP port 3323, serves static VRP (ROA) and ASPA records
over RTR protocol version 2.  Handles ResetQuery and SerialQuery.

Wire format follows RFC 8210 (v1) and draft-ietf-sidrops-8210bis (v2).
ASPA PDU type 11 is v2-only.
"""

import json
import socket
import struct
import sys
import time

LISTEN_PORT = 3323
SESSION_ID = 1
SERIAL = 1
REFRESH = 30
RETRY = 5
EXPIRE = 120
OUTPUT_FILE = "/tmp/rtr-server-status.json"

# RTR protocol versions
RTR_V1 = 1
RTR_V2 = 2

# PDU types
PDU_SERIAL_NOTIFY = 0
PDU_SERIAL_QUERY = 1
PDU_RESET_QUERY = 2
PDU_CACHE_RESPONSE = 3
PDU_IPV4_PREFIX = 4
PDU_END_OF_DATA = 7
PDU_CACHE_RESET = 8
PDU_ERROR_REPORT = 10
PDU_ASPA = 11

# ── Static data ──────────────────────────────────────────────────

# ROAs: all test prefixes are RPKI Valid so RPKI step 0.5 ties.
ROAS = [
    # (flags=announce, prefix_len, max_len, ip_bytes, asn)
    (1, 24, 24, socket.inet_aton("192.168.1.0"), 65002),
    (1, 24, 24, socket.inet_aton("192.168.2.0"), 65002),
    (1, 24, 24, socket.inet_aton("192.168.3.0"), 65002),
    (1, 24, 24, socket.inet_aton("192.168.4.0"), 65002),
    (1, 24, 24, socket.inet_aton("172.16.0.0"), 65006),
]

# ASPA records: (flags=announce, customer_asn, [provider_asns])
ASPAS = [
    (1, 65003, [65002, 65006]),  # 65003 authorizes 65002 and 65006
    (1, 65004, [65099]),         # 65004 only authorizes 65099 (not 65002)
]
# Note: 65005 has NO ASPA record → Unknown


def recv_exact(sock, n):
    """Receive exactly n bytes."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def encode_cache_response(version, session_id):
    """CacheResponse: version(1) type(1) session_id(2) length(4)."""
    return struct.pack("!BBHI", version, PDU_CACHE_RESPONSE, session_id, 8)


def encode_ipv4_prefix(version, flags, prefix_len, max_len, ip_bytes, asn):
    """IPv4Prefix PDU: 20 bytes total."""
    return struct.pack("!BBHIBBBx", version, PDU_IPV4_PREFIX, 0, 20,
                       flags, prefix_len, max_len) + ip_bytes + struct.pack("!I", asn)


def encode_aspa(version, flags, customer_asn, provider_asns):
    """ASPA PDU (type 11, v2 only): 12 + 4*len(providers) bytes."""
    total_len = 12 + 4 * len(provider_asns)
    # byte 0: version, byte 1: type(11), byte 2: flags, byte 3: zero, bytes 4-7: length
    hdr = struct.pack("!BBBxI", version, PDU_ASPA, flags, total_len)
    body = struct.pack("!I", customer_asn)
    for asn in provider_asns:
        body += struct.pack("!I", asn)
    return hdr + body


def encode_end_of_data(version, session_id, serial, refresh, retry, expire):
    """EndOfData PDU: 24 bytes total."""
    return struct.pack("!BBHIIIII", version, PDU_END_OF_DATA, session_id, 24,
                       serial, refresh, retry, expire)


def encode_error_report(version, code, encap_pdu, text):
    """ErrorReport PDU."""
    text_bytes = text.encode("utf-8")
    total_len = 16 + len(encap_pdu) + len(text_bytes)
    hdr = struct.pack("!BBHI", version, PDU_ERROR_REPORT, code, total_len)
    body = struct.pack("!I", len(encap_pdu)) + encap_pdu
    body += struct.pack("!I", len(text_bytes)) + text_bytes
    return hdr + body


def send_full_table(conn, version):
    """Send CacheResponse + ROAs + ASPAs + EndOfData."""
    conn.sendall(encode_cache_response(version, SESSION_ID))
    for roa in ROAS:
        conn.sendall(encode_ipv4_prefix(version, *roa))
    if version >= RTR_V2:
        for flags, customer, providers in ASPAS:
            conn.sendall(encode_aspa(version, flags, customer, providers))
    conn.sendall(encode_end_of_data(version, SESSION_ID, SERIAL,
                                     REFRESH, RETRY, EXPIRE))


def handle_client(conn, addr):
    """Handle one RTR client connection."""
    print(f"RTR: connection from {addr}", flush=True)
    conn.settimeout(300)  # 5 min timeout
    queries_served = 0

    try:
        while True:
            # Read PDU header (8 bytes minimum)
            hdr = recv_exact(conn, 8)
            if hdr is None:
                print("RTR: client disconnected", flush=True)
                break

            version, pdu_type, session_field = struct.unpack("!BBH", hdr[:4])
            length = struct.unpack("!I", hdr[4:8])[0]

            # Read remaining body if any
            body_len = length - 8
            if body_len > 0:
                body = recv_exact(conn, body_len)
                if body is None:
                    print("RTR: client disconnected mid-PDU", flush=True)
                    break
            else:
                body = b""

            print(f"RTR: recv version={version} type={pdu_type} len={length}",
                  flush=True)

            if pdu_type == PDU_RESET_QUERY:
                if version < RTR_V2:
                    # Client tried v1 — reject with "Unsupported Protocol Version"
                    print("RTR: v1 ResetQuery — sending ErrorReport code=4", flush=True)
                    err = encode_error_report(version, 4, hdr + body,
                                              "This server requires RTR v2")
                    conn.sendall(err)
                    continue
                print("RTR: serving full table (v2)", flush=True)
                send_full_table(conn, RTR_V2)
                queries_served += 1

            elif pdu_type == PDU_SERIAL_QUERY:
                client_serial = struct.unpack("!I", body[:4])[0] if body else 0
                if client_serial == SERIAL:
                    # No changes — send CacheResponse + EndOfData
                    print(f"RTR: serial {client_serial} is current, no changes",
                          flush=True)
                    conn.sendall(encode_cache_response(version, SESSION_ID))
                    conn.sendall(encode_end_of_data(version, SESSION_ID, SERIAL,
                                                     REFRESH, RETRY, EXPIRE))
                else:
                    # Unknown serial — send CacheReset so client does ResetQuery
                    print(f"RTR: unknown serial {client_serial}, sending CacheReset",
                          flush=True)
                    conn.sendall(struct.pack("!BBHI", version, PDU_CACHE_RESET, 0, 8))
                queries_served += 1
            else:
                print(f"RTR: ignoring unexpected PDU type {pdu_type}", flush=True)

            # Write status after each interaction
            write_status(queries_served)

    except socket.timeout:
        print("RTR: client timeout", flush=True)
    except Exception as e:
        print(f"RTR: error: {e}", flush=True)


def write_status(queries_served):
    """Write server status to JSON for test script verification."""
    status = {
        "listening": True,
        "version": RTR_V2,
        "roa_count": len(ROAS),
        "aspa_count": len(ASPAS),
        "queries_served": queries_served,
        "timestamp": time.time(),
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(status, f)


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT))
    srv.listen(2)
    srv.settimeout(300)

    print(f"RTR v2 server listening on :{LISTEN_PORT}", flush=True)
    write_status(0)

    try:
        while True:
            conn, addr = srv.accept()
            handle_client(conn, addr)
    except socket.timeout:
        print("RTR: no connections for 5 minutes, exiting", flush=True)
    except KeyboardInterrupt:
        print("RTR: shutting down", flush=True)
    finally:
        write_status(0)
        print("RTR: done", flush=True)


if __name__ == "__main__":
    main()
