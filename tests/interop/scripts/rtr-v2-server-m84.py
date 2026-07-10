#!/usr/bin/env python3
"""Phased RTR v2 server for the M84 multi-cache epoch conformance job.

Serves VRP (ROA) and ASPA records over RTR protocol version 2 and walks
through scripted phases driven by an integer in /tmp/rtr-phase (written
by the test runner via docker exec). On every phase change the server
updates its serial and pushes a Serial Notify to connected clients, so
the client re-queries immediately instead of waiting for its refresh
timer.

Phases (serial in parentheses):
  1 (1): base VRP 192.0.2.0/24 -> AS65999, ASPA 65004 -> [65003, 65099]
  2 (2): + VRP 198.18.9.0/24 -> AS65003            (incremental announce)
  3 (3): ASPA 65004 -> [65099]                     (provider-set REPLACE)
  4 (4): ASPA 65004 withdrawn (flags=0, empty providers on the wire)
  5 (1): SERIAL REGRESSION — same session, serial rolls back to 1; any
         Serial Query is answered with an EoD carrying the regressed
         serial (no payload) so the client must detect the regression
         and resynchronize with a Reset Query. The full table at serial
         1 is the base VRP only (the phase-2 VRP is gone — a client
         that fails to purge it holds a stale VRP).

Wire format follows RFC 8210 (v1) and draft-ietf-sidrops-8210bis (v2).
"""

import json
import selectors
import socket
import struct
import time

LISTEN_PORT = 3323
SESSION_ID = 84
REFRESH = 10
RETRY = 5
EXPIRE = 600
PHASE_FILE = "/tmp/rtr-phase"
STATUS_FILE = "/tmp/rtr-server-status.json"

RTR_V2 = 2

PDU_SERIAL_NOTIFY = 0
PDU_SERIAL_QUERY = 1
PDU_RESET_QUERY = 2
PDU_CACHE_RESPONSE = 3
PDU_IPV4_PREFIX = 4
PDU_END_OF_DATA = 7
PDU_CACHE_RESET = 8
PDU_ERROR_REPORT = 10
PDU_ASPA = 11

# ── Data per phase ───────────────────────────────────────────────

VRP_BASE = (24, 24, "192.0.2.0", 65999)   # makes FRR's 192.0.2.0/24 Invalid
VRP_P2 = (24, 24, "198.18.9.0", 65003)    # added in phase 2, gone after regression
ASPA_P1 = (65004, [65003, 65099])
ASPA_P3 = (65004, [65099])                # replaces (not merges with) ASPA_P1

# phase -> (serial, full_vrps, full_aspas)
PHASES = {
    1: (1, [VRP_BASE], [ASPA_P1]),
    2: (2, [VRP_BASE, VRP_P2], [ASPA_P1]),
    3: (3, [VRP_BASE, VRP_P2], [ASPA_P3]),
    4: (4, [VRP_BASE, VRP_P2], []),
    5: (1, [VRP_BASE], []),
}

# (from_serial, to_serial) -> (vrp_announce, vrp_withdraw, aspa_announce, aspa_withdraw)
DIFFS = {
    (1, 2): ([VRP_P2], [], [], []),
    (2, 3): ([], [], [ASPA_P3], []),
    (3, 4): ([], [], [], [(65004, [])]),
}

# ── PDU encoders ─────────────────────────────────────────────────


def encode_cache_response(session_id):
    return struct.pack("!BBHI", RTR_V2, PDU_CACHE_RESPONSE, session_id, 8)


def encode_ipv4_prefix(flags, vrp):
    prefix_len, max_len, prefix, asn = vrp
    return struct.pack(
        "!BBHIBBBx", RTR_V2, PDU_IPV4_PREFIX, 0, 20, flags, prefix_len, max_len
    ) + socket.inet_aton(prefix) + struct.pack("!I", asn)


def encode_aspa(flags, customer_asn, provider_asns):
    total_len = 12 + 4 * len(provider_asns)
    pdu = struct.pack("!BBBxI", RTR_V2, PDU_ASPA, flags, total_len)
    pdu += struct.pack("!I", customer_asn)
    for asn in provider_asns:
        pdu += struct.pack("!I", asn)
    return pdu


def encode_end_of_data(session_id, serial):
    return struct.pack(
        "!BBHIIIII", RTR_V2, PDU_END_OF_DATA, session_id, 24,
        serial, REFRESH, RETRY, EXPIRE,
    )


def encode_serial_notify(session_id, serial):
    return struct.pack("!BBHII", RTR_V2, PDU_SERIAL_NOTIFY, session_id, 12, serial)


def encode_cache_reset():
    return struct.pack("!BBHI", RTR_V2, PDU_CACHE_RESET, 0, 8)


def encode_error_report(version, code, encap_pdu, text):
    text_bytes = text.encode("utf-8")
    total_len = 16 + len(encap_pdu) + len(text_bytes)
    hdr = struct.pack("!BBHI", version, PDU_ERROR_REPORT, code, total_len)
    return hdr + struct.pack("!I", len(encap_pdu)) + encap_pdu \
        + struct.pack("!I", len(text_bytes)) + text_bytes


# ── Server state ─────────────────────────────────────────────────


class Server:
    def __init__(self):
        self.phase = 1
        self.conns = {}  # socket -> recv buffer

    @property
    def serial(self):
        return PHASES[self.phase][0]

    def read_phase_file(self):
        try:
            with open(PHASE_FILE, encoding="ascii") as f:
                p = int(f.read().strip())
            return p if p in PHASES else self.phase
        except (OSError, ValueError):
            return self.phase

    def write_status(self):
        _, vrps, aspas = PHASES[self.phase]
        status = {
            "listening": True,
            "version": RTR_V2,
            "phase": self.phase,
            "serial": self.serial,
            "session_id": SESSION_ID,
            "roa_count": len(vrps),
            "aspa_count": len(aspas),
            "timestamp": time.time(),
        }
        with open(STATUS_FILE, "w", encoding="ascii") as f:
            json.dump(status, f)

    def send_full_table(self, conn):
        serial, vrps, aspas = PHASES[self.phase]
        out = encode_cache_response(SESSION_ID)
        for vrp in vrps:
            out += encode_ipv4_prefix(1, vrp)
        for customer, providers in aspas:
            out += encode_aspa(1, customer, providers)
        out += encode_end_of_data(SESSION_ID, serial)
        conn.sendall(out)
        print(f"RTR: served full table phase={self.phase} serial={serial}", flush=True)

    def send_diffs(self, conn, client_serial):
        out = encode_cache_response(SESSION_ID)
        for s in range(client_serial, self.serial):
            va, vw, aa, aw = DIFFS[(s, s + 1)]
            for vrp in va:
                out += encode_ipv4_prefix(1, vrp)
            for vrp in vw:
                out += encode_ipv4_prefix(0, vrp)
            for customer, providers in aa:
                out += encode_aspa(1, customer, providers)
            for customer, providers in aw:
                out += encode_aspa(0, customer, providers)
        out += encode_end_of_data(SESSION_ID, self.serial)
        conn.sendall(out)
        print(f"RTR: served diffs {client_serial}->{self.serial}", flush=True)

    def handle_pdu(self, conn, version, pdu_type, hdr, body):
        if pdu_type == PDU_RESET_QUERY:
            if version < RTR_V2:
                print("RTR: v1 ResetQuery — ErrorReport code=4", flush=True)
                conn.sendall(encode_error_report(
                    version, 4, hdr + body, "This server requires RTR v2"))
                return
            self.send_full_table(conn)
        elif pdu_type == PDU_SERIAL_QUERY:
            client_serial = struct.unpack("!I", body[:4])[0] if body else 0
            if self.phase == 5:
                # Regression phase: whatever the client holds, answer with
                # the regressed serial so it must detect the rollback.
                print(f"RTR: phase 5 — answering serial query (client "
                      f"serial {client_serial}) with regressed serial "
                      f"{self.serial}", flush=True)
                conn.sendall(encode_cache_response(SESSION_ID)
                             + encode_end_of_data(SESSION_ID, self.serial))
            elif client_serial == self.serial:
                conn.sendall(encode_cache_response(SESSION_ID)
                             + encode_end_of_data(SESSION_ID, self.serial))
            elif all((s, s + 1) in DIFFS
                     for s in range(client_serial, self.serial)) \
                    and client_serial < self.serial:
                self.send_diffs(conn, client_serial)
            else:
                print(f"RTR: unknown serial {client_serial}, CacheReset",
                      flush=True)
                conn.sendall(encode_cache_reset())
        else:
            print(f"RTR: ignoring PDU type {pdu_type}", flush=True)

    def on_readable(self, conn):
        try:
            data = conn.recv(4096)
        except OSError:
            data = b""
        if not data:
            return False
        buf = self.conns[conn] + data
        while len(buf) >= 8:
            version, pdu_type = buf[0], buf[1]
            length = struct.unpack("!I", buf[4:8])[0]
            if length < 8 or len(buf) < length:
                break
            hdr, body = buf[:8], buf[8:length]
            buf = buf[length:]
            print(f"RTR: recv version={version} type={pdu_type} len={length}",
                  flush=True)
            self.handle_pdu(conn, version, pdu_type, hdr, body)
        self.conns[conn] = buf
        return True

    def on_phase_tick(self):
        new_phase = self.read_phase_file()
        if new_phase == self.phase:
            return
        print(f"RTR: phase {self.phase} -> {new_phase} "
              f"(serial {PHASES[new_phase][0]})", flush=True)
        self.phase = new_phase
        self.write_status()
        notify = encode_serial_notify(SESSION_ID, self.serial)
        for conn in list(self.conns):
            try:
                conn.sendall(notify)
            except OSError:
                pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT))
    srv.listen(4)
    srv.setblocking(False)

    server = Server()
    sel = selectors.DefaultSelector()
    sel.register(srv, selectors.EVENT_READ)

    print(f"RTR v2 phased server listening on :{LISTEN_PORT}", flush=True)
    server.write_status()

    while True:
        for key, _ in sel.select(timeout=1.0):
            sock = key.fileobj
            if sock is srv:
                conn, addr = srv.accept()
                print(f"RTR: connection from {addr}", flush=True)
                conn.setblocking(True)  # sendall on a ready socket
                server.conns[conn] = b""
                sel.register(conn, selectors.EVENT_READ)
            elif not server.on_readable(sock):
                print("RTR: client disconnected", flush=True)
                sel.unregister(sock)
                del server.conns[sock]
                sock.close()
        server.on_phase_tick()


if __name__ == "__main__":
    main()
