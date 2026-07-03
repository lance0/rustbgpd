#!/usr/bin/env python3
"""Dual-port raw BMP byte sink for the M81 interop lab.

Listens on two TCP ports (11019 = a version-3 collector slot, 11020 = a
version-4 collector slot), accepts sequential reconnects from rustbgpd,
and appends one JSON line per BMP message to /tmp/bmp-raw-<port>.jsonl:

  {"port": 11020, "conn": 0, "seq": 3, "version": 4, "type": 0,
   "len": 128, "hex": "04...."}

This sink deliberately does NOT interpret message bodies — it splits the
stream on the 6-byte RFC 7854 common header (version, length, type) and
records raw bytes. Byte-level assertions (TLV offsets, v3-vs-v4
byte-equality) live in the test script; semantic BMP decoding is the job
of the real collectors (pmacct, gobmp) and tshark.
"""

import json
import socket
import struct
import sys
import threading

PORTS = [11019, 11020]
HDR_LEN = 6  # version(1) + length(4) + type(1)

# Optional conn-id base (argv[1]): the reconnect-dump test restarts the
# sink process, and a distinct base keeps post-restart connection ids
# unambiguous in the appended JSONL.
CONN_BASE = int(sys.argv[1]) if len(sys.argv) > 1 else 0


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def serve(port):
    out_path = f"/tmp/bmp-raw-{port}.jsonl"
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    print(f"raw BMP sink listening on :{port} -> {out_path}", flush=True)

    conn_id = CONN_BASE
    while True:
        conn, addr = srv.accept()
        print(f":{port} connection {conn_id} from {addr}", flush=True)
        seq = 0
        with open(out_path, "a") as out:
            while True:
                hdr = recv_exact(conn, HDR_LEN)
                if hdr is None:
                    break
                version, length, msg_type = struct.unpack("!BIB", hdr)
                body = b""
                if length > HDR_LEN:
                    body = recv_exact(conn, length - HDR_LEN)
                    if body is None:
                        print(f":{port} closed mid-message", flush=True)
                        break
                out.write(
                    json.dumps(
                        {
                            "port": port,
                            "conn": conn_id,
                            "seq": seq,
                            "version": version,
                            "type": msg_type,
                            "len": length,
                            "hex": (hdr + body).hex(),
                        }
                    )
                    + "\n"
                )
                out.flush()
                seq += 1
        print(f":{port} connection {conn_id} closed ({seq} messages)", flush=True)
        conn.close()
        conn_id += 1


def main():
    threads = [
        threading.Thread(target=serve, args=(p,), daemon=True) for p in PORTS
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
