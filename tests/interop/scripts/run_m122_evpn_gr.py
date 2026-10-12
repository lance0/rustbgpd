#!/usr/bin/env python3
"""Run the admitted GoBGP EVPN RR restart/LLGR correctness lifecycle."""

import json
import hashlib
import os
import re
import subprocess
import time
from pathlib import Path

from m105_capture_oracle import messages, reassemble, need
from m122_evpn_gr_oracle import SOURCE, RR, RR_CLIENT, CLIENT, admit_open, analyze_wire, check_rr, check_client, client_withdrawals, expected_nlri, nlri_key

LAB = "m122-evpn-gr-rr-gobgp"
REFLECTOR = f"clab-{LAB}-rustbgpd"
PE = f"clab-{LAB}-gobgp-source"
SINK = f"clab-{LAB}-gobgp-client"
CAPTURE = f"clab-{LAB}-capture"
OUT = Path(os.environ.get("M122_OUT", "/tmp/m122-evpn-gr-rr")).resolve()
TOOLS = os.environ.get("M122_TOOLS_IMAGE", "rustbgpd:m122-tools")
IFACE = os.environ.get("M122_SOURCE_INTERFACE", "eth1")


def command(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True, timeout=30).stdout


def docker(container, *args):
    return command("docker", "exec", container, *args)


def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def wait(label, read, check, timeout=45):
    # Query/JSON errors escape immediately; only a successfully observed
    # intermediate state may be polled again.
    until = time.monotonic() + timeout
    while True:
        value = read()
        try:
            check(value)
            print(f"PASS {label}", flush=True)
            return value
        except ValueError:
            if time.monotonic() >= until:
                raise
        time.sleep(1)


def ready(container, args):
    for _ in range(30):
        result = subprocess.run(["docker", "exec", container, *args], text=True, capture_output=True, timeout=10)
        if result.returncode == 0:
            return
        time.sleep(1)
    raise ValueError(f"{container}: daemon did not become ready: {result.stderr}")


def gobgp(container, *args):
    return docker(container, "gobgp", *args)


def start_peer(container, restarting=False):
    args = " -r" if restarting else ""
    docker(container, "sh", "-c", f"nohup gobgpd -f /config/gobgp.toml{args} >/tmp/gobgpd.log 2>&1 &")
    ready(container, ["gobgp", "global"])


def kill_source():
    docker(PE, "sh", "-c", 'for p in /proc/[0-9]*; do if [ "$(cat "$p/comm" 2>/dev/null)" = gobgpd ]; then kill -9 "${p#/proc/}"; fi; done')


def inject(s):
    e = f"00:00:00:00:00:00:00:12:0{s}"
    paths = [
        ["a-d", "esi", "arbitrary", e, "etag", "0", "label", "10122", "rd", f"65001:1{s}"],
        ["macadv", f"02:00:00:00:12:0{s}", f"192.0.2.{s}", "etag", "0", "label", "10122", "rd", f"65001:2{s}"],
        ["multicast", SOURCE, "etag", "0", "rd", f"65001:3{s}", "pmsi", "ingress-repl", "10122", SOURCE],
        ["esi", SOURCE, "esi", "arbitrary", e, "rd", f"65001:4{s}"],
        ["prefix", f"203.0.113.{s}/32", "gw", "0.0.0.0", "etag", "0", "label", "10122", "rd", f"65001:5{s}"],
    ]
    for path in paths:
        gobgp(PE, "global", "rib", "add", "-a", "evpn", *path, "rt", "65001:122", "encap", "vxlan", "nexthop", SOURCE)


def rr_rows():
    return json.loads(docker(REFLECTOR, "rbgp", "-s", "http://127.0.0.1:50051", "evpn", "-j"))


def sink_rows():
    return json.loads(gobgp(SINK, "global", "rib", "-a", "evpn", "-j"))


def metric(name):
    text = docker(CAPTURE, "python3", "-c", 'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:9179/metrics", timeout=5).read().decode())')
    matches = re.findall(rf'^{re.escape(name)}\{{peer="{re.escape(SOURCE)}"\}} (\d+)$', text, re.M)
    need(len(matches) == 1, f"missing/duplicate source metric {name}")
    return int(matches[0])


def flaps():
    text = gobgp(SINK, "neighbor", RR_CLIENT)
    need("BGP state = SESSION_STATE_ESTABLISHED" in text, "client session is not Established")
    values = re.findall(r"Flops = (\d+)", text)
    need(len(values) == 1, "client flap counter missing")
    return int(values[0])


def snapshot(phase, sets, llgr=False):
    rr = wait(f"{phase}: exact RR identities", rr_rows, lambda rows: check_rr(rows, sets, llgr))
    sink = wait(f"{phase}: exact client identities", sink_rows, lambda rows: check_client(rows, sets, llgr))
    need(flaps() == 0, "client session flapped")
    # The labelled gauge is created by the first GR transition, not PeerUp.
    stale = None if phase == "initial" else metric("bgp_gr_stale_routes")
    save(f"{phase}.json", {"rr": rr, "client": sink, "source_stale": stale, "client_flaps": 0})


def payloads():
    text = docker(CAPTURE, "tshark", "-r", "/out/capture.pcap", "-Y", "tcp.len > 0", "-T", "fields",
                  "-e", "tcp.stream", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.seq_raw", "-e", "tcp.payload")
    (OUT / "capture.tsv").write_text(text)
    return text.splitlines()


def live_admission(lines):
    parts = {}
    for line in lines:
        stream, src, dst, seq, payload = line.split("\t")
        if payload:
            parts.setdefault((stream, src, dst), []).append((int(seq), bytes.fromhex(payload.replace(":", ""))))
    witnesses = []
    for (_, src, dst), segments in parts.items():
        for typ, body in messages(reassemble(segments)):
            if typ == 1:
                witnesses.append({"source": src, "destination": dst, **admit_open(body)})
    need({(w["source"], w["destination"]) for w in witnesses} == {(SOURCE, RR), (RR, SOURCE), (CLIENT, RR_CLIENT), (RR_CLIENT, CLIENT)}, "initial OPEN exchange incomplete")
    return witnesses


def provenance():
    peers = []
    for container in (PE, SINK):
        need(gobgp(container, "--version").strip() == "gobgp version 4.10.0", "GoBGP CLI version differs")
        need(docker(container, "gobgpd", "--version").strip() == "gobgpd version 4.10.0", "GoBGP daemon version differs")
        hashes = docker(container, "sha256sum", "/usr/local/bin/gobgp", "/usr/local/bin/gobgpd").splitlines()
        want = ["55eded2e53f5c597baab409f69d18729292a6e28084fd0ce2be9b5383a406f86", "bea17d8561b776cb35820ce14601a617e26acb1efa687b9d949a1737ee2f670d"]
        need([line.split()[0] for line in hashes] == want, "GoBGP binary identity differs")
        image = command("docker", "inspect", "--format", "{{.Image}}", container).strip()
        need(command("docker", "image", "inspect", "--format", "{{.Architecture}}", image).strip() == "amd64", "GoBGP image architecture differs")
        peers.append({"image": image, "gobgp_sha256": want[0], "gobgpd_sha256": want[1]})
    source_id = command("bash", "scripts/source-id.sh").strip()
    need(docker(REFLECTOR, "cat", "/usr/local/share/rustbgpd/source-id").strip() == source_id, "RR image source ID differs")
    inputs = ["tests/interop/scripts/m122_evpn_gr_oracle.py", "tests/interop/scripts/run_m122_evpn_gr.py",
              "tests/interop/scripts/m105_capture_oracle.py", "tests/interop/scripts/test-m122-evpn-gr-rr-gobgp.sh",
              "tests/interop/m122-evpn-gr-rr-gobgp.clab.yml", "tests/interop/Dockerfile.m122-tools",
              "tests/interop/configs/rustbgpd-m122-evpn-gr-rr.toml", "tests/interop/configs/gobgp-m122-source.toml",
              "tests/interop/configs/gobgp-m122-client.toml"]
    hashes = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in inputs}
    save("provenance.json", {"rustbgpd_source_id": source_id, "rustbgpd_commit": command("git", "rev-parse", "HEAD").strip(),
                            "harness_dirty": bool(command("git", "status", "--porcelain").strip()), "harness_sha256": hashes,
                            "gobgp_source_commit": "da824d99912e02124b53741245ee4186c381adcc", "gobgp_version": "4.10.0", "peers": peers})


def run():
    OUT.mkdir(parents=True, exist_ok=True)
    provenance()
    command("docker", "run", "-d", "--name", CAPTURE, "--label", "rustbgpd.lab=m122", "--network", f"container:{REFLECTOR}",
            "--cap-add", "NET_RAW", "-v", f"{OUT}:/out", TOOLS, "tcpdump", "--immediate-mode", "-B", "8192", "-s", "0", "-U", "-i", "any", "-w", "/out/capture.pcap", "tcp", "port", "179")
    try:
        wait("capture armed", lambda: subprocess.run(["docker", "logs", CAPTURE], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True).stdout,
             lambda value: need("listening on any" in value, "capture not armed"))
        docker(REFLECTOR, "sh", "-c", "nohup rustbgpd /etc/rustbgpd/config.toml >/tmp/rustbgpd.log 2>&1 &")
        ready(REFLECTOR, ["rbgp", "-s", "http://127.0.0.1:50051", "health", "--liveness"])
        start_peer(PE)
        start_peer(SINK)
        wait("source Established", lambda: gobgp(PE, "neighbor", RR), lambda v: need("SESSION_STATE_ESTABLISHED" in v, "source pending"))
        wait("client Established", lambda: gobgp(SINK, "neighbor", RR_CLIENT), lambda v: need("SESSION_STATE_ESTABLISHED" in v, "client pending"))
        lines = wait("actual MP25/70 GR64 and positive LLGR71 OPEN admission", payloads, live_admission)
        save("admission.json", live_admission(lines))
        inject(1)
        inject(2)
        snapshot("initial", [1, 2])
        kill_source()
        wait("ten stored EVPN paths marked stale", lambda: metric("bgp_gr_stale_routes"), lambda v: need(v == 10, "stale gauge differs"))
        snapshot("gr-ten", [1, 2])
        need(not client_withdrawals(payloads()), "GR window withdrew client EVPN routes")
        docker(PE, "ip", "link", "set", IFACE, "down")
        start_peer(PE, restarting=True)
        inject(1)
        docker(PE, "ip", "link", "set", IFACE, "up")
        snapshot("eor-five", [1])
        wait("EoR clears stored stale gauge", lambda: metric("bgp_gr_stale_routes"), lambda v: need(v == 0, "stale remains"))
        kill_source()
        wait("five stored EVPN paths marked stale", lambda: metric("bgp_gr_stale_routes"), lambda v: need(v == 5, "stale gauge differs"))
        snapshot("gr-five", [1])
        need(client_withdrawals(payloads()) == {nlri_key(n) for n in expected_nlri([2])}, "second GR window changed client withdrawals")
        wait("RR LLGR promotion", rr_rows, lambda rows: check_rr(rows, [1], True), timeout=90)
        snapshot("llgr-five", [1], True)
        wait("LLGR expiry at RR", rr_rows, lambda rows: check_rr(rows, []), timeout=60)
        snapshot("expired", [])
        wait("expiry clears stored stale gauge", lambda: metric("bgp_gr_stale_routes"), lambda v: need(v == 0, "stale remains"))
        lines = wait("complete raw restart/EoR/LLGR witnesses", payloads, analyze_wire, timeout=15)
        save("wire-witnesses.json", analyze_wire(lines))
        save("verdict.json", {"result": "pass", "initial_routes": 10, "refreshed_routes": 5, "eor_swept_routes": 5,
                              "llgr_routes": 5, "expired_routes": 5, "route_types": [1, 2, 3, 4, 5], "client_flaps": 0})
        print("PASS M122 EVPN GR/EoR/LLGR Types 1–5", flush=True)
    finally:
        for container in (REFLECTOR, PE, SINK):
            subprocess.run(["docker", "cp", f"{container}:/tmp/" + ("rustbgpd.log" if container == REFLECTOR else "gobgpd.log"), str(OUT / ("rr.log" if container == REFLECTOR else "source.log" if container == PE else "client.log"))], capture_output=True)
        subprocess.run(["docker", "kill", "--signal", "SIGINT", CAPTURE], capture_output=True)
        subprocess.run(["docker", "wait", CAPTURE], capture_output=True, timeout=15)
        captured = subprocess.run(["docker", "logs", CAPTURE], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15)
        (OUT / "capture.log").write_text(captured.stdout)
        subprocess.run(["docker", "rm", "-f", CAPTURE], capture_output=True)


if __name__ == "__main__":
    run()
