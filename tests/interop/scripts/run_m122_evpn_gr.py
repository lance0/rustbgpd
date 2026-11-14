#!/usr/bin/env python3
"""Run the admitted GoBGP EVPN RR restart/LLGR correctness lifecycle."""

import json
import hashlib
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from m105_capture_oracle import messages, reassemble, need
from m122_evpn_gr_oracle import SOURCE, RR, RR_CLIENT, CLIENT, admit_open, analyze_wire, check_rr, check_client, client_withdrawals, expected_nlri, nlri_key, capture_row
from m122_fsm_trace import parse_logs

LAB = "m122-evpn-gr-rr-gobgp"
REFLECTOR = f"clab-{LAB}-rustbgpd"
PE = f"clab-{LAB}-gobgp-source"
SINK = f"clab-{LAB}-gobgp-client"
CAPTURE = f"clab-{LAB}-capture"
OUT = Path(os.environ.get("M122_OUT", "/tmp/m122-evpn-gr-rr")).resolve()
TOOLS = os.environ.get("M122_TOOLS_IMAGE", "rustbgpd:m122-tools")
IFACE = os.environ.get("M122_SOURCE_INTERFACE", "eth1")
CAPTURE_FIELDS = ("-r", "/out/capture.pcap", "-Y", "tcp.len > 0", "-T", "fields",
                  "-e", "tcp.stream", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.seq_raw", "-e", "tcp.payload",
                  "-e", "tcp.srcport", "-e", "tcp.dstport")


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
    # Keep the original session's collision history when the source restarts.
    docker(container, "sh", "-c", f"nohup gobgpd -f /config/gobgp.toml{args} >>/tmp/gobgpd.log 2>&1 &")
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
    expected_stale = {"gr-ten": 10, "gr-five": 5, "llgr-five": 5, "eor-five": 0, "expired": 0}
    stale = None if phase == "initial" else wait(
        f"{phase}: exact stored stale gauge", lambda: metric("bgp_gr_stale_routes"),
        lambda value: need(value == expected_stale[phase], "phase stale gauge differs"))
    save(f"{phase}.json", {"rr": rr, "client": sink, "source_stale": stale, "client_flaps": 0})


def payloads():
    text = docker(CAPTURE, "tshark", *CAPTURE_FIELDS)
    (OUT / "capture.tsv").write_text(text)
    return text.splitlines()


def collect_evidence():
    def retain(args, destination=None):
        try:
            result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT if destination == "capture.log" else subprocess.PIPE,
                                    check=True, timeout=15)
            if destination:
                (OUT / destination).write_text(result.stdout)
            return result
        except (OSError, subprocess.SubprocessError) as error:
            print(f"WARNING: M122 evidence collection failed: {error}", file=sys.stderr)
            return None

    retain(["docker", "kill", "--signal", "SIGINT", CAPTURE])
    flushed = retain(["docker", "wait", CAPTURE])
    # Retain actual container state before removal even when wait timed out.
    # This is diagnostic evidence; it cannot replace the bounded wait result.
    retain(["docker", "inspect", "--format", "{{json .State}}", CAPTURE], "capture-state.json")
    clean_exit = flushed is not None and flushed.stdout.strip() == "0"
    if not clean_exit:
        status = None if flushed is None else flushed.stdout.strip()
        print(f"WARNING: M122 capture did not stop cleanly: exit={status}", file=sys.stderr)
    # A live sample must not masquerade as the final capture if extraction fails.
    tsv_removed = True
    try:
        (OUT / "capture.tsv").unlink(missing_ok=True)
    except OSError as error:
        tsv_removed = False
        print(f"WARNING: cannot remove stale M122 capture TSV: {error}", file=sys.stderr)
    extracted = None
    if flushed is not None:
        extracted = retain(["docker", "run", "--rm", "--network", "none", "-v", f"{OUT}:/out:ro",
                            TOOLS, "tshark", *CAPTURE_FIELDS], "capture.tsv")
    retain(["docker", "logs", CAPTURE], "capture.log")
    for container, source, destination in ((REFLECTOR, "rustbgpd.log", "rr.log"),
                                           (PE, "gobgpd.log", "source.log"),
                                           (SINK, "gobgpd.log", "client.log")):
        retain(["docker", "cp", f"{container}:/tmp/{source}", str(OUT / destination)])
    retain(["docker", "rm", "-f", CAPTURE])
    try:
        traces = parse_logs({name: (OUT / name).read_text() for name in ("rr.log", "source.log", "client.log")})
        save("fsm-traces.json", traces)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"WARNING: M122 FSM evidence incomplete: {error}", file=sys.stderr)
    return clean_exit and tsv_removed and extracted is not None


def live_admission(lines):
    parts = {}
    for line in lines:
        stream, src, dst, seq, payload, _ = capture_row(line)
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
    source_commit = "53ceb78fe284018ce83a92f3039198f0a86dc823"
    patch_path = "tests/interop/patches/m122-gobgp-fsm-trace.patch"
    patch_sha256 = hashlib.sha256(Path(patch_path).read_bytes()).hexdigest()
    version = "4.11.0-m122-fsm-trace"
    for container in (PE, SINK):
        need(gobgp(container, "--version").strip() == f"gobgp version {version}", "GoBGP CLI version differs")
        need(docker(container, "gobgpd", "--version").strip() == f"gobgpd version {version}", "GoBGP daemon version differs")
        need(docker(container, "cat", "/usr/local/share/gobgp-m122/source-commit").strip() == source_commit, "GoBGP source identity differs")
        need(docker(container, "cat", "/usr/local/share/gobgp-m122/patch-sha256").strip() == patch_sha256, "GoBGP trace patch differs")
        hashes = docker(container, "sha256sum", "/usr/local/bin/gobgp", "/usr/local/bin/gobgpd").splitlines()
        manifest = docker(container, "cat", "/usr/local/share/gobgp-m122/binaries.sha256").splitlines()
        need(hashes == manifest and len(hashes) == 2, "GoBGP instrumented binary identity differs")
        image = command("docker", "inspect", "--format", "{{.Image}}", container).strip()
        need(command("docker", "image", "inspect", "--format", "{{.Architecture}}", image).strip() == "amd64", "GoBGP image architecture differs")
        peers.append({"image": image, "gobgp_sha256": hashes[0].split()[0], "gobgpd_sha256": hashes[1].split()[0]})
    source_id = command("bash", "scripts/source-id.sh").strip()
    need(docker(REFLECTOR, "cat", "/usr/local/share/rustbgpd/source-id").strip() == source_id, "RR image source ID differs")
    inputs = ["tests/interop/scripts/m122_evpn_gr_oracle.py", "tests/interop/scripts/run_m122_evpn_gr.py",
              "tests/interop/scripts/m105_capture_oracle.py", "tests/interop/scripts/m122_fsm_trace.py",
              "tests/interop/Dockerfile.gobgp-m122-trace", patch_path, "tests/interop/scripts/test-m122-evpn-gr-rr-gobgp.sh",
              "tests/interop/m122-evpn-gr-rr-gobgp.clab.yml", "tests/interop/Dockerfile.m122-tools",
              "tests/interop/configs/rustbgpd-m122-evpn-gr-rr.toml", "tests/interop/configs/gobgp-m122-source.toml",
              "tests/interop/configs/gobgp-m122-client.toml"]
    hashes = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in inputs}
    save("provenance.json", {"rustbgpd_source_id": source_id, "rustbgpd_commit": command("git", "rev-parse", "HEAD").strip(),
                            "harness_dirty": bool(command("git", "status", "--porcelain").strip()), "harness_sha256": hashes,
                            "gobgp_source_commit": source_commit, "gobgp_version": version,
                            "gobgp_trace_patch_sha256": patch_sha256, "peers": peers})


def run():
    OUT.mkdir(parents=True, exist_ok=True)
    for name in ("verdict.json", "wire-witnesses.json", "fsm-traces.json", "capture-state.json", "rr.log", "source.log", "client.log"):
        (OUT / name).unlink(missing_ok=True)
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
        # Wait for the wire lifecycle only. Collision classification needs the
        # final flushed capture and logs, and must not be polled until it passes.
        wait("complete client expiry withdrawals", payloads,
             lambda rows: need(client_withdrawals(rows) == {nlri_key(n) for n in expected_nlri([1, 2])},
                               "client expiry withdrawals incomplete"), timeout=15)
    finally:
        capture_complete = collect_evidence()
    finalize_evidence(capture_complete)
    print("PASS M122 EVPN GR/EoR/LLGR Types 1–5", flush=True)


def finalize_evidence(capture_complete):
    need(capture_complete, "final capture lacks clean exit and fresh extraction")
    traces = parse_logs({name: (OUT / name).read_text() for name in ("rr.log", "source.log", "client.log")})
    save("fsm-traces.json", traces)
    witnesses = analyze_wire((OUT / "capture.tsv").read_text().splitlines(), traces)
    save("wire-witnesses.json", witnesses)
    save("verdict.json", {"result": "pass", "initial_routes": 10, "refreshed_routes": 5, "eor_swept_routes": 5,
                          "llgr_routes": 5, "expired_routes": 5, "route_types": [1, 2, 3, 4, 5], "client_flaps": 0})


if __name__ == "__main__":
    run()
