#!/usr/bin/env python3
"""Measure two EVPN originators and 1..480 receivers in an isolated Linux network."""

import argparse
from datetime import datetime
import json
import os
import re
from pathlib import Path
import subprocess
import time
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--bin-dir",
    type=Path,
    default=Path("target/release"),
    help="directory containing rustbgpd, rbgp, evpn-tester, evpn-monitor",
)
parser.add_argument("--receivers", type=int, required=True)
parser.add_argument("--routes", type=int, default=5000, help="routes per originator")
parser.add_argument("--churn-seconds", type=int, default=10)
parser.add_argument("--churn-delay-seconds", type=int, default=10)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
if not 1 <= args.receivers <= 480:
    parser.error("--receivers must be in 1..480")
if not 40 <= args.routes <= 0x01000000 or args.routes % 40:
    parser.error("--routes must be a multiple of 40 in 40..16777216")
if args.churn_seconds < 0 or args.churn_seconds % 2:
    parser.error("--churn-seconds must be zero or a positive multiple of 2")
if args.churn_delay_seconds < 0:
    parser.error("--churn-delay-seconds must be nonnegative")
args.bin_dir = args.bin_dir.resolve()
for name in ("rustbgpd", "rbgp", "evpn-tester", "evpn-monitor"):
    if not os.access(args.bin_dir / name, os.X_OK):
        parser.error(f"not an executable: {args.bin_dir / name}")
args.out.mkdir(parents=True, exist_ok=False)
root = args.out.resolve()
state = root / "state"
state.mkdir()
peers = [f"127.77.{i // 250}.{i % 250 + 1}" for i in range(args.receivers + 2)]
config = f"""[global]
asn = 65000
router_id = "10.77.0.254"
cluster_id = "10.77.0.254"
listen_addresses = ["127.77.255.254"]
listen_port = 1179
runtime_state_dir = {json.dumps(str(state))}
[global.telemetry]
prometheus_addr = "127.77.255.254:9179"
log_format = "json"
"""
for peer in peers:
    config += f'''\n[[neighbors]]
address = "{peer}"
remote_asn = 65000
families = ["l2vpn_evpn"]
route_reflector_client = true
hold_time = 180
'''
(root / "config.toml").write_text(config)
processes = []
handles = []


def start(name, command, threads=1):
    out = open(root / f"{name}.json", "w")
    log = open(root / f"{name}.log", "w")
    handles.extend([out, log])
    proc = subprocess.Popen(
        command,
        stdout=out,
        stderr=log,
        env=os.environ | {"TOKIO_WORKER_THREADS": str(threads), "RUST_LOG": "info"},
    )
    processes.append(proc)
    return proc


try:
    monitors = []
    for i, peer in enumerate(peers[2:]):
        monitors.append(
            start(
                f"monitor-{i:03}",
                [
                    str(args.bin_dir / "evpn-monitor"),
                    "--listen",
                    f"{peer}:179",
                    "--router-id",
                    f"10.77.{i // 250}.{i % 250 + 1}",
                    "--expect",
                    str(2 * args.routes),
                    "--stable-sec",
                    "1",
                    "--timeout-sec",
                    "180",
                    "--observe-sec",
                    str(args.churn_delay_seconds + args.churn_seconds + 10),
                ],
            )
        )
    for i, peer in enumerate(peers[:2]):
        start(
            f"tester-{i}",
            [
                str(args.bin_dir / "evpn-tester"),
                "--listen",
                f"{peer}:179",
                "--router-id",
                f"10.78.0.{i + 1}",
                "--count",
                str(args.routes),
                "--rate",
                "0",
                "--batch",
                "40",
                "--churn-duration-sec",
                str(args.churn_seconds),
                "--churn-rate",
                "1000",
                "--churn-delay-sec",
                str(args.churn_delay_seconds),
                "--linger-sec",
                str(max(240, 220 + args.churn_delay_seconds + args.churn_seconds)),
            ],
        )
    time.sleep(1)
    if any(p.poll() is not None for p in processes):
        raise RuntimeError("peer failed before reflector start; inspect peer logs")
    daemon = start("daemon", [str(args.bin_dir / "rustbgpd"), str(root / "config.toml")], threads=8)
    started = time.monotonic()
    samples = []
    while any(p.poll() is None for p in monitors):
        if daemon.poll() is not None:
            raise RuntimeError("reflector exited; inspect daemon logs")
        if time.monotonic() - started >= 190 + args.churn_delay_seconds + args.churn_seconds:
            raise RuntimeError("overall deadline exceeded")
        stat = Path(f"/proc/{daemon.pid}/stat").read_text().split()
        samples.append(
            {
                "elapsed_sec": time.monotonic() - started,
                "cpu_sec": (int(stat[13]) + int(stat[14])) / os.sysconf("SC_CLK_TCK"),
                "rss_bytes": int(stat[23]) * os.sysconf("SC_PAGE_SIZE"),
            }
        )
        time.sleep(0.2)
    reports = [
        json.loads((root / f"monitor-{i:03}.json").read_text()) for i in range(args.receivers)
    ]
    expected = 2 * args.routes

    def event_time(name, event):
        line = next(
            line for line in (root / f"{name}.log").read_text().splitlines() if event in line
        )
        stamp = re.search(r"\d{4}-\d{2}-\d{2}T[0-9:.]+Z", line).group()
        return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()

    full_table_times = [
        event_time(f"monitor-{i:03}", "session established, observing")
        + report["initial_convergence_sec"]
        for i, report in enumerate(reports)
    ]
    before_churn = args.churn_seconds == 0 or max(full_table_times) < min(
        event_time(f"tester-{i}", "starting churn phase") for i in range(2)
    )
    valid = (
        before_churn
        and all(p.returncode == 0 for p in monitors)
        and all(
            r["converged"]
            and not r["timed_out"]
            and r["final_count"] == expected
            and r["stats"]["parse_errors"] == 0
            and r["total_withdrawals"] == 1000 * args.churn_seconds
            for r in reports
        )
    )
    neighbors = subprocess.run(
        [str(args.bin_dir / "rbgp"), "-s", f"unix://{state}/grpc.sock", "--json", "neighbor"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    (root / "neighbors.json").write_text(neighbors.stdout)
    # Monitors deliberately exit after their observation window. Originators must remain live.
    neighbor_rows = json.loads(neighbors.stdout)
    valid &= neighbors.returncode == 0 and all(
        any(p["address"] == peer and p["state"] == "Established" for p in neighbor_rows)
        for peer in peers[:2]
    )
    routes = subprocess.run(
        [str(args.bin_dir / "rbgp"), "-s", f"unix://{state}/grpc.sock", "--json", "evpn"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    (root / "selected.json").write_text(routes.stdout)
    selected = json.loads(routes.stdout)
    selected_count = len(selected)
    expected_keys = {
        (
            f"10.78.0.{source}:1",
            f"02:00:00:{index >> 16:02x}:{(index >> 8) & 255:02x}:{index & 255:02x}",
        )
        for source in (1, 2)
        for index in range(args.routes)
    }
    selected_keys = {(row["rd"], row["mac"]) for row in selected}
    valid &= (
        routes.returncode == 0 and selected_count == expected and selected_keys == expected_keys
    )
    valid &= all(
        row["route_type"] == 2 and row["ethernet_tag"] == "0" and row["ip"] == ""
        for row in selected
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open("http://127.77.255.254:9179/metrics", timeout=10) as response:
            (root / "metrics.txt").write_bytes(response.read())
    finally:
        (root / "samples.json").write_text(json.dumps(samples))
    summary = {
        "receivers": args.receivers,
        "originators": 2,
        "routes_per_originator": args.routes,
        "churn_seconds": args.churn_seconds,
        "all_receivers_full_before_churn": before_churn,
        "churn_delay_seconds": args.churn_delay_seconds,
        "correct": bool(valid),
        "selected_count": selected_count,
        "initial_convergence_min_sec": min(r["initial_convergence_sec"] for r in reports),
        "initial_convergence_max_sec": max(r["initial_convergence_sec"] for r in reports),
        "expected_withdrawals_per_receiver": 1000 * args.churn_seconds,
        "withdrawals_min": min(r["total_withdrawals"] for r in reports),
        "withdrawals_max": max(r["total_withdrawals"] for r in reports),
        "cpu_sec": samples[-1]["cpu_sec"],
        "elapsed_sec": samples[-1]["elapsed_sec"],
        "peak_rss_bytes": max(s["rss_bytes"] for s in samples),
    }
    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
    if not valid:
        raise RuntimeError("receiver correctness failed; inspect summary and raw reports")
finally:
    for proc in reversed(processes):
        if proc.poll() is None:
            proc.terminate()
    for proc in processes:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    for handle in handles:
        handle.close()
