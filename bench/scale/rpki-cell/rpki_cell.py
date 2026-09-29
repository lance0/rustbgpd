#!/usr/bin/env python3
"""Helpers for run-rpki-cell.sh: the VRP fixture, the VRP-loaded gate, and
the per-cell extraction.

    rpki_cell.py check N_PEERS TOTAL_PREFIXES VRPS
    rpki_cell.py vrps N_PEERS TOTAL_PREFIXES VRPS OUT_JSON
    rpki_cell.py wait-vrps METRICS_URL WANT TIMEOUT_SECS DAEMON_PID
    rpki_cell.py summarize OUT_DIR

`vrps` writes a StayRTR JSON cache of exactly VRPS entries. Every reloadstall
base-table /24 is Valid for the stub that announces it: stub i announces the
contiguous slice member_slice(TOTAL, N_PEERS, i) with origin AS 64512+i, the
first TOTAL % N_PEERS stubs one prefix more than the rest (see member_slice,
base_prefix and stub_asn in bench/scale/reloadstall/src/main.rs). The rest
are /24s in 100.0.0.0/8 and up that cover no announced route. The output is
byte-identical for the same arguments.

`check` validates the same shape arithmetically without building the table.

`wait-vrps` polls the daemon's /metrics until the bgp_rpki_vrp_count series
sum to at least WANT, and exits 1 with a message naming the loaded count if
that does not happen within TIMEOUT_SECS or the daemon exits first.

`summarize` reads every OUT_DIR/cells/ARM-rN cell, writes OUT_DIR/cells.csv
and OUT_DIR/summary.txt, and exits 1 if any cell is incomplete, lost its VRP
table, failed its harness, or the arms ran unequal run counts.
"""

from __future__ import annotations

import csv
import json
import statistics
import sys
import time
import urllib.request
from pathlib import Path

BASE_ASN = 64512
PAD_ASN = 65000
CHUNK_SUM = 'bgp_rib_actor_work_duration_seconds_sum{work_unit="route_chunk"}'
CHUNK_COUNT = 'bgp_rib_actor_work_duration_seconds_count{work_unit="route_chunk"}'
COLUMNS = ["arm", "run", "position", "vrps_expected", "vrps_loaded", "route_chunk_sum_s",
           "route_chunk_count", "daemon_cpu_s", "convergence_wall_s", "harness_rc"]
ARMS = ("base", "head")
METRICS = ("route_chunk_sum_s", "daemon_cpu_s", "convergence_wall_s")


def member_slice(total: int, peers: int, member: int) -> tuple[int, int]:
    """(start, len) of a member's base-table slice, as reloadstall's member_slice:
    contiguous disjoint slices, the first TOTAL % N_PEERS members one longer."""
    q, r = divmod(total, peers)
    return member * q + min(member, r), q + (member < r)


def check_shape(n_peers: int, total: int, vrps: int) -> None:
    """Arithmetic-only shape check; raises ValueError."""
    if n_peers < 1 or total < n_peers:
        raise ValueError("need at least one prefix per peer")
    if vrps < total:
        raise ValueError(f"VRPS={vrps} is below the {total} announced prefixes; every route must validate")
    if 20 + ((total - 1) >> 16) >= 100 or 100 + ((vrps - total - 1) >> 16) > 223:
        raise ValueError("prefix space exhausted")


def roas(n_peers: int, total: int, vrps: int) -> list[dict]:
    check_shape(n_peers, total, vrps)
    out = []
    for member in range(n_peers):
        start, length = member_slice(total, n_peers, member)
        for idx in range(start, start + length):
            out.append({"asn": f"AS{BASE_ASN + member}",
                        "prefix": f"{20 + (idx >> 16)}.{(idx >> 8) & 0xFF}.{idx & 0xFF}.0/24",
                        "maxLength": 24, "ta": "bench"})
    for j in range(vrps - total):
        out.append({"asn": f"AS{PAD_ASN + j % 500}",
                    "prefix": f"{100 + (j >> 16)}.{(j >> 8) & 0xFF}.{j & 0xFF}.0/24",
                    "maxLength": 24, "ta": "bench"})
    return out


def write_vrps(n_peers: int, total: int, vrps: int, path: str) -> None:
    doc = {"metadata": {"generated": 1710000000, "valid": 4102444800}, "roas": roas(n_peers, total, vrps)}
    Path(path).write_text(json.dumps(doc, separators=(",", ":")))


def series(text: str, name: str) -> float | None:
    """Value of the exact series `name` (with labels), or None if absent."""
    for line in text.splitlines():
        if line.startswith(name + " "):
            return float(line.rsplit(" ", 1)[1])
    return None


def vrp_total(text: str) -> int | None:
    values = [float(line.rsplit(" ", 1)[1]) for line in text.splitlines()
              if line.startswith(("bgp_rpki_vrp_count{", "bgp_rpki_vrp_count "))]
    return int(sum(values)) if values else None


def alive(pid: int) -> bool:
    """False once PID has exited, including an unreaped zombie child."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return stat.rsplit(")", 1)[1].split()[0] != "Z"


def wait_vrps(url: str, want: int, timeout: float, pid: int) -> int:
    deadline = time.monotonic() + timeout
    loaded = None
    while True:
        if not alive(pid):
            print(f"VRP gate failed: daemon {pid} exited with {loaded} of {want} VRPs loaded", file=sys.stderr)
            return 1
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                loaded = vrp_total(resp.read().decode())
        except OSError:
            pass
        if loaded is not None and loaded >= want:
            print(f"vrps_loaded={loaded}")
            return 0
        if time.monotonic() >= deadline:
            print(f"VRP gate failed: {loaded} of {want} VRPs loaded after {timeout:g}s; "
                  "no route was sent", file=sys.stderr)
            return 1
        time.sleep(0.5)


def read_env(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)


def cell_row(cell: Path) -> dict:
    """One cells.csv row; raises ValueError naming what is wrong."""
    env = read_env(cell / "cell.env")
    before = (cell / "metrics-before.prom").read_text()
    after = (cell / "metrics-after.prom").read_text()
    chunk_after, count = series(after, CHUNK_SUM), series(after, CHUNK_COUNT)
    if chunk_after is None or count is None or count == 0:
        raise ValueError(f"{cell.name}: no route_chunk work in metrics-after.prom")
    expected, loaded = int(env["vrps_expected"]), vrp_total(after)
    if loaded is None or loaded < expected:
        raise ValueError(f"{cell.name}: {loaded} of {expected} VRPs loaded at the convergence scrape")
    if env["harness_rc"] != "0":
        raise ValueError(f"{cell.name}: harness exited {env['harness_rc']}")
    hz = int(env["clk_tck"])
    return {
        "arm": env["arm"], "run": int(env["run"]), "position": int(env["position"]),
        "vrps_expected": expected, "vrps_loaded": loaded,
        "route_chunk_sum_s": round(chunk_after - (series(before, CHUNK_SUM) or 0.0), 4),
        "route_chunk_count": int(count - (series(before, CHUNK_COUNT) or 0.0)),
        "daemon_cpu_s": round((int(env["cpu_ticks_end"]) - int(env["cpu_ticks_start"])) / hz, 2),
        "convergence_wall_s": round(float(env["t_ready"]) - float(env["t_start"]), 2),
        "harness_rc": 0,
    }


def summarize(out: Path) -> int:
    cells = sorted(p for p in (out / "cells").iterdir() if p.is_dir())
    arms = ARMS
    rows, problems = [], []
    for cell in cells:
        try:
            rows.append(cell_row(cell))
        except (OSError, KeyError, ValueError) as err:
            problems.append(str(err) if isinstance(err, ValueError) else f"{cell.name}: {err!r}")
    runs = {arm: sum(1 for r in rows if r["arm"] == arm) for arm in arms}
    if not rows or len(set(runs.values())) != 1 or set(r["arm"] for r in rows) - set(arms):
        problems.append(f"unequal or empty complete runs per arm: {runs}")
    rows.sort(key=lambda r: (r["run"], r["position"]))
    with open(out / "cells.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    lines = []
    if not problems:
        base, head = arms
        for key in METRICS:
            b = [r[key] for r in rows if r["arm"] == base]
            h = [r[key] for r in rows if r["arm"] == head]
            mb, mh = statistics.median(b), statistics.median(h)
            lines.append(f"{key}: {base}={mb:.3f} [{min(b):.3f}-{max(b):.3f}] "
                         f"{head}={mh:.3f} [{min(h):.3f}-{max(h):.3f}] delta={(mh - mb) / mb * 100:+.1f}%")
    lines += [f"INVALID {p}" for p in problems]
    (out / "summary.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 1 if problems else 0


def main(argv: list[str]) -> int:
    cmd, args = (argv[1], argv[2:]) if len(argv) > 1 else ("", [])
    if cmd in ("check", "vrps") and len(args) == (3 if cmd == "check" else 4):
        try:
            if cmd == "check":
                check_shape(int(args[0]), int(args[1]), int(args[2]))
            else:
                write_vrps(int(args[0]), int(args[1]), int(args[2]), args[3])
        except ValueError as err:
            print(f"{cmd}: {err}", file=sys.stderr)
            return 2
        return 0
    if cmd == "wait-vrps" and len(args) == 4:
        return wait_vrps(args[0], int(args[1]), float(args[2]), int(args[3]))
    if cmd == "summarize" and len(args) == 1:
        return summarize(Path(args[0]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
