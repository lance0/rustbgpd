#!/usr/bin/env python3
"""Helpers for run-rpki-cell.sh: the VRP fixture, the VRP-loaded gate, and
the per-cell extraction.

    rpki_cell.py check N_PEERS TOTAL_PREFIXES VRPS [IPV4_PREFIXES]
    rpki_cell.py vrps N_PEERS TOTAL_PREFIXES VRPS OUT_JSON [IPV4_PREFIXES]
    rpki_cell.py maxlen-delta N_PEERS TOTAL_PREFIXES VRPS IPV4_PREFIXES N BASE_JSON OUT_JSON
    rpki_cell.py wait-vrps METRICS_URL WANT TIMEOUT_SECS DAEMON_PID
    rpki_cell.py summarize OUT_DIR

`vrps` writes a StayRTR JSON cache of exactly VRPS entries. Without the
optional split, every reloadstall IPv4 base-table /24 is Valid for its owning
stub, preserving the historical output. IPV4_PREFIXES selects the dual-stack
shape: TOTAL_PREFIXES is the total across families, the remainder is IPv6,
and each family uses member_slice(FAMILY_TOTAL, N_PEERS, i) with origin
AS 64512+i. IPv6 base routes are 3001:HHHH:LLLL::/48. Padding /24s cover no
announced route. `maxlen-delta` takes only a canonical dual-stack `vrps`
output and changes N distributed announced entries' maxLength, from 24 to 25
or 48 to 49. The ROA still validates its /24 or /48 route; exactly N old
entries are withdrawn and N replacement entries announced if served as an
incremental RTR update. This helper does not serve RTR or prove that update.

`check` validates the same shape arithmetically without building the table.

`wait-vrps` polls the daemon's /metrics until the bgp_rpki_vrp_count series
sum to at least WANT, and exits 1 with a message naming the loaded count if
that does not happen within TIMEOUT_SECS or the daemon exits first.

`summarize` reads every OUT_DIR/cells/ARM-rN cell, writes OUT_DIR/cells.csv
and OUT_DIR/summary.txt, and exits 1 if any cell is incomplete, lost its VRP
table, failed its harness, or the arms have unpaired or duplicate run IDs.
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
MIN_PEERS = 8  # reloadstall CHURNERS: the harness refuses fewer stubs
MAX_PEERS = 51200  # reloadstall stub i uses 127.1.(i // 200).(i % 200 + 1)
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


def family_totals(n_peers: int, total: int, ipv4_prefixes: int | None) -> tuple[int, int]:
    if ipv4_prefixes is None:
        return total, 0
    ipv6_prefixes = total - ipv4_prefixes
    if ipv4_prefixes < n_peers or ipv6_prefixes < n_peers:
        raise ValueError("both families need at least one prefix per peer")
    return ipv4_prefixes, ipv6_prefixes


def check_fixture(n_peers: int, total: int, vrps: int,
                  ipv4_prefixes: int | None = None) -> None:
    if n_peers < 1 or total < n_peers:
        raise ValueError("need at least one prefix per peer")
    v4, v6 = family_totals(n_peers, total, ipv4_prefixes)
    if vrps < total:
        raise ValueError(f"VRPS={vrps} is below the {total} announced prefixes; every route must validate")
    if (20 + ((v4 - 1) >> 16) >= 100 or v6 > 1 << 32
            or 100 + ((vrps - total - 1) >> 16) > 223):
        raise ValueError("prefix space exhausted")


def check_shape(n_peers: int, total: int, vrps: int,
                ipv4_prefixes: int | None = None) -> None:
    """Arithmetic-only check of a cell shape, including the harness's own
    rules (at least CHURNERS stubs, IPv4-only TOTAL a multiple of N_PEERS;
    dual-stack families can have remainder slices). Raises ValueError."""
    if n_peers < MIN_PEERS:
        raise ValueError(f"N_PEERS={n_peers} is below the reloadstall minimum of {MIN_PEERS}")
    if n_peers > MAX_PEERS:
        raise ValueError(f"N_PEERS={n_peers} exceeds the reloadstall address limit of {MAX_PEERS}")
    if ipv4_prefixes is None and total % n_peers:
        raise ValueError(f"TOTAL_PREFIXES={total} is not a multiple of N_PEERS={n_peers}; reloadstall refuses it")
    check_fixture(n_peers, total, vrps, ipv4_prefixes)


def roas(n_peers: int, total: int, vrps: int,
         ipv4_prefixes: int | None = None) -> list[dict]:
    check_fixture(n_peers, total, vrps, ipv4_prefixes)
    v4, v6 = family_totals(n_peers, total, ipv4_prefixes)
    out = []
    for member in range(n_peers):
        start, length = member_slice(v4, n_peers, member)
        for idx in range(start, start + length):
            out.append({"asn": f"AS{BASE_ASN + member}",
                        "prefix": f"{20 + (idx >> 16)}.{(idx >> 8) & 0xFF}.{idx & 0xFF}.0/24",
                        "maxLength": 24, "ta": "bench"})
    for member in range(n_peers):
        start, length = member_slice(v6, n_peers, member)
        for idx in range(start, start + length):
            out.append({"asn": f"AS{BASE_ASN + member}",
                        "prefix": f"3001:{idx >> 16:x}:{idx & 0xffff:x}::/48",
                        "maxLength": 48, "ta": "bench"})
    for j in range(vrps - total):
        out.append({"asn": f"AS{PAD_ASN + j % 500}",
                    "prefix": f"{100 + (j >> 16)}.{(j >> 8) & 0xFF}.{j & 0xFF}.0/24",
                    "maxLength": 24, "ta": "bench"})
    return out


def fixture_doc(n_peers: int, total: int, vrps: int,
                ipv4_prefixes: int | None = None) -> dict:
    return {"metadata": {"generated": 1710000000, "valid": 4102444800},
            "roas": roas(n_peers, total, vrps, ipv4_prefixes)}


def write_vrps(n_peers: int, total: int, vrps: int, path: str,
               ipv4_prefixes: int | None = None) -> None:
    doc = fixture_doc(n_peers, total, vrps, ipv4_prefixes)
    Path(path).write_text(json.dumps(doc, separators=(",", ":")))


def replacement_indices(v4: int, v6: int, count: int) -> list[int]:
    """Spread changed announced records across both family inventories."""
    if not 1 <= count <= v4 + v6:
        raise ValueError(f"replacement count must be in 1..={v4 + v6}")
    v4_count = min(v4, (count + 1) // 2)
    v6_count = min(v6, count - v4_count)
    v4_count = count - v6_count
    return ([i * v4 // v4_count for i in range(v4_count)]
            + [v4 + i * v6 // v6_count for i in range(v6_count)])


def write_maxlen_delta(n_peers: int, total: int, vrps: int, ipv4_prefixes: int,
                       count: int, base_path: str, out_path: str) -> tuple[int, int]:
    """Accept only our baseline; change N announced VRPs without changing validity."""
    check_shape(n_peers, total, vrps, ipv4_prefixes)
    if Path(base_path).resolve() == Path(out_path).resolve():
        raise ValueError("BASE_JSON and OUT_JSON must be different paths")
    baseline = json.loads(Path(base_path).read_text())
    if baseline != fixture_doc(n_peers, total, vrps, ipv4_prefixes):
        raise ValueError("BASE_JSON is not the canonical VRP fixture for this shape")
    v4, v6 = family_totals(n_peers, total, ipv4_prefixes)
    selected = replacement_indices(v4, v6, count)
    for index in selected:
        baseline["roas"][index]["maxLength"] += 1
    Path(out_path).write_text(json.dumps(baseline, separators=(",", ":")))
    v4_changed = sum(index < v4 for index in selected)
    return v4_changed, count - v4_changed


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
    """Only a scrape that completes by the deadline counts, and no request may
    wait longer than the budget that remains."""
    deadline = time.monotonic() + timeout
    loaded = None
    while True:
        if not alive(pid):
            print(f"VRP gate failed: daemon {pid} exited with {loaded} of {want} VRPs loaded", file=sys.stderr)
            return 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print(f"VRP gate failed: {loaded} of {want} VRPs loaded after {timeout:g}s; "
                  "no route was sent", file=sys.stderr)
            return 1
        try:
            with urllib.request.urlopen(url, timeout=min(5.0, remaining)) as resp:
                text = resp.read().decode()
            if time.monotonic() <= deadline:
                loaded = vrp_total(text)
        except OSError:
            pass
        if loaded is not None and loaded >= want:
            print(f"vrps_loaded={loaded}")
            return 0
        time.sleep(max(0.0, min(0.5, deadline - time.monotonic())))


def read_env(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)


def cell_row(cell: Path) -> dict:
    """One cells.csv row; raises ValueError naming what is wrong."""
    env = read_env(cell / "cell.env")
    before = (cell / "metrics-before.prom").read_text()
    after = (cell / "metrics-after.prom").read_text()
    chunk_before, count_before = series(before, CHUNK_SUM), series(before, CHUNK_COUNT)
    chunk_after, count_after = series(after, CHUNK_SUM), series(after, CHUNK_COUNT)
    if chunk_before is None or count_before is None or chunk_after is None or count_after is None:
        raise ValueError(f"{cell.name}: missing route_chunk series in metrics snapshot")
    if count_after <= count_before:
        raise ValueError(f"{cell.name}: no route_chunk work between metrics snapshots")
    expected, loaded = int(env["vrps_expected"]), vrp_total(after)
    if loaded is None or loaded < expected:
        raise ValueError(f"{cell.name}: {loaded} of {expected} VRPs loaded at the convergence scrape")
    if env["harness_rc"] != "0":
        raise ValueError(f"{cell.name}: harness exited {env['harness_rc']}")
    hz = int(env["clk_tck"])
    return {
        "arm": env["arm"], "run": int(env["run"]), "position": int(env["position"]),
        "vrps_expected": expected, "vrps_loaded": loaded,
        "route_chunk_sum_s": round(chunk_after - chunk_before, 4),
        "route_chunk_count": int(count_after - count_before),
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
    runs = {arm: [r["run"] for r in rows if r["arm"] == arm] for arm in arms}
    if (not rows or set(runs[arms[0]]) != set(runs[arms[1]])
            or any(len(ids) != len(set(ids)) for ids in runs.values())
            or set(r["arm"] for r in rows) - set(arms)):
        problems.append(f"unequal, duplicate, or empty complete runs per arm: {runs}")
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
    if cmd in ("check", "vrps") and len(args) in ((3, 4) if cmd == "check" else (4, 5)):
        try:
            if cmd == "check":
                check_shape(int(args[0]), int(args[1]), int(args[2]),
                            int(args[3]) if len(args) == 4 else None)
            else:
                write_vrps(int(args[0]), int(args[1]), int(args[2]), args[3],
                           int(args[4]) if len(args) == 5 else None)
        except ValueError as err:
            print(f"{cmd}: {err}", file=sys.stderr)
            return 2
        return 0
    if cmd == "maxlen-delta" and len(args) == 7:
        try:
            v4_changed, v6_changed = write_maxlen_delta(
                int(args[0]), int(args[1]), int(args[2]), int(args[3]),
                int(args[4]), args[5], args[6])
        except (OSError, ValueError, TypeError) as err:
            print(f"{cmd}: {err}", file=sys.stderr)
            return 2
        print(f"maxlen-delta: withdrawals={v4_changed + v6_changed} "
              f"announcements={v4_changed + v6_changed} "
              f"ipv4={v4_changed} ipv6={v6_changed}")
        return 0
    if cmd == "wait-vrps" and len(args) == 4:
        return wait_vrps(args[0], int(args[1]), float(args[2]), int(args[3]))
    if cmd == "summarize" and len(args) == 1:
        return summarize(Path(args[0]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
