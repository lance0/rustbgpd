#!/usr/bin/env python3
"""Post-hoc analyzer for the EVPN route-reflector soak.

Reads samples.csv + cycles.log + run.json + rustbgpd.log +
management-plane-load.jsonl + metrics-snapshots.txt.gz emitted by
run-soak-evpn-rr.sh and emits a JSON verdict against the precommitted gates
in docs/soaks/soak-acceptance-gates.md (scenario 12).

Reused unchanged from the route-server flagship analyzer: minimum sample
count, aggregate sent-counter monotonicity, readyz availability, late-window
RSS/intern slopes, no ABORT record, the daemon-log gate and every
management-plane gate (with the EVPN operation set). Scenario-specific:

  - RSS peak below this scenario's own ceiling (EVPN_RSS_PEAK_LIMIT_MB)

  - session floor: every post-warmup sample fully Established, except one
    client down inside a declared flap window
  - reload accounting exact: issued == complete == planned
  - flap accounting exact: executed == planned, numbered 1..planned, never
    client 0, each re-established within the reestablish cap
  - flap budget exact: daemon session-flap delta == executed flaps
  - max-prefix flat: bgp_max_prefix_exceeded_total stays 0
  - EVPN convergence: one line per planned epoch, each with every client
    receiving exactly the expected reflected set (min == max == expected,
    receivers == clients, no invalid routes, no parse errors), within the
    convergence cap, with the planned churn/flap/reload schedule
  - EVPN terminal receipt: exactly one, matching the plan
  - per-series sent counters: every bgp_messages_sent_total series in the
    retained /metrics snapshots is present in each later snapshot and never
    decreases

Missing evidence fails closed. Stdlib only. Exit code 0 on pass, 1 on any
gate failure, 2 on harness/input error.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import importlib.util
import json
import re
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from flagship_daemon_log import analyze_daemon_log  # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "rs_soak_analyzer", HERE / "analyze-soak-rs-flagship.py")
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("could not load the route-server flagship analyzer")
rs = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(rs)

EVPN_OPERATIONS = ("metrics", "neighbor", "evpn_received", "evpn_advertised", "doctor")
EVPN_PEER = "127.1.0.1"
# Precommitted in soak-acceptance-gates.md scenario 12: 1.6x the 2,512 MB
# peak (initial table dump; 2.15 GB steady) measured at the default shape.
EVPN_RSS_PEAK_LIMIT_MB = 4096.0
REUSED_GATES = (
    "min_samples", "msgs_sent_monotone", "readyz",
    "rss_late_slope_per_hour", "intern_late_slope_per_hour", "no_abort",
)
META_INTS = (
    "peers", "type2_per_client", "type5_per_client", "shift2_per_epoch",
    "shift5_per_epoch", "expected_per_client", "soak_seconds", "epoch_sec",
    "converge_cap_sec", "reestablish_cap_sec", "planned_epochs", "flap_every",
    "reload_every", "planned_flaps", "planned_reloads", "sample_interval_sec",
    "warmup_sec",
)
KV_RE = re.compile(r"(\w+)=(-?\d+)")
SENT_RE = re.compile(r"^bgp_messages_sent_total\{(?P<labels>[^}]*)\} (?P<value>\S+)$")


def kv(body: str) -> dict[str, int]:
    return {key: int(value) for key, value in KV_RE.findall(body)}


def parse_evpn_cycles(lines: list[str]) -> dict:
    epochs: list[dict] = []
    receipts: list[dict] = []
    flaps: dict[int, dict] = {}
    lost: list[str] = []
    for raw in lines:
        m = rs.CYCLE_RE.match(raw.strip())
        if not m:
            continue
        ts = rs.parse_ts(m.group("ts"))
        body = m.group("body")
        if body.startswith("evpn_epoch "):
            epochs.append(kv(body))
        elif body.startswith("evpn_receipt "):
            receipts.append(kv(body))
        elif body.startswith("evpn_session_lost "):
            lost.append(body)
        elif body.startswith("evpn_flap "):
            fields = kv(body)
            state = "up" if " up " in body else "down" if " down " in body else None
            n = fields.get("n")
            if n is None or state is None:
                continue
            flap = flaps.setdefault(n, {})
            flap.setdefault("client", fields.get("client"))
            if flap["client"] != fields.get("client"):
                flap["client_mismatch"] = True
            flap[state] = ts
            if state == "up":
                flap["reestablish_ms"] = fields.get("reestablish_ms")
    return {"epochs": epochs, "receipts": receipts, "flaps": flaps, "lost": lost}


def check_epochs(epochs: list[dict], meta: dict) -> dict:
    planned = meta["planned_epochs"]
    expected = meta["expected_per_client"]
    clients = meta["peers"]
    cap_ms = meta["converge_cap_sec"] * 1000
    per_client = 2 * (meta["shift2_per_epoch"] + meta["shift5_per_epoch"])
    defects: list[str] = []
    numbers = [e.get("n") for e in epochs]
    if numbers != list(range(1, planned + 1)):
        defects.append(f"epoch numbers {numbers[:5]}... != 1..{planned} ({len(numbers)} lines)")
    converge_ms = []
    for e in epochs:
        n = e.get("n")
        flap_due = isinstance(n, int) and n % meta["flap_every"] == 0
        reload_due = isinstance(n, int) and n % meta["reload_every"] == 0
        want = {
            "receivers": clients, "expected": expected, "min_live": expected,
            "max_live": expected, "converged": 1, "invalid": 0, "parse_errors": 0,
            "churn_events": per_client * (clients - 1 if flap_due else clients),
        }
        bad = [f"{k}={e.get(k)} expected {v}" for k, v in want.items() if e.get(k) != v]
        if (e.get("flap_client", -1) != -1) != flap_due or e.get("flap_client") == 0:
            bad.append(f"flap_client={e.get('flap_client')} (flap due: {flap_due})")
        if (e.get("reload", 0) != 0) != reload_due:
            bad.append(f"reload={e.get('reload')} (reload due: {reload_due})")
        ms = e.get("converge_ms")
        if ms is None or ms > cap_ms:
            bad.append(f"converge_ms={ms} > cap {cap_ms}")
        else:
            converge_ms.append(ms)
        if bad and len(defects) < 20:
            defects.append(f"epoch {n}: " + "; ".join(bad))
    converge_ms.sort()
    return {
        "value": {
            "epochs": len(epochs), "planned": planned, "expected_per_client": expected,
            "converge_ms_p50": converge_ms[len(converge_ms) // 2] if converge_ms else None,
            "converge_ms_max": converge_ms[-1] if converge_ms else None,
            "defects": defects,
        },
        "pass": bool(epochs) and not defects,
    }


def check_receipt(receipts: list[dict], meta: dict) -> dict:
    if len(receipts) != 1:
        defects = [f"{len(receipts)} evpn_receipt lines (expected exactly 1)"]
    else:
        r = receipts[0]
        want = {
            "clients": meta["peers"], "expected": meta["expected_per_client"],
            "epochs": meta["planned_epochs"], "converged_epochs": meta["planned_epochs"],
            "flaps": meta["planned_flaps"], "reloads": meta["planned_reloads"],
            "receivers": meta["peers"], "min_live": meta["expected_per_client"],
            "max_live": meta["expected_per_client"], "invalid": 0, "parse_errors": 0,
        }
        defects = [f"{k}={r.get(k)} expected {v}" for k, v in want.items() if r.get(k) != v]
    return {"value": {"receipt": receipts[:1], "defects": defects}, "pass": not defects}


def check_flaps(flaps: dict[int, dict], meta: dict) -> dict:
    planned = meta["planned_flaps"]
    bound_ms = meta["reestablish_cap_sec"] * 1000
    defects = []
    if sorted(flaps) != list(range(1, planned + 1)):
        defects.append(f"flap numbers {sorted(flaps)[:5]}... != 1..{planned}")
    for n, flap in sorted(flaps.items()):
        bad = [k for k in ("down", "up") if k not in flap]
        if flap.get("client_mismatch") or not isinstance(flap.get("client"), int) \
                or not 0 < flap["client"] < meta["peers"]:
            bad.append(f"client={flap.get('client')}")
        ms = flap.get("reestablish_ms")
        if ms is None or ms > bound_ms:
            bad.append(f"reestablish_ms={ms} > {bound_ms}")
        if "down" in flap and "up" in flap and flap["up"] < flap["down"]:
            bad.append("up precedes down")
        if bad and len(defects) < 20:
            defects.append(f"flap {n}: " + ", ".join(bad))
    executed = sum(1 for f in flaps.values() if "down" in f and "up" in f)
    return {
        "value": {"executed": executed, "planned": planned, "defects": defects},
        "pass": executed == planned and not defects,
    }


def session_floor(rows: list[dict], flaps: dict[int, dict], meta: dict) -> dict:
    grace = meta["sample_interval_sec"]
    windows = [(f["down"] - grace, f["up"] + grace)
               for f in flaps.values() if "down" in f and "up" in f]
    violations = []
    for row in rows:
        elapsed = float(row["elapsed_sec"])
        established = int(row["established"])
        if elapsed < meta["warmup_sec"] or established == meta["peers"]:
            continue
        stamp = rs.parse_ts(row["timestamp"])
        if established == meta["peers"] - 1 and any(lo <= stamp <= hi for lo, hi in windows):
            continue
        violations.append({"elapsed_sec": elapsed, "established": established})
    return {"value": {"violations": len(violations), "first": violations[:5]},
            "pass": not violations}


def sent_series_monotone(path: Path) -> dict:
    """Per-series bgp_messages_sent_total across the retained snapshots."""
    snapshots: list[dict[str, float]] = []
    error = None
    try:
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            for line in stream:
                if line.startswith("# snapshot "):
                    snapshots.append({})
                    continue
                m = SENT_RE.match(line.rstrip("\n"))
                if m and snapshots:
                    snapshots[-1][m.group("labels")] = float(m.group("value"))
    except (OSError, EOFError, zlib.error, UnicodeDecodeError, ValueError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    decreases, vanished = [], []
    for index, (before, after) in enumerate(zip(snapshots, snapshots[1:]), 1):
        for labels, value in before.items():
            if labels not in after:
                vanished.append({"snapshot": index, "series": labels})
            elif after[labels] < value:
                decreases.append({"snapshot": index, "series": labels,
                                  "from": value, "to": after[labels]})
    series = len(snapshots[-1]) if snapshots else 0
    return {
        "value": {"snapshots": len(snapshots), "series": series,
                  "decreases": decreases[:20], "vanished": vanished[:20],
                  "error": error},
        "pass": (error is None and len(snapshots) >= 2 and series > 0
                 and all(snapshots) and not decreases and not vanished),
    }


def evpn_identity(meta: dict) -> tuple[dict, list[str]]:
    peer = meta.get("management_evpn_peer")
    errors = [] if peer == EVPN_PEER else [
        f"run metadata management_evpn_peer {peer!r} is not client 0 ({EVPN_PEER})"]
    return {"evpn_peer": peer}, errors


def analyze(run_dir: str, rows: list[dict], cycle_lines: list[str], meta: dict,
            management_raw: bytes, min_slope_seconds: float) -> dict:
    cycles = rs.parse_cycles(cycle_lines)
    evpn = parse_evpn_cycles(cycle_lines)
    base = rs.analyze(rows, cycles, {**meta, "planned_trips": 0}, min_slope_seconds)
    gates = {name: base["gates"][name] for name in REUSED_GATES}
    peak = base["peak_rss_mb"]
    gates["rss_peak_mb"] = {
        "value": peak, "limit": EVPN_RSS_PEAK_LIMIT_MB,
        "pass": peak is not None and peak < EVPN_RSS_PEAK_LIMIT_MB,
    }

    issued, complete = len(cycles["reload_issued"]), len(cycles["reload_complete"])
    planned_reloads = meta["planned_reloads"]
    gates["reload_accounting"] = {
        "value": {"issued": issued, "complete": complete, "planned": planned_reloads},
        "pass": planned_reloads > 0 and issued == complete == planned_reloads
        and sorted(cycles["reload_complete"]) == list(range(1, planned_reloads + 1)),
    }
    gates["session_floor"] = session_floor(rows, evpn["flaps"], meta)
    gates["flap_accounting"] = check_flaps(evpn["flaps"], meta)
    flaps = [int(r["flaps_total"]) for r in rows]
    executed = gates["flap_accounting"]["value"]["executed"]
    gates["flap_budget"] = {
        "value": flaps[-1] - flaps[0] if flaps else None,
        "limit": executed,
        "pass": bool(flaps) and flaps[-1] - flaps[0] == executed,
    }
    exceeded = [int(r["max_prefix_exceeded_total"]) for r in rows]
    gates["max_prefix_flat"] = {
        "value": max(exceeded) if exceeded else None, "limit": 0,
        "pass": bool(exceeded) and max(exceeded) == 0,
    }
    gates["evpn_convergence"] = check_epochs(evpn["epochs"], meta)
    gates["evpn_terminal_receipt"] = check_receipt(evpn["receipts"], meta)
    gates["evpn_sessions_not_lost"] = {"value": evpn["lost"][:20], "pass": not evpn["lost"]}
    gates["sent_counters_monotone"] = sent_series_monotone(
        Path(run_dir) / "metrics-snapshots.txt.gz")
    gates["daemon_log"] = analyze_daemon_log(run_dir)
    gates.update(rs.analyze_management_load(
        management_raw, meta,
        gates["daemon_log"]["value"]["first_administrative_shutdown_unix"],
        cycles, EVPN_OPERATIONS, evpn_identity,
    ))
    return {
        "verdict": "pass" if all(g["pass"] for g in gates.values()) else "fail",
        "samples": len(rows),
        "epochs": len(evpn["epochs"]),
        "flaps_executed": executed,
        "reloads_complete": complete,
        "peak_rss_mb": base["peak_rss_mb"],
        "rss_late_slope_per_hour": base["rss_late_slope_per_hour"],
        "intern_late_slope_per_hour": base["intern_late_slope_per_hour"],
        "slope_window_evaluated": base["slope_window_evaluated"],
        "gates": gates,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze the EVPN route-reflector soak")
    parser.add_argument("run_dir")
    parser.add_argument("--output", help="Write verdict JSON to this path")
    parser.add_argument("--min-slope-seconds", type=float, default=3600.0)
    args = parser.parse_args()
    run = Path(args.run_dir)
    try:
        meta = json.loads((run / "run.json").read_text(encoding="utf-8"))
        with (run / "samples.csv").open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            missing = rs.REQUIRED - set(reader.fieldnames or [])
            if missing:
                print("error: missing required columns: " + ", ".join(sorted(missing)),
                      file=sys.stderr)
                return 2
            rows = list(reader)
        cycle_lines = (run / "cycles.log").read_text(encoding="utf-8").splitlines()
        management_raw = (run / "management-plane-load.jsonl").read_bytes()
    except (OSError, ValueError) as e:
        print(f"error reading run dir: {e}", file=sys.stderr)
        return 2
    for key in META_INTS:
        if isinstance(meta.get(key), bool) or not isinstance(meta.get(key), int) \
                or meta[key] <= 0:
            print(f"error: run.json missing positive integer {key}", file=sys.stderr)
            return 2
    if meta.get("management_load_file") != "management-plane-load.jsonl":
        print("error: run.json has invalid management_load_file", file=sys.stderr)
        return 2
    if not rows:
        print("error: samples.csv is empty", file=sys.stderr)
        return 2
    for line, row in enumerate(rows, 2):
        for column in rs.REQUIRED - {"timestamp"}:
            value = rs.safe_float(row.get(column))
            if value is None or value < 0 or (
                    column in rs.COUNTERS and not value.is_integer()):
                print(f"error: row {line}: invalid {column}", file=sys.stderr)
                return 2
        try:
            rs.parse_ts(row["timestamp"])
        except ValueError:
            print(f"error: row {line}: invalid timestamp", file=sys.stderr)
            return 2
    if any(float(a["elapsed_sec"]) >= float(b["elapsed_sec"])
           for a, b in zip(rows, rows[1:])):
        print("error: sample elapsed times must strictly increase", file=sys.stderr)
        return 2

    result = analyze(args.run_dir, rows, cycle_lines, meta, management_raw,
                     args.min_slope_seconds)
    out = json.dumps(result, indent=2)
    print(out)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    return 0 if result["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
