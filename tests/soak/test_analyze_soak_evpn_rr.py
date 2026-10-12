#!/usr/bin/env python3
"""Load-bearing gate contracts for the EVPN route-reflector soak analyzer.

Every scenario-specific gate gets a plausible broken run that must fail."""

import csv
import gzip
import hashlib
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).parent
ANALYZER = HERE / "analyze-soak-evpn-rr.py"
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
FIELDS = [
    "timestamp", "elapsed_sec", "rss_mb", "intern_size", "established",
    "flaps_total", "msgs_sent_total", "max_prefix_exceeded_total",
    "readyz_code", "readyz_ms",
]
OPERATIONS = ("metrics", "neighbor", "evpn_received", "evpn_advertised", "doctor")
PEERS = 12
EXPECTED = (PEERS - 1) * (40 + 10)


def ts(elapsed):
    return (T0 + timedelta(seconds=elapsed)).strftime("%Y-%m-%dT%H:%M:%SZ")


def cline(elapsed, body):
    return f"[{ts(elapsed)}] {body}"


def smoke_meta(**over):
    meta = {
        "peers": PEERS, "type2_per_client": 40, "type5_per_client": 10,
        "shift2_per_epoch": 8, "shift5_per_epoch": 2,
        "expected_per_client": EXPECTED, "soak_seconds": 240, "epoch_sec": 20,
        "churn_sec": 8, "converge_cap_sec": 60, "reestablish_cap_sec": 120,
        "planned_epochs": 12, "flap_every": 4, "reload_every": 3,
        "planned_flaps": 3, "planned_reloads": 4, "sample_interval_sec": 30,
        "warmup_sec": 30, "metrics_snapshot_every": 3,
        "management_load_file": "management-plane-load.jsonl",
        "management_metrics_interval_sec": 30,
        "management_cli_interval_sec": 60,
        "management_doctor_interval_sec": 120,
        "management_timeout_sec": 5,
        "management_evpn_peer": "127.1.0.1",
        "measured_start_monotonic": 1000.1,
        "measured_end_monotonic": 1240.1,
        "engine_finish_release_monotonic": 1240.3,
    }
    meta.update(over)
    return meta


def epoch_line(n, **over):
    flap = n % 4 == 0
    fields = {
        "n": n, "receivers": PEERS, "expected": EXPECTED, "min_live": EXPECTED,
        "max_live": EXPECTED, "converged": 1, "converge_ms": 412,
        "churn_events": 20 * (PEERS - 1 if flap else PEERS),
        "flap_client": 1 + (n // 4 - 1) % (PEERS - 1) if flap else -1,
        "reload": n // 3 if n % 3 == 0 else 0,
        "invalid": 0, "parse_errors": 0, "self_reflected": 0,
    }
    fields.update(over)
    return "evpn_epoch " + " ".join(f"{k}={v}" for k, v in fields.items())


def receipt_line(**over):
    fields = {
        "clients": PEERS, "expected": EXPECTED, "epochs": 12, "converged_epochs": 12,
        "flaps": 3, "reloads": 4, "receivers": PEERS, "min_live": EXPECTED,
        "max_live": EXPECTED, "invalid": 0, "parse_errors": 0, "self_reflected": 0,
    }
    fields.update(over)
    return "evpn_receipt " + " ".join(f"{k}={v}" for k, v in fields.items())


def smoke_cycles(epoch_over=None, drop=(), extra=()):
    """Epoch n starts at 20 (n - 1); flaps every fourth epoch, reloads every third."""
    lines = []
    for n in range(1, 13):
        start = 20 * (n - 1)
        if n % 3 == 0:
            lines.append(cline(start, f"reload {n // 3} issued"))
        if n % 4 == 0:
            k = n // 4
            client = 1 + (k - 1) % (PEERS - 1)
            lines.append(cline(start, f"evpn_flap n={k} client={client} down wall_us=1"))
            lines.append(cline(start + 1, (
                f"evpn_flap n={k} client={client} up wall_us=2 reestablish_ms=900")))
        if n % 3 == 0:
            lines.append(cline(start + 9, f"reload {n // 3} complete"))
        lines.append(cline(start + 10, epoch_line(n, **(epoch_over or {}).get(n, {}))))
    lines.append(cline(241, receipt_line()))
    lines += [cline(242, body) for body in extra]
    return [line for line in lines if not any(d in line for d in drop)]


def smoke_rows():
    rows = []
    for elapsed in range(0, 241, 30):
        flaps = sum(1 for k in range(1, 4) if 20 * (4 * k - 1) <= elapsed)
        rows.append({
            "timestamp": ts(elapsed), "elapsed_sec": elapsed, "rss_mb": 100.0,
            "intern_size": 50, "established": PEERS, "flaps_total": flaps,
            "msgs_sent_total": 1000 + elapsed * 50, "max_prefix_exceeded_total": 0,
            "readyz_code": 200, "readyz_ms": 5.0,
        })
    return rows


def snapshots(values_by_snapshot):
    """One gzip member per snapshot, as the runner appends them."""
    blob = b""
    for index, values in enumerate(values_by_snapshot):
        body = f"# snapshot {ts(index * 90)} elapsed_sec={index * 90}\n"
        body += "# TYPE bgp_messages_sent_total counter\n"
        for peer, value in values.items():
            body += f'bgp_messages_sent_total{{peer="{peer}",type="update"}} {value}\n'
        body += "bgp_session_flaps_total 0\n"
        blob += gzip.compress(body.encode())
    return blob


CLEAN_SNAPSHOTS = snapshots([
    {"127.1.0.1": 10, "127.1.0.2": 10},
    {"127.1.0.1": 20, "127.1.0.2": 15},
    {"127.1.0.1": 30, "127.1.0.2": 15},
])


def management_jsonl(meta, *, failure=None, peer=None):
    start = meta["measured_start_monotonic"] - 0.1
    end = meta["measured_end_monotonic"] + 0.1
    intervals = {
        op: meta["management_metrics_interval_sec"] if op == "metrics"
        else meta["management_doctor_interval_sec"] if op == "doctor"
        else meta["management_cli_interval_sec"]
        for op in OPERATIONS
    }
    identity = {"evpn_peer": peer or meta["management_evpn_peer"]}
    records = [{
        "record": "start", "started_monotonic": start, "operations": list(OPERATIONS),
        "interval_seconds": intervals, "timeout_seconds": meta["management_timeout_sec"],
        "peer_count": meta["peers"], **identity,
    }]
    counts = {}
    digest = hashlib.sha256(b"{}").hexdigest()
    for op in OPERATIONS:
        count = int((end - start - 0.1) // intervals[op]) + 1
        counts[op] = count
        for index in range(count):
            due = start + index * intervals[op]
            records.append({
                "record": "operation", "scheduled_monotonic": due,
                "started_monotonic": due + 0.001, "completed_monotonic": due + 0.002,
                "operation": op, "duration_ms": 1.0,
                "exit": 200 if op == "metrics" else 0,
                "result": failure[1] if failure and failure[0] == op else "ok",
                "bytes": 2, "sha256": digest,
            })
    records.append({
        "record": "summary", "started_monotonic": start,
        "stop_requested_monotonic": end - 0.05, "completed_monotonic": end,
        "completed_unix": T0.timestamp() + end, "operation": "summary",
        "duration_ms": (end - start) * 1000, "exit": 0, "result": "clean_sigterm",
        "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest(), "signal": "SIGTERM",
        "scheduled": counts, "completed": counts,
        "missed": {op: 0 for op in OPERATIONS}, "interval_seconds": intervals,
        "timeout_seconds": meta["management_timeout_sec"], "peer_count": meta["peers"],
        **identity,
    })
    return b"".join((json.dumps(r) + "\n").encode() for r in records)


def daemon_record(message, elapsed, **fields):
    return (json.dumps({
        "timestamp": ts(elapsed), "level": "INFO", "target": "rustbgpd",
        "fields": {"message": message, **fields},
    }) + "\n").encode()


CLEAN_DAEMON = daemon_record("daemon ready", 70) + daemon_record(
    "BGP NOTIFICATION", 200000, direction="received", code=6, subcode=2)


def run_analyzer(rows=None, cycles=None, meta=None, management=None,
                 snapshots_blob=CLEAN_SNAPSHOTS, daemon=CLEAN_DAEMON):
    meta = smoke_meta() if meta is None else meta
    with tempfile.TemporaryDirectory() as tmp:
        run_dir = Path(tmp)
        with (run_dir / "samples.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(smoke_rows() if rows is None else rows)
        (run_dir / "cycles.log").write_text(
            "\n".join(smoke_cycles() if cycles is None else cycles) + "\n")
        (run_dir / "run.json").write_text(json.dumps(meta))
        (run_dir / "management-plane-load.jsonl").write_bytes(
            management_jsonl(meta) if management is None else management)
        if snapshots_blob is not None:
            (run_dir / "metrics-snapshots.txt.gz").write_bytes(snapshots_blob)
        (run_dir / "rustbgpd.log").write_bytes(daemon)
        result = subprocess.run(
            ["python3", str(ANALYZER), str(run_dir)],
            text=True, capture_output=True, check=False,
        )
    payload = json.loads(result.stdout) if result.stdout else None
    return result, payload


class EvpnRrAnalyzerContracts(unittest.TestCase):
    def assert_only_failure(self, gate, **kwargs):
        result, payload = run_analyzer(**kwargs)
        self.assertEqual(result.returncode, 1, result.stderr)
        failed = sorted(k for k, g in payload["gates"].items() if not g["pass"])
        self.assertEqual(failed, [gate], json.dumps(payload["gates"], indent=1))
        return payload["gates"][gate]

    def test_clean_smoke_run_passes_every_gate(self):
        result, payload = run_analyzer()
        self.assertEqual(result.returncode, 0, payload)
        self.assertEqual(set(payload["gates"]), {
            "min_samples", "msgs_sent_monotone", "readyz", "rss_peak_mb",
            "rss_late_slope_per_hour", "intern_late_slope_per_hour", "no_abort",
            "reload_accounting", "session_floor", "flap_accounting", "flap_budget",
            "max_prefix_flat", "evpn_convergence", "evpn_terminal_receipt",
            "evpn_sessions_not_lost", "sent_counters_monotone", "daemon_log",
            "management_evidence", "management_lifetime", "management_operations",
            "management_completion", "management_cadence", "management_failures",
            "management_doctor",
        })
        self.assertTrue(all(g["pass"] for g in payload["gates"].values()))

    def test_session_dip_outside_flap_window_fails(self):
        rows = smoke_rows()
        rows[6]["established"] = PEERS - 1  # elapsed 180: no flap window covers it
        self.assert_only_failure("session_floor", rows=rows)

    def test_two_clients_down_inside_flap_window_fails(self):
        rows = smoke_rows()
        rows[2]["established"] = PEERS - 2  # elapsed 60: inside flap 1's window
        self.assert_only_failure("session_floor", rows=rows)

    def test_one_client_down_inside_flap_window_passes(self):
        rows = smoke_rows()
        rows[2]["established"] = PEERS - 1
        result, payload = run_analyzer(rows=rows)
        self.assertEqual(result.returncode, 0, payload["gates"]["session_floor"])

    def test_reload_without_completion_fails(self):
        self.assert_only_failure("reload_accounting",
                                 cycles=smoke_cycles(drop=("reload 2 complete",)))

    def test_flap_that_never_came_back_fails(self):
        result, payload = run_analyzer(cycles=smoke_cycles(drop=("n=3 client=3 up",)))
        self.assertEqual(result.returncode, 1)
        gate = payload["gates"]["flap_accounting"]
        self.assertFalse(gate["pass"])
        self.assertEqual(gate["value"]["executed"], 2)
        # The daemon still counted three flaps against two completed ones.
        self.assertFalse(payload["gates"]["flap_budget"]["pass"])

    def test_flap_of_client_zero_fails(self):
        cycles = [line.replace("n=1 client=1 ", "n=1 client=0 ") for line in smoke_cycles()]
        self.assert_only_failure("flap_accounting", cycles=cycles)

    def test_unplanned_daemon_flap_breaks_exact_budget(self):
        rows = smoke_rows()
        for row in rows[4:]:
            row["flaps_total"] += 1
        self.assert_only_failure("flap_budget", rows=rows)

    def test_rss_peak_uses_the_scenario_ceiling(self):
        rows = smoke_rows()
        rows[4]["rss_mb"] = 3500.0  # above scenario 10's 3072 MB, below 4096
        result, payload = run_analyzer(rows=rows)
        self.assertEqual(result.returncode, 0, payload["gates"]["rss_peak_mb"])
        rows[4]["rss_mb"] = 4096.0
        gate = self.assert_only_failure("rss_peak_mb", rows=rows)
        self.assertEqual(gate["limit"], 4096.0)

    def test_spurious_max_prefix_latch_fails(self):
        rows = smoke_rows()
        rows[5]["max_prefix_exceeded_total"] = 1
        self.assert_only_failure("max_prefix_flat", rows=rows)

    def test_one_client_missing_one_reflected_route_fails(self):
        cycles = smoke_cycles(epoch_over={7: {"min_live": EXPECTED - 1, "converged": 0}})
        gate = self.assert_only_failure("evpn_convergence", cycles=cycles)
        self.assertIn("epoch 7", gate["value"]["defects"][0])

    def test_reflected_foreign_route_fails_even_when_counts_match(self):
        cycles = smoke_cycles(epoch_over={4: {"invalid": 1}})
        self.assert_only_failure("evpn_convergence", cycles=cycles)

    def test_self_reflected_route_fails_even_when_counts_match(self):
        cycles = smoke_cycles(epoch_over={6: {"self_reflected": 1}})
        gate = self.assert_only_failure("evpn_convergence", cycles=cycles)
        self.assertIn("self_reflected=1", gate["value"]["defects"][0])
        receipt = [line.replace(" self_reflected=0", " self_reflected=1")
                   if "evpn_receipt" in line else line for line in smoke_cycles()]
        self.assert_only_failure("evpn_terminal_receipt", cycles=receipt)

    def test_missing_epoch_line_fails(self):
        cycles = smoke_cycles(drop=("evpn_epoch n=5 ",))
        self.assert_only_failure("evpn_convergence", cycles=cycles)

    def test_convergence_over_cap_fails(self):
        cycles = smoke_cycles(epoch_over={2: {"converge_ms": 60001}})
        self.assert_only_failure("evpn_convergence", cycles=cycles)

    def test_skipped_churn_fails(self):
        cycles = smoke_cycles(epoch_over={5: {"churn_events": 0}})
        self.assert_only_failure("evpn_convergence", cycles=cycles)

    def test_missing_terminal_receipt_fails(self):
        self.assert_only_failure("evpn_terminal_receipt",
                                 cycles=smoke_cycles(drop=("evpn_receipt",)))

    def test_lost_session_fails(self):
        cycles = smoke_cycles(extra=("evpn_session_lost client=4 wall_us=9",))
        self.assert_only_failure("evpn_sessions_not_lost", cycles=cycles)

    def test_per_peer_sent_counter_reset_fails_while_aggregate_grows(self):
        blob = snapshots([
            {"127.1.0.1": 10, "127.1.0.2": 10},
            {"127.1.0.1": 40, "127.1.0.2": 3},
        ])
        gate = self.assert_only_failure("sent_counters_monotone", snapshots_blob=blob)
        self.assertEqual(gate["value"]["decreases"][0]["to"], 3.0)

    def test_vanished_sent_series_fails(self):
        blob = snapshots([{"127.1.0.1": 10, "127.1.0.2": 10}, {"127.1.0.1": 20}])
        self.assert_only_failure("sent_counters_monotone", snapshots_blob=blob)

    def test_missing_or_single_snapshot_evidence_fails_closed(self):
        for blob in (None, snapshots([{"127.1.0.1": 1}]), b"not gzip",
                     snapshots([{}, {}])):
            with self.subTest(blob=blob if blob is None else len(blob)):
                self.assert_only_failure("sent_counters_monotone", snapshots_blob=blob)

    def test_management_identity_must_be_client_zero(self):
        meta = smoke_meta(management_evpn_peer="127.1.0.2")
        result, payload = run_analyzer(meta=meta)
        self.assertEqual(result.returncode, 1)
        self.assertIn("is not client 0",
                      payload["gates"]["management_evidence"]["value"]["errors"][0])

    def test_failed_evpn_view_read_fails(self):
        meta = smoke_meta()
        management = management_jsonl(meta, failure=("evpn_advertised", "route"))
        self.assert_only_failure("management_failures", management=management)

    def test_unicast_operation_set_is_rejected(self):
        meta = smoke_meta()
        raw = management_jsonl(meta).replace(b"evpn_received", b"rib_prefix")
        result, payload = run_analyzer(management=raw)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["management_evidence"]["pass"])

    def test_missing_metadata_is_an_input_error(self):
        for key in ("planned_epochs", "expected_per_client", "planned_flaps"):
            with self.subTest(key=key):
                meta = smoke_meta()
                del meta[key]
                result, _ = run_analyzer(meta=meta)
                self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
