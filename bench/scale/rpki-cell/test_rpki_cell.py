#!/usr/bin/env python3
"""Tests for rpki_cell.py: the VRP fixture, the VRP-loaded gate, and the
summary's refusal of incomplete cells."""

from __future__ import annotations

import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rpki_cell  # noqa: E402

CHUNK = 'bgp_rib_actor_work_duration_seconds_{}{{work_unit="route_chunk"}} {}'


def metrics(chunk_sum: float, chunk_count: int, vrps: int | None) -> str:
    lines = ["# HELP bgp_rpki_vrp_count Number of RPKI VRP entries by address family",
             CHUNK.format("sum", chunk_sum), CHUNK.format("count", chunk_count)]
    if vrps is not None:
        lines += [f'bgp_rpki_vrp_count{{af="ipv4"}} {vrps}', 'bgp_rpki_vrp_count{af="ipv6"} 0']
    return "\n".join(lines) + "\n"


def write_cell(out: Path, arm: str, run: int, position: int, chunk: float, *,
               vrps_after: int | None = 100, harness_rc: str = "0", after: str | None = None) -> Path:
    cell = out / "cells" / f"{arm}-r{run}"
    cell.mkdir(parents=True)
    (cell / "metrics-before.prom").write_text(metrics(0.01, 1, 100))
    (cell / "metrics-after.prom").write_text(after if after is not None else metrics(0.01 + chunk, 11, vrps_after))
    (cell / "cell.env").write_text("\n".join([
        f"arm={arm}", f"run={run}", f"position={position}", "vrps_expected=100",
        "cpu_ticks_start=100", "cpu_ticks_end=350", "clk_tck=100",
        "t_start=1000.0", "t_ready=1002.5", f"harness_rc={harness_rc}"]) + "\n")
    return cell


def campaign(out: Path) -> None:
    for run, (first, second) in enumerate((("base", "head"), ("head", "base"), ("base", "head")), 1):
        write_cell(out, first, run, 1, {"base": 0.42, "head": 0.39}[first] + run / 1000)
        write_cell(out, second, run, 2, {"base": 0.42, "head": 0.39}[second] + run / 1000)


class VrpFixture(unittest.TestCase):
    def assert_owned(self, n_peers: int, total: int, vrps: int) -> list[dict]:
        roas = rpki_cell.roas(n_peers, total, vrps)
        self.assertEqual(len(roas), vrps)
        # reloadstall member_slice: the first total % n_peers members own q + 1.
        q, r = divmod(total, n_peers)
        by_prefix = {row["prefix"]: row["asn"] for row in roas}
        for idx in range(total):
            owner = idx // (q + 1) if idx < r * (q + 1) else r + (idx - r * (q + 1)) // q
            prefix = f"{20 + (idx >> 16)}.{(idx >> 8) & 0xFF}.{idx & 0xFF}.0/24"
            self.assertEqual(by_prefix.get(prefix), f"AS{64512 + owner}", prefix)
        self.assertEqual(len(by_prefix), vrps, "padding must not duplicate or cover announced prefixes")
        self.assertTrue(all(row["prefix"].startswith(("100.", "101.")) for row in roas[total:]))
        return roas

    def test_every_announced_prefix_is_valid_for_its_owner(self):
        self.assert_owned(10, 2000, 2500)

    def test_non_divisible_shape_follows_reloadstall_slices(self):
        roas = self.assert_owned(9, 50, 80)
        # 50 = 9 x 5 + 5: members 0-4 own six indexes, members 5-8 own five.
        self.assertEqual(roas[5]["asn"], "AS64512")
        self.assertEqual(roas[6]["asn"], "AS64513")
        self.assertEqual(roas[29]["asn"], "AS64516")
        self.assertEqual(roas[30]["asn"], "AS64517")
        self.assertEqual(roas[49]["asn"], "AS64520")

    def test_check_is_arithmetic_only(self):
        rpki_cell.check_shape(700, 400400, 500000)
        with self.assertRaises(ValueError):
            rpki_cell.check_shape(10, 50, 49)
        with self.assertRaises(ValueError):
            rpki_cell.check_shape(7, 49, 80)
        with self.assertRaises(ValueError):
            rpki_cell.check_shape(9, 50, 80)

    def test_default_shape_crosses_the_second_octet_boundary(self):
        roas = rpki_cell.roas(700, 400400, 500000)
        self.assertEqual(roas[400399], {"asn": "AS65211", "prefix": "26.28.15.0/24",
                                        "maxLength": 24, "ta": "bench"})

    def test_too_few_vrps_is_refused(self):
        with self.assertRaises(ValueError):
            rpki_cell.roas(9, 50, 49)

    def test_output_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp, "a.json"), Path(tmp, "b.json")
            rpki_cell.write_vrps(10, 2000, 5000, str(a))
            rpki_cell.write_vrps(10, 2000, 5000, str(b))
            self.assertEqual(a.read_bytes(), b.read_bytes())
            self.assertEqual(len(json.loads(a.read_text())["roas"]), 5000)


class VrpGate(unittest.TestCase):
    """The gate that must stop a cell before any route when VRPs are missing."""

    def serve(self, body: str | None) -> str:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if body is None:
                    self.send_error(503)
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}/metrics"

    def serve_slow(self, first: str, later: str, first_delay: float, drip: float) -> str:
        """First request: `first` after `first_delay`; later ones: `later`, its
        headers at once and its body in four chunks `drip` seconds apart."""
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                seen.append(1)
                body = (first if len(seen) == 1 else later).encode()
                time.sleep(first_delay if len(seen) == 1 else 0)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.flush()
                step = len(body) // 4 + 1
                for i in range(0, len(body), step):
                    if len(seen) > 1:
                        time.sleep(drip)
                    self.wfile.write(body[i:i + step])
                    self.wfile.flush()

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}/metrics"

    def gate(self, url: str, want: int, pid: int = 0, timeout: str = "1.2") -> subprocess.CompletedProcess:
        script = Path(rpki_cell.__file__)
        return subprocess.run([sys.executable, str(script), "wait-vrps", url, str(want), timeout,
                               str(pid or os.getpid())],
                              capture_output=True, text=True, timeout=30)

    def test_full_table_passes(self):
        result = self.gate(self.serve(metrics(0, 0, 500)), 500)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("vrps_loaded=500", result.stdout)

    def test_partial_table_fails(self):
        result = self.gate(self.serve(metrics(0, 0, 499)), 500)
        self.assertEqual(result.returncode, 1)
        self.assertIn("VRP gate failed: 499 of 500", result.stderr)

    def test_no_vrp_series_fails(self):
        result = self.gate(self.serve(metrics(0, 0, None)), 500)
        self.assertEqual(result.returncode, 1)
        self.assertIn("None of 500", result.stderr)

    def test_closed_metrics_port_fails(self):
        result = self.gate(self.serve(None), 1)
        self.assertEqual(result.returncode, 1)

    def test_dead_daemon_fails_before_timeout(self):
        child = subprocess.Popen(["true"])
        child.wait()
        result = self.gate(self.serve(metrics(0, 0, 500)), 500, pid=child.pid)
        self.assertEqual(result.returncode, 1)
        self.assertIn("exited", result.stderr)


    def test_table_completed_after_the_deadline_fails(self):
        # The second scrape starts inside the budget but its body finishes
        # after it; each chunk arrives within the per-request socket timeout.
        url = self.serve_slow(metrics(0, 0, 499), metrics(0, 0, 500), first_delay=0, drip=0.3)
        result = self.gate(url, 500, timeout="1.0")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("499 of 500", result.stderr)

    def test_slow_scrape_is_bounded_by_the_remaining_budget(self):
        url = self.serve_slow(metrics(0, 0, 500), metrics(0, 0, 500), first_delay=4, drip=0)
        started = time.monotonic()
        result = self.gate(url, 500, timeout="1.0")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertLess(time.monotonic() - started, 3.0)


class Summary(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.out)

    def summarize(self) -> int:
        return rpki_cell.summarize(self.out)

    def test_complete_campaign(self):
        campaign(self.out)
        self.assertEqual(self.summarize(), 0)
        rows = (self.out / "cells.csv").read_text().splitlines()
        self.assertEqual(len(rows), 7)
        self.assertEqual(rows[1], "base,1,1,100,100,0.421,10,2.5,2.5,0")
        summary = (self.out / "summary.txt").read_text()
        self.assertIn("route_chunk_sum_s: base=0.422 [0.421-0.423] head=0.392 [0.391-0.393] delta=-7.1%", summary)
        self.assertNotIn("INVALID", summary)

    def test_lost_vrp_table_is_invalid(self):
        campaign(self.out)
        (self.out / "cells" / "head-r2" / "metrics-after.prom").write_text(metrics(0.4, 11, 99))
        self.assertEqual(self.summarize(), 1)
        self.assertIn("INVALID head-r2: 99 of 100 VRPs", (self.out / "summary.txt").read_text())

    def test_failed_harness_is_invalid(self):
        campaign(self.out)
        env = self.out / "cells" / "base-r3" / "cell.env"
        env.write_text(env.read_text().replace("harness_rc=0", "harness_rc=1"))
        self.assertEqual(self.summarize(), 1)

    def test_missing_route_chunk_series_is_invalid(self):
        campaign(self.out)
        text = metrics(0.4, 11, 100)
        (self.out / "cells" / "base-r1" / "metrics-after.prom").write_text(
            "\n".join(line for line in text.splitlines() if "route_chunk" not in line))
        self.assertEqual(self.summarize(), 1)

    def test_unequal_runs_are_invalid(self):
        campaign(self.out)
        (self.out / "cells" / "head-r3" / "cell.env").unlink()
        self.assertEqual(self.summarize(), 1)
        self.assertIn("unequal", (self.out / "summary.txt").read_text())


if __name__ == "__main__":
    unittest.main()
