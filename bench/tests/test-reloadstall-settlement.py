#!/usr/bin/env python3
"""Exercise SIGHUP settlement with tiny real daemon/reloadstall sessions.

The last case injects metrics: pending until the engine observes receiver
barriers, then rejected_no_effect. It tests harness sequencing, NOT a real
runtime rollback. Logs and generated inputs are retained in --artifact-dir.
"""

import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

REPO = Path(__file__).resolve().parents[2]
BARRIER = "reload 1 receiver_barriers_complete awaiting_daemon_settlement"
ATTEMPTS = 3


class PortCollision(Exception):
    """The daemon exited at startup because a probed port was taken meanwhile."""


def wait_ready(process, address, log):
    for _ in range(200):
        if process.poll() is not None and "Address already in use" in log.read_text():
            raise PortCollision(f"daemon could not bind a probed port; see {log}")
        assert process.poll() is None, "daemon exited during startup; see daemon.log"
        try:
            with urllib.request.urlopen(f"http://{address}/readyz", timeout=0.5) as reply:
                if reply.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.1)
    raise AssertionError("daemon readiness deadline; see daemon.log")


def run_case(args, name, **kind):
    # Ports are probed by bind-and-close, so another socket can take one before the
    # daemon binds it. Only that startup collision is retried, with fresh ports.
    for attempt in range(1, ATTEMPTS + 1):
        try:
            return run_attempt(args, name, attempt, **kind)
        except PortCollision as collision:
            print(f"{name}: attempt {attempt}/{ATTEMPTS}: {collision}", flush=True)
    raise AssertionError(f"{name}: probed ports were taken on all {ATTEMPTS} attempts")


def run_attempt(args, name, attempt, *, dualstack=False, rejected=False, injected=False):
    dest = args.artifact_dir / name / f"attempt-{attempt}"
    dest.mkdir(parents=True)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("GEN_", "RELOADSTALL_"))}
    env.update(GEN_DUALSTACK=str(int(dualstack)), GEN_FILTER_COUNT="4" if dualstack else "0")
    # Keep the generated UDS path below sun_path's limit, even in deep CI checkouts.
    with tempfile.TemporaryDirectory(prefix="rls-", dir="/tmp") as temporary:
        scenario = Path(temporary)
        with socket.socket() as bgp, socket.socket() as metrics:
            bgp.bind(("127.0.0.1", 0))
            metrics.bind(("127.0.0.1", 0))
            bgp_port = str(bgp.getsockname()[1])
            metrics_address = f"127.0.0.1:{metrics.getsockname()[1]}"
        with (dest / "generator.log").open("w") as log:
            subprocess.run([sys.executable, str(REPO / "bench/scale/reloadstall/gen-scenario.py"),
                            "12", str(scenario), bgp_port, "12"], env=env, check=True,
                           stdout=log, stderr=subprocess.STDOUT)
        config = scenario / "config.toml"
        rendered = config.read_text().replace("127.0.0.1:9179", metrics_address)
        # One explicit IPv4 endpoint binds atomically: a taken port stops the daemon at
        # startup instead of leaving it bound on [::] only, unreachable to IPv4 stubs.
        pinned = rendered.replace(f"\nlisten_port = {bgp_port}\n",
                                  f'\nlisten_port = {bgp_port}\nlisten_addresses = ["127.0.0.1"]\n')
        assert pinned != rendered, "generated config has no listen_port line to pin"
        config.write_text(pinned)
        with (dest / "check.log").open("w") as log:
            subprocess.run([str(args.daemon), "--check", str(config)], check=True,
                           stdout=log, stderr=subprocess.STDOUT, timeout=30)
        with (dest / "daemon.log").open("w") as daemon_log:
            daemon = subprocess.Popen([str(args.daemon), str(config)], stdout=daemon_log,
                                      stderr=subprocess.STDOUT)
            fixture = None
            try:
                wait_ready(daemon, metrics_address, dest / "daemon.log")
                env.update(RELOADSTALL_DUALSTACK=str(int(dualstack)),
                           RELOADSTALL_FILTER_COUNT="4" if dualstack else "0",
                           RELOADSTALL_CYCLE_QUIESCE_SECS="1",
                           RELOADSTALL_RELOAD_METRICS_ADDR=metrics_address)
                if rejected:
                    env["RELOADSTALL_STAGE_CMD"] = shlex.join([
                        sys.executable, "-c",
                        'from pathlib import Path; import sys; '
                        'Path(sys.argv[1]).write_text("invalid policy input\\n")',
                        str(scenario / "member.rpol")])
                engine_log = dest / "reloadstall.log"
                engine_log.touch()
                if injected:
                    class MetricsFixture(http.server.BaseHTTPRequestHandler):
                        def log_message(self, *unused):
                            pass

                        def do_GET(self):
                            # Synchronize on the actual barrier, never an elapsed-time guess.
                            barrier_seen = BARRIER in engine_log.read_text()
                            outcomes = dict(complete=0, known_partial=0,
                                            rejected_no_effect=int(barrier_seen),
                                            ignored_in_flight=0, task_failed=0)
                            body = "".join(
                                f'bgp_sighup_reload_outcomes_total{{outcome="{key}"}} {value}\n'
                                for key, value in outcomes.items()).encode()
                            with (dest / "injected-metrics.jsonl").open("a") as log:
                                log.write(json.dumps({"receiver_barriers_complete": barrier_seen,
                                                      "outcomes": outcomes}) + "\n")
                            self.send_response(200)
                            self.send_header("Content-Length", str(len(body)))
                            self.end_headers()
                            self.wfile.write(body)

                    fixture = http.server.HTTPServer(("127.0.0.1", 0), MetricsFixture)
                    thread = threading.Thread(target=fixture.serve_forever)
                    thread.start()
                    env["RELOADSTALL_RELOAD_METRICS_ADDR"] = f"127.0.0.1:{fixture.server_port}"
                with engine_log.open("w") as log:
                    result = subprocess.run([
                        str(args.harness), "12", "600", bgp_port, str(daemon.pid),
                        str(scenario / "member.rpol"), str(scenario / "gen-a.rpol"),
                        str(scenario / "gen-b.rpol"), "2", "1", "12"], env=env,
                        # Above the engine's 120 s connect window, so its own error surfaces.
                        stdout=log, stderr=subprocess.STDOUT, timeout=180)
                (dest / "engine.exit").write_text(f"{result.returncode}\n")
                text = engine_log.read_text()
                if rejected or injected:
                    assert result.returncode == 1, text
                    assert "reload 1 daemon SIGHUP outcome rejected_no_effect" in text, text
                    assert "reloadstall_csv," not in text, text
                    assert "reload 2 " not in text, text
                    assert (scenario / "member.rpol").read_bytes() != (
                        scenario / "gen-a.rpol").read_bytes(), "next A policy was staged"
                    if rejected:
                        assert "SIGHUP reload rejected without runtime effect" in (
                            dest / "daemon.log").read_text()
                    if injected:
                        assert BARRIER in text, text
                        assert (scenario / "member.rpol").read_bytes() == (
                            scenario / "gen-b.rpol").read_bytes()
                        samples = [json.loads(line) for line in
                                   (dest / "injected-metrics.jsonl").read_text().splitlines()]
                        assert not samples[0]["receiver_barriers_complete"], samples
                        assert samples[-1]["receiver_barriers_complete"], samples
                else:
                    assert result.returncode == 0, text
                    for reload in (1, 2):
                        assert text.index(f"reload {reload} daemon_applied") < text.index(
                            f"reloadstall_csv,{reload},"), text
                # Use the runner's actual marker translation to check the soak receipt too.
                shell = ('source "$1"; CYCLES_LOG="$2"; '
                         'while IFS= read -r line; do handle_line "$line"; done < "$3"')
                with (dest / "runner.log").open("w") as log:
                    runner = subprocess.run([
                        "bash", "-c", shell, "settlement-test",
                        str(REPO / "tests/soak/run-soak-rs-flagship.sh"),
                        str(dest / "cycles.log"), str(engine_log)],
                        stdout=log, stderr=subprocess.STDOUT, timeout=15)
                cycles = (dest / "cycles.log").read_text()
                assert ("reload 1 complete" in cycles) == (not rejected and not injected), cycles
                assert runner.returncode == (1 if rejected or injected else 0), cycles
                if rejected or injected:
                    assert "ABORT: reload 1 failed: daemon SIGHUP outcome rejected_no_effect" in cycles
                summary = {"case": name, "attempts": attempt,
                           "engine_exit": result.returncode, "assertions": "pass",
                           "metrics_injected_not_runtime_rollback": injected}
                (dest / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
                print(json.dumps(summary), flush=True)
            finally:
                if fixture:
                    fixture.shutdown()
                    thread.join()
                    fixture.server_close()
                daemon.terminate()
                try:
                    daemon.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()
                (dest / "daemon.exit").write_text(f"{daemon.returncode}\n")
                for path in [config, *scenario.glob("*.rpol")]:
                    shutil.copy2(path, dest / path.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--harness", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True,
                        help="new directory; retained on success and failure")
    args = parser.parse_args()
    args.daemon = args.daemon.resolve(strict=True)
    args.harness = args.harness.resolve(strict=True)
    args.artifact_dir = args.artifact_dir.resolve()
    os.umask(0o077)
    args.artifact_dir.mkdir(parents=True)
    print(f"artifacts: {args.artifact_dir}", flush=True)
    with (args.artifact_dir / "binaries.sha256").open("w") as log:
        for binary in (args.daemon, args.harness):
            with binary.open("rb") as source:
                log.write(f"{hashlib.file_digest(source, 'sha256').hexdigest()}  {binary}\n")
    run_case(args, "native-success")
    run_case(args, "dualstack-filter-success", dualstack=True)
    run_case(args, "native-rejection", rejected=True)
    run_case(args, "receiver-complete-then-rejected", injected=True)


if __name__ == "__main__":
    main()
