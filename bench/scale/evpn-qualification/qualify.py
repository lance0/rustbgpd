#!/usr/bin/env python3
"""Paired real-daemon, non-RTC EVPN memory qualification.

The exported candidate alone invokes the bench ownership constructor. Both
exports have the same private observer. Neither patch changes normal builds.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPEC = importlib.util.spec_from_file_location(
    "recovery_mass_dirty", HERE.parent / "reloadstall/recovery_mass_dirty.py")
COMMON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMMON)
require, digest, write_json = COMMON.require, COMMON.digest, COMMON.write_json
CAUSES = ("peer_limit", "daemon_limit", "allocation_failure", "capture_unavailable", "admission_invariant")
SHAPES = ((75, 500), (150, 250), (100, 1000), (200, 500))
SCHEDULE = ("candidate", "private") * 3
MAX_SLOPE_BYTES = 10
RECOVERY_BARS = {"clients": 150, "routes_per_client": 250, "dirty_members": 150,
                 "consecutive_dirty_samples": 2, "sample_hz": 20,
                 "readiness_seconds": .2, "convergence_seconds": 60,
                 "candidate_median_ratio": 1.03, "max_budget_fraction": .8,
                 "max_churn_rounds": 32, "overlap_source_spacing_ms": 50}
DAEMON_BYTES = 12 * 1024 ** 3
BUILD_CPUS = ",".join(str(cpu) for cpu in sorted(os.sched_getaffinity(0)))
SCOPE = ("initial-load whole-daemon memory and ownership only; not mass-dirty, "
         "fleet regroup, section F wire parity, RTC, soak or production activation")


class AcceptanceFailure(ValueError):
    """A valid observation breached a predeclared behavior or resource bar."""


def accept(condition, message):
    if not condition:
        raise AcceptanceFailure(message)


def manifest_for(output):
    row = json.loads((output / "campaign.json").read_text())
    require(row["schema"] == "rustbgpd.evpn-memory.v1"
            and re.fullmatch(r"[0-9a-f]{40}", row["head"])
            and row["shapes"] == [list(shape) for shape in SHAPES]
            and row["schedule"] == list(SCHEDULE)
            and row["settle_seconds"] == 45 and row["daemon_bytes"] == DAEMON_BYTES
            and row["max_slope_bytes_per_delivery"] == MAX_SLOPE_BYTES,
            "campaign shape, source or predeclared bars changed")
    require(digest(output / "source.tar") == row["source_sha256"], "source archive changed")
    return row


def timing_window(start, end):
    if start is None and end is None:
        return None
    require(start is not None and end is not None, "both authorized window endpoints are required")
    parsed = [datetime.fromisoformat(value.replace("Z", "+00:00")) for value in (start, end)]
    require(all(value.tzinfo is not None and value.utcoffset().total_seconds() == 0 for value in parsed)
            and parsed[0] < parsed[1], "authorized window must be an increasing UTC interval")
    return {"start": parsed[0].isoformat(), "end": parsed[1].isoformat()}


def require_timing_window(manifest, now=None):
    window = manifest.get("timing_window")
    require(window is not None and timing_window(window["start"], window["end"]) == window,
            "measured cells require an explicitly authorized UTC window")
    now = now or datetime.now(timezone.utc)
    require(datetime.fromisoformat(window["start"]) <= now < datetime.fromisoformat(window["end"]),
            "cell start is outside the authorized UTC window")


def cell_gate(output, manifest, leg, correctness):
    if correctness:
        return
    require_timing_window(manifest)
    script = output / "sources/candidate/bench/scale/host-quiet.sh"
    with (leg / "quiet-host.log").open("x") as log:
        status = subprocess.run(["bash", "-c", 'source "$1"; wait_for_rustbgpd_quiet_host "$2"',
                                 "evpn-quiet", str(script), str(leg / "quiet-host.tsv")],
                                stdout=log, stderr=subprocess.STDOUT).returncode
    (leg / "quiet-host.exit").write_text(f"{status}\n")
    require(status == 0, "per-cell quiet-host gate failed")
    require_timing_window(manifest)


def cleanup_cell(record, leg, fixture, driver, daemon, controller=None):
    """Attempt every cleanup and retain a receipt even if another one fails."""
    errors = []
    actions = [("driver", lambda: COMMON.stop_owned(driver)),
               ("daemon", lambda: COMMON.stop_owned(daemon))]
    if controller is not None:
        actions.insert(0, ("controller", controller.close))
    for name, action in actions:
        try:
            action()
        except Exception as error:
            errors.append(f"{name}: {error}")
    try:
        COMMON.copy_fixture(fixture, leg / "fixture")
        shutil.rmtree(fixture)
    except Exception as error:
        errors.append(f"fixture: {error}")
        record["retained_fixture"] = str(fixture)
    if errors:
        record["status"] = "INVALID"
        record["cleanup_errors"] = errors
        record.setdefault("error", "owned-resource cleanup failed")
    write_json(leg / "result.json", record)
    if errors:
        raise ValueError("owned-resource cleanup failed; see retained result")


def check_cgroup(cg):
    require(all(type(cg[key]) is int and cg[key] >= 0 for key in ("memory.current", "memory.peak"))
            and cg["memory.current"] <= cg["memory.peak"] and cg["memory.max"] == DAEMON_BYTES
            and cg["memory.swap.max"] == cg["memory.swap.current"] == cg["memory.swap.peak"] == 0,
            "invalid cgroup memory/swap receipt")


def replace_once(text, old, new):
    require(text.count(old) == 1, f"private derivation anchor drift: {old!r}")
    return text.replace(old, new, 1)


def derived_texts(main, rib, observer, arm, input_observer=None):
    anchor = ".with_readiness_queries(rib_readiness_rx)"
    if arm == "candidate":
        main = replace_once(main, anchor, ".with_bench_evpn_group_ownership()\n        " + anchor)
    else:
        require(main.count(anchor) == 1 and ".with_bench_evpn_group_ownership()" not in main,
                "private daemon already activates ownership")
    rib = replace_once(rib, "    fn sample_outbound_dirty_gauges(&self) {",
                       "    fn sample_outbound_dirty_gauges(&self) {\n" + observer)
    if input_observer is not None:
        anchor = "                    self.handle_end_of_rib(peer, afi, safi);"
        rib = replace_once(rib, anchor, anchor + "\n" + input_observer)
    return main, rib


def derive(source, arm):
    """Only exported sources are eligible; normal worktrees remain untouched."""
    source = Path(source)
    require(not (source / ".git").exists(), "private derivation refuses a Git checkout")
    require(arm in ("candidate", "private"), "unknown arm")
    main = source / "src/main.rs"
    rib = source / "crates/rib/src/manager/mod.rs"
    observer = source / "bench/scale/evpn-qualification/observer.rs"
    input_observer = source / "bench/scale/evpn-qualification/input_observer.rs"
    main_text, rib_text = derived_texts(main.read_text(), rib.read_text(), observer.read_text(), arm,
                                      input_observer.read_text())
    main.write_text(main_text)
    rib.write_text(rib_text)


def verify_export(output, arm):
    """Compare the entire export to the archive plus the two reviewed patches."""
    source = output / "sources" / arm
    with tarfile.open(output / "source.tar") as archive:
        names = ("src/main.rs", "crates/rib/src/manager/mod.rs", "bench/scale/evpn-qualification/observer.rs")
        texts = [archive.extractfile(name).read().decode() for name in names]
        input_observer = archive.extractfile("bench/scale/evpn-qualification/input_observer.rs").read().decode()
        changed = dict(zip(names[:2], derived_texts(*texts, arm, input_observer), strict=True))
        tracked = set()
        for member in archive:
            if member.issym():
                tracked.add(member.name)
                path = source / member.name
                require(path.is_symlink() and str(path.readlink()) == member.linkname,
                        f"exported symlink drift: {arm}/{member.name}")
            if member.isfile():
                tracked.add(member.name)
                expected = changed[member.name].encode() if member.name in changed else archive.extractfile(member).read()
                require((source / member.name).read_bytes() == expected, f"exported source drift: {arm}/{member.name}")
        require({str(path.relative_to(source)) for path in source.rglob("*")
                 if path.is_file() or path.is_symlink()} == tracked,
                "export contains untracked build inputs")


def prepare(args):
    source, output = Path(args.source).resolve(), Path(args.output).resolve()
    require(not output.exists(), "campaign directory must be new")
    head = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    require(not subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True),
            "commit the reviewed source before freezing a campaign")
    output.mkdir(parents=True)
    archive = output / "source.tar"
    subprocess.run(["git", "-C", str(source), "archive", "--format=tar", "-o", str(archive), head], check=True)
    for arm in ("candidate", "private"):
        destination = output / "sources" / arm
        destination.mkdir(parents=True)
        with tarfile.open(archive) as stream:
            stream.extractall(destination, filter="data")
        derive(destination, arm)
    # One archive identifies the full source, not a per-file seal roster.
    manifest = {"schema": "rustbgpd.evpn-memory.v1", "head": head,
                "source_sha256": digest(archive), "shapes": SHAPES,
                "schedule": SCHEDULE,
                "settle_seconds": 45, "daemon_bytes": DAEMON_BYTES,
                "max_slope_bytes_per_delivery": MAX_SLOPE_BYTES,
                "daemon_cpus": args.daemon_cpus, "harness_cpus": args.harness_cpus,
                "recovery": RECOVERY_BARS,
                "timing_window": timing_window(args.window_start, args.window_end),
                "scope": SCOPE}
    daemon, harness = COMMON.cpu_set(args.daemon_cpus), COMMON.cpu_set(args.harness_cpus)
    require(not daemon & harness and daemon | harness <= os.sched_getaffinity(0),
            "daemon/harness CPU assignments overlap or are unavailable")
    write_json(output / "campaign.json", manifest)
    write_json(output / "source-derivation.json", {
        "candidate": "bench-only constructor plus observer", "private": "same observer only",
        "production_ownership_changed": False})


def build(args):
    output = Path(args.output).resolve()
    manifest_for(output)
    binaries = output / "bin"
    binaries.mkdir()
    write_json(output / "toolchain.json", {
        tool: subprocess.check_output([tool, "--version"], text=True).strip()
        for tool in ("rustc", "cargo")})
    for arm in ("candidate", "private"):
        verify_export(output, arm)
        source = output / "sources" / arm
        target = output / f"target-{arm}"
        command = ["taskset", "-c", BUILD_CPUS, "cargo", "build", "--locked", "--release",
                   "--bin", "rustbgpd", "--features", "rustbgpd-rib/bench-internals", "-j", "6"]
        env = {key: value for key, value in os.environ.items()
               if key not in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS")}
        env["CARGO_TARGET_DIR"] = str(target)
        with (output / f"build-{arm}.log").open("x") as log:
            result = subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
        (output / f"build-{arm}.exit").write_text(f"{result.returncode}\n")
        require(result.returncode == 0, f"{arm} build failed; retained its first log")
        shutil.copy2(target / "release/rustbgpd", binaries / f"rustbgpd-{arm}")
    target = output / "target-candidate"
    env["CARGO_TARGET_DIR"] = str(target)
    for package, binary, label in (("rustbgpd-evpn-load", "evpn-rr-soak", "harness"),
                                   ("rustbgpctl", "rbgp", "client")):
        command = ["taskset", "-c", BUILD_CPUS, "cargo", "build", "--locked", "--release",
                   "-p", package, "--bin", binary, "-j", "6"]
        with (output / f"build-{label}.log").open("x") as log:
            result = subprocess.run(command, cwd=output / "sources/candidate", env=env,
                                    stdout=log, stderr=subprocess.STDOUT)
        (output / f"build-{label}.exit").write_text(f"{result.returncode}\n")
        require(result.returncode == 0, f"{label} build failed; retained its first log")
        shutil.copy2(target / "release" / binary, binaries / binary)
    identities = {path.name: digest(path) for path in binaries.iterdir()}
    require(identities["rustbgpd-candidate"] != identities["rustbgpd-private"], "identical control/candidate binaries")
    write_json(output / "binaries.json", identities)


def metrics(text):
    values = {}
    for line in text.splitlines():
        if line.startswith(("jemalloc_allocated_bytes ", "bgp_evpn_recovery_provenance_exhausted_total{")):
            name, value = line.rsplit(None, 1)
            require(name not in values, f"duplicate metric {name}")
            values[name] = float(value)
    allocated = values.get("jemalloc_allocated_bytes")
    require(allocated is not None and math.isfinite(allocated) and allocated > 0,
            "release jemalloc live-heap metric missing/invalid")
    resets = {}
    for cause in CAUSES:
        name = f'bgp_evpn_recovery_provenance_exhausted_total{{cause="{cause}"}}'
        value = values.get(name)
        require(value is not None and math.isfinite(value) and value >= 0 and value.is_integer(),
                f"execution-confirmed reset series missing/invalid: {cause}")
        resets[cause] = int(value)
    require(len(values) == len(CAUSES) + 1, "unknown EVPN executed-reset cause")
    accept(not any(resets.values()), "executed EVPN provenance reset")
    return {"jemalloc_allocated_bytes": int(allocated), "executed_resets": resets}


def receipt(text, clients, routes):
    lines = [line for line in text.splitlines() if line.startswith("evpn_receipt ")]
    require(len(lines) == 1 and "FAIL:" not in text and "evpn_session_lost " not in text,
            "missing/duplicate/failed EVPN fleet receipt")
    row = dict(item.split("=", 1) for item in lines[0].split()[1:])
    expected = (clients - 1) * routes
    for key, value in {"clients": clients, "receivers": clients, "expected": expected,
                       "min_live": expected, "max_live": expected, "epochs": 0,
                       "converged_epochs": 0, "flaps": 0, "reloads": 0, "invalid": 0,
                       "parse_errors": 0, "self_reflected": 0}.items():
        require(row.get(key) == str(value), f"EVPN fleet receipt differs: {key}")
    convergence = re.findall(r"^converged \(initial\) clients=\d+ expected=\d+ ms=(\d+)$", text, re.M)
    require(len(convergence) == 1, "initial convergence evidence missing")
    return {"exact_receiver_keys": True, "initial_convergence_ms": int(convergence[0])}


def validate_provenance(row, clients):
    """Validate charges and peer identity, including partial or dirty rosters."""
    counts = ("members", "retained", "peak", "peer_budget", "daemon_budget")
    require(all(type(row[name]) is int and row[name] >= 0 for name in counts), "invalid provenance count")
    require(row["peer_budget"] == 16 * 1024 ** 2 and row["daemon_budget"] == 256 * 1024 ** 2,
            "EVPN provenance budgets changed")
    require(row["retained"] <= row["peak"] <= row["daemon_budget"], "invalid daemon provenance charge")
    require(type(row["peers"]) is list and len(row["peers"]) == row["members"] <= clients,
            "invalid provenance peer roster")
    expected_peers = {COMMON.peer(index) for index in range(clients)}
    seen = set()
    for peer in row["peers"]:
        require(type(peer) is list and len(peer) == 10, "invalid provenance peer shape")
        require(type(peer[0]) is str and peer[0] in expected_peers and peer[0] not in seen,
                "unknown or duplicate provenance peer")
        seen.add(peer[0])
        require(peer[1] is None or (type(peer[1]) is int and peer[1] >= 0), "invalid provenance group")
        require(all(type(peer[index]) is bool for index in (2, 6, 7, 8, 9))
                and all(type(peer[index]) is int and peer[index] >= 0 for index in (3, 4, 5))
                and peer[3] <= peer[4] <= row["peer_budget"], "invalid peer provenance charge")


def accept_provenance_headroom(row):
    fraction = RECOVERY_BARS["max_budget_fraction"]
    accept(row["peak"] <= row["daemon_budget"] * fraction, "daemon provenance headroom breached")
    accept(all(peer[4] <= row["peer_budget"] * fraction for peer in row["peers"]),
           "peer provenance headroom breached")


OBSERVER_COUNTS = ("owned_groups", "owned_members", "owned_routes", "private_routes", "dirty",
                   "pending_resets", "completion_receipts", "marker_debt", "retained_recovery",
                   "refresh_pending", "eor_pending", "protocol_obligations")


def ownership(row, arm, clients, routes):
    validate_provenance(row, clients)
    require(all(type(row[name]) is int and row[name] >= 0 for name in OBSERVER_COUNTS), "invalid ownership count")
    require(row["members"] == clients and row["dirty"] == row["pending_resets"] == row["marker_debt"] == row["retained_recovery"] == 0,
            "ownership witness is incomplete or unsettled")
    require(row["refresh_pending"] == row["eor_pending"] == row["protocol_obligations"] == 0,
            "ownership witness retains a refresh/EoR obligation")
    for peer in row["peers"]:
        require(all(peer[index] is False for index in (2, 6, 7, 8, 9)) and peer[5] == 0,
                "unsettled peer provenance")
    if arm == "candidate":
        require(row["owned_members"] == clients and row["owned_groups"] == 1
                and row["owned_routes"] == clients * routes and row["private_routes"] == 0,
                "candidate did not actually own the one-group EVPN table")
        require(all(type(peer[1]) is int and peer[1] >= 0 for peer in row["peers"])
                and len({peer[1] for peer in row["peers"]}) == 1, "candidate peer ownership differs")
    else:
        require(row["owned_members"] == row["owned_groups"] == row["owned_routes"] == 0
                and row["private_routes"] == clients * (clients - 1) * routes,
                "control is not the actual private EVPN path")
        require(all(peer[1] is None for peer in row["peers"]), "private peer owns EVPN")
    accept_provenance_headroom(row)
    return row


def latest_observation(text):
    rows = [json.loads(line.removeprefix("evpn_qualification ")) for line in text.splitlines()
            if line.startswith("evpn_qualification ")]
    require(rows, "private daemon observer produced no evidence")
    return rows[-1]


def fetch(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=1) as response:
        return response.status, response.read().decode()


def probe_readiness():
    try:
        status, _ = fetch(19186, "/readyz")
        return {"status": status, "http_error_code": None}
    except urllib.error.HTTPError as error:
        return {"status": error.code, "http_error_code": error.code}
    except OSError:
        return {"status": 0, "http_error_code": None}


def run_cell(output, manifest, arm, clients, routes, index, correctness):
    leg = output / f"memory-{index:02}-{arm}-{clients}x{routes}"
    leg.mkdir()
    binary = output / "bin" / f"rustbgpd-{arm}"
    harness = output / "bin/evpn-rr-soak"
    for path in (binary, harness):
        require(digest(path) == json.loads((output / "binaries.json").read_text())[path.name],
                "binary changed after build")
    scenario = Path(tempfile.mkdtemp(prefix="evpn-q-"))
    daemon = driver = None
    record = {"arm": arm, "clients": clients, "routes_per_client": routes,
              "correctness_only": correctness, "status": "INVALID", "scope": SCOPE}
    try:
        cell_gate(output, manifest, leg, correctness)
        env = {key: value for key, value in os.environ.items() if not key.startswith("GEN_")}
        env.update(GEN_EVPN="1", GEN_IBGP_RR_ASN="64512")
        subprocess.run([sys.executable, str(output / "sources/candidate/bench/scale/reloadstall/gen-scenario.py"),
                        str(clients), str(scenario), "17986"], env=env, check=True,
                       stdout=subprocess.DEVNULL)
        config = scenario / "config.toml"
        config.write_text(config.read_text().replace("127.0.0.1:9179", "127.0.0.1:19186"))
        with (leg / "daemon.log").open("x") as log, (leg / "observer.log").open("x") as observer, (leg / "driver.log").open("x") as driver_log:
            subprocess.run(["taskset", "-c", manifest["daemon_cpus"], str(binary), "--check", "--strict", str(config)],
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)
            command = ["systemd-run", "--user", "--scope", "--quiet", "-p", f"MemoryMax={DAEMON_BYTES}",
                       "-p", "MemorySwapMax=0", "--", "taskset", "-c", manifest["daemon_cpus"], str(binary), str(config)]
            if not correctness:
                require_timing_window(manifest)
            record["started_at"] = datetime.now(timezone.utc).isoformat()
            daemon = COMMON.own_child(subprocess.Popen(command, stdout=log, stderr=observer))
            pid = COMMON.daemon_pid(binary, time.monotonic() + 120)
            require(pid == daemon.pid, "scope launcher did not retain exact owned PID")
            record["daemon_owner"] = COMMON.process_identity(pid, binary)
            deadline = time.monotonic() + 1800
            while True:
                require(daemon.poll() is None and time.monotonic() < deadline, "daemon startup failed")
                try:
                    _, body = fetch(19186, "/metrics")
                    metrics(body)
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(.1)
            command = ["taskset", "-c", manifest["harness_cpus"], str(harness), "--daemon", "127.0.0.1:17986",
                       "--clients", str(clients), "--type2", str(routes * 4 // 5), "--type5", str(routes // 5),
                       "--shift2", "1", "--shift5", "1", "--epochs", "0", "--epoch-secs", "1", "--churn-secs", "0",
                       "--evidence-dir", str(scenario / "finish"), "--hold-time", "180"]
            driver = COMMON.own_child(subprocess.Popen(command, stdout=driver_log, stderr=subprocess.STDOUT))
            samples = []
            ready_at = None
            while True:
                require(daemon.poll() is None and driver.poll() is None and time.monotonic() < deadline,
                        "owned process exited or fixed deadline expired")
                start = time.monotonic()
                sample = probe_readiness()
                sample["elapsed_seconds"] = None if correctness else time.monotonic() - start
                samples.append(sample)
                if (scenario / "finish/ready").exists():
                    ready_at = ready_at or time.monotonic()
                    if time.monotonic() - ready_at >= (1 if correctness else manifest["settle_seconds"]):
                        break
                time.sleep(.25)
            record.update(receipt((leg / "driver.log").read_text(), clients, routes))
            _, body = fetch(19186, "/metrics")
            (leg / "metrics.txt").write_text(body)
            heap = metrics(body)
            observed = ownership(latest_observation((leg / "observer.log").read_text()), arm, clients, routes)
            record["ownership"] = observed
            record["executed_resets"] = heap["executed_resets"]
            cg = COMMON.snapshot_cgroup(pid, DAEMON_BYTES)
            write_json(leg / "cgroup.json", cg)
            record["memory"] = None if correctness else {**cg, "jemalloc_allocated_bytes": heap["jemalloc_allocated_bytes"]}
            record["readiness"] = samples
            if correctness:
                record["initial_convergence_ms"] = None
            (scenario / "finish/ack").touch()
            status = driver.wait(timeout=60)
            record["driver_exit"] = status
            require(status == 0, "EVPN driver failed after finish handshake")
            receipt((leg / "driver.log").read_text(), clients, routes)
            accept(all(sample["status"] == 200 for sample in samples), "readiness failed during initial load/settle")
            record["status"] = "PASS"
    except Exception as error:
        if isinstance(error, AcceptanceFailure):
            record["status"] = "FAIL"
        record["error"] = str(error)
        raise
    finally:
        cleanup_cell(record, leg, scenario, driver, daemon)


def run(args):
    output = Path(args.output).resolve()
    manifest = manifest_for(output)
    for arm in ("candidate", "private"):
        verify_export(output, arm)
    require(args.correctness_only or manifest.get("source_kind", "committed") == "committed",
            "measured cells require a final committed source")
    # Entry through run.sh holds the canonical descriptor across this process.
    lock_fd = os.environ.get("RUSTBGPD_HOST_LOCK_FD")
    require(lock_fd is not None and Path(f"/proc/self/fd/{int(lock_fd)}").exists(), "use run.sh to hold the host lock")
    shapes = [(3, 10)] if args.correctness_only else SHAPES
    schedule = ["candidate", "private"] if args.correctness_only else manifest["schedule"]
    index = 0
    for clients, routes in shapes:
        for arm in schedule:
            try:
                run_cell(output, manifest, arm, clients, routes, index, args.correctness_only)
            except AcceptanceFailure as error:
                if arm != "private":
                    raise
                print(f"private baseline cell {index} FAIL: {error}", file=sys.stderr)
            index += 1
    analyze(args)


def analyze(args):
    path = Path(args.output).resolve() / "summary.json"
    write_json(path, {"status": "INVALID", "scope": SCOPE, "error": "analysis incomplete"})
    try:
        return analyze_results(args)
    except Exception as error:
        summary = json.loads(path.read_text())
        summary.update(status="FAIL" if isinstance(error, AcceptanceFailure) else "INVALID", error=str(error))
        write_json(path, summary)
        raise


def analyze_results(args):
    output = Path(args.output).resolve()
    manifest = manifest_for(output)
    paths = sorted(output.glob("memory-*/result.json"))
    rows = [json.loads(path.read_text()) for path in paths]
    require(rows, "missing memory cells")
    correct = rows[0]["correctness_only"]
    require(all(row["correctness_only"] == correct for row in rows), "mixed correctness/measured campaign")
    expected = [(arm, clients, routes) for clients, routes in ([(3, 10)] if correct else SHAPES)
                for arm in (["candidate", "private"] if correct else manifest["schedule"])]
    require([(row["arm"], row["clients"], row["routes_per_client"]) for row in rows] == expected,
            "incomplete, repeated or reordered memory matrix")
    require(all(row["status"] in ("PASS", "FAIL") for row in rows), "invalid memory cell")
    failures = [{"cell": path.parent.name, "arm": row["arm"], "error": row["error"]}
                for path, row in zip(paths, rows, strict=True) if row["status"] == "FAIL"]
    if failures:
        write_json(output / "summary.json", {
            "status": "FAIL", "correctness_only": correct, "scope": SCOPE,
            "head": manifest["head"], "production_activation_qualified": False,
            "cells": len(rows), "slopes": [], "failed_cells": failures})
        accept(False, "recorded cell acceptance failures; see failed_cells")
    for path, row in zip(paths, rows, strict=True):
        leg = path.parent
        receipt((leg / "driver.log").read_text(), row["clients"], row["routes_per_client"])
        require(row["driver_exit"] == 0, "driver did not finish successfully")
        # The final observer may describe peer teardown; the retained settled
        # observation must occur in the actual daemon log before that teardown.
        observed = [json.loads(line.removeprefix("evpn_qualification "))
                    for line in (leg / "observer.log").read_text().splitlines()
                    if line.startswith("evpn_qualification ")]
        require(row["ownership"] in observed, "retained ownership witness absent from daemon log")
        for observation in observed:
            validate_provenance(observation, row["clients"])
        for observation in observed:
            accept_provenance_headroom(observation)
        heap = metrics((leg / "metrics.txt").read_text())
        require(row["executed_resets"] == heap["executed_resets"], "reset receipt differs from raw metrics")
        ownership(row["ownership"], row["arm"], row["clients"], row["routes_per_client"])
        require(set(row["executed_resets"]) == set(CAUSES) and not any(row["executed_resets"].values()),
                "reset evidence missing or nonzero")
        require(row["readiness"] and all(sample["status"] == 200 for sample in row["readiness"]), "failed/empty readiness evidence")
        if not correct:
            cg = json.loads((leg / "cgroup.json").read_text())
            require(row["memory"] == {**cg, "jemalloc_allocated_bytes": heap["jemalloc_allocated_bytes"]},
                    "memory receipt differs from raw cgroup/heap observations")
            check_cgroup(cg)
    slopes = []
    if not correct:
        for low, high in ((SHAPES[0], SHAPES[1]), (SHAPES[2], SHAPES[3])):
            for arm in ("candidate", "private"):
                pair = []
                for shape in (low, high):
                    samples = [row["memory"] for row in rows if row["arm"] == arm and
                               (row["clients"], row["routes_per_client"]) == shape]
                    require(len(samples) == 3, "three repetitions required")
                    pair.append({key: statistics.median(sample[key] for sample in samples)
                                 for key in ("jemalloc_allocated_bytes", "memory.current", "memory.peak")})
                deliveries = high[0] * (high[0] - 1) * high[1] - low[0] * (low[0] - 1) * low[1]
                slopes.append({"arm": arm, "total_routes": low[0] * low[1],
                               "bytes_per_delivery": {key: (pair[1][key] - pair[0][key]) / deliveries for key in pair[0]},
                               "bytes_per_added_receiver": {key: (pair[1][key] - pair[0][key]) / (high[0] - low[0])
                                                            for key in pair[0]}})
    accepted = correct or all(row["bytes_per_delivery"]["jemalloc_allocated_bytes"] <=
                             manifest["max_slope_bytes_per_delivery"] for row in slopes if row["arm"] == "candidate")
    summary = {"status": "PASS" if accepted else "FAIL", "correctness_only": correct,
               "scope": SCOPE, "head": manifest["head"], "slopes": slopes,
               "source_kind": manifest.get("source_kind", "committed"),
               "production_activation_qualified": False, "max_slope_bytes_per_delivery": manifest["max_slope_bytes_per_delivery"]}
    write_json(output / "summary.json", summary)
    accept(accepted, "candidate live-heap slope exceeds predeclared bar")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("prepare")
    p.add_argument("output")
    p.add_argument("--source", default=str(ROOT))
    p.add_argument("--daemon-cpus", default="0-23")
    p.add_argument("--harness-cpus", default="32-55")
    p.add_argument("--window-start", help="explicit authorized timed interval start, UTC ISO-8601")
    p.add_argument("--window-end", help="explicit authorized timed interval end, UTC ISO-8601")
    for name in ("build", "run", "analyze"):
        p = commands.add_parser(name)
        p.add_argument("output")
        if name == "run":
            p.add_argument("--correctness-only", action="store_true")
    args = parser.parse_args()
    globals()[args.command](args)


if __name__ == "__main__":
    main()
