#!/usr/bin/env python3
"""Frozen real-daemon mass-dirty recovery qualification; never a component receipt."""

from __future__ import annotations

import argparse
import contextlib
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import statistics
import stat
import subprocess
import sys
import time
import traceback
import urllib.request


HERE = Path(__file__).resolve().parent
GIB = 1024 ** 3
CAUSES = ("peer_limit", "daemon_limit", "allocation_failure", "missing_proof")
LIMITS = {"daemon_bytes": 10 * GIB, "harness_bytes": 2 * GIB,
          "minimum_available_bytes": 12 * GIB, "swap_bytes": 0,
          "leg_deadline_seconds": 1800, "readiness_request_deadline_ms": 1000,
          "readiness_interval_seconds": .25, "readiness_max_gap_seconds": 1.25,
          "readiness_ceiling_seconds": 1.0, "readiness_slow_seconds": .250, "readiness_slow_run": 3,
          "readiness_p99_relative": 1.25, "readiness_p99_absolute_seconds": .025,
          "readiness_max_relative": 1.5, "readiness_max_absolute_seconds": .050,
          "convergence_relative": 1.10, "convergence_absolute_seconds": 0.030}
OWNED_INPUTS = ("src/main.rs", "src/recovery_mass_dirty.rs", "recovery_mass_dirty.py",
                "test_recovery_mass_dirty.py", "run-recovery-mass-dirty.sh", "README.md")
SUPPORT_INPUTS = ("sample-daemon-cgroup.py", "../provenance.sh", "../cgroup-memory.sh",
                  "../../../tests/soak/host-lock.sh")
FIXTURE_INPUTS = ("config.toml", "member.rpol", "generation.list")
BUILD_ROLES = ("candidate", "flat", "harness", "rbgp")
BUILD_EVIDENCE_FILES = ("campaign.json", "campaign.sha256", "candidate.sha", "capture-source.rs",
                        "flat-control-source.rs", "flat-control.patch", "derivation.json",
                        "rustc-version.txt", "cargo-version.txt", "binaries.sha256", "binary-validation.json",
                        *(f"build-{role}.{suffix}" for role in BUILD_ROLES for suffix in ("log", "exit")))
BUILD_EVIDENCE_SEAL = "campaign-build-evidence.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_fixture(directory, hashes):
    require(isinstance(hashes, dict) and set(hashes) == set(FIXTURE_INPUTS), "fixture input roster differs")
    for name in FIXTURE_INPUTS:
        require(digest(Path(directory) / name) == hashes[name], f"retained fixture input changed: {name}")


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def snapshot_timeout(returncode, stdout, stderr):
    return (type(returncode) is int and returncode == 1 and stdout == "" and isinstance(stderr, str) and
            stderr.strip() == "Error: deadline exceeded: RIB snapshot query timed out")


def snapshot_failure_counts(path, receivers):
    counts = {}
    records = [json.loads(line) for line in Path(path).read_text().splitlines()]
    phases = ("initial", "initial-source", "held-b", "settled-b", "settled-b-source",
              "held-a", "settled-a", "settled-a-source")
    previous_phase = -1
    for sequence, record in enumerate(records, 1):
        phase, address = record["phase"], record["peer"]
        sources = {"initial-source", "settled-b-source", "settled-a-source"}
        members = {"initial", "settled-b", "settled-a"}
        held = {"held-b", "held-a"}
        require(phase in sources | members | held, "unknown ordinary snapshot phase")
        require(phases.index(phase) >= previous_phase, "ordinary snapshot phase order differs")
        previous_phase = phases.index(phase)
        expected = {peer(0)} if phase in sources else {peer(index) for index in range(1, receivers + 1)}
        if phase in held:
            expected.add(peer(0))
        require(address in expected, "ordinary snapshot peer/phase differs")
        peers = counts.setdefault(phase, {})
        attempt = peers.get(address, 0) + 1
        require(type(record["sequence"]) is int and record["sequence"] == sequence and
                type(record["attempt"]) is int and record["attempt"] == attempt, "ordinary snapshot attempt order differs")
        require(record["error"] == "CalledProcessError" and
                snapshot_timeout(record["returncode"], record["stdout"], record["stderr"]),
                "non-retryable ordinary snapshot failure in completed leg")
        peers[address] = attempt
    return {"total": len(records), "by_phase": counts}


def poll_snapshot_witness(read, rbgp, addr, deadline, failures, phase, processes=()):
    def active():
        require(all(process.poll() is None for process in processes), "owned process exited during ordinary snapshot polling")
        if time.monotonic() >= deadline:
            raise TimeoutError("fixed leg deadline expired during ordinary snapshot polling")

    def query(address):
        active()
        begin = time.monotonic()
        if begin >= deadline:
            raise TimeoutError("fixed leg deadline expired during ordinary snapshot polling")
        completed = None
        try:
            completed = subprocess.run([str(rbgp), "--addr", addr, "--json", "neighbor", address],
                                       text=True, capture_output=True, timeout=min(30, deadline - begin), check=True)
            row = json.loads(completed.stdout)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as error:
            stdout = completed.stdout if completed is not None else getattr(error, "output", None)
            stderr = completed.stderr if completed is not None else getattr(error, "stderr", None)
            previous = [json.loads(line) for line in Path(failures).read_text().splitlines()]
            record = {"sequence": len(previous) + 1, "phase": phase, "peer": address,
                      "attempt": 1 + sum(item["phase"] == phase and item["peer"] == address for item in previous),
                      "error": type(error).__name__,
                      "returncode": completed.returncode if completed is not None else getattr(error, "returncode", None),
                      "stdout": stdout.decode("utf-8", "surrogateescape") if isinstance(stdout, bytes) else stdout,
                      "stderr": stderr.decode("utf-8", "surrogateescape") if isinstance(stderr, bytes) else stderr}
            with Path(failures).open("a") as stream:
                stream.write(json.dumps(record) + "\n")
            raise
        return row, begin, time.monotonic()

    while True:
        active()
        try:
            result = read(query)
            active()
            return result
        except subprocess.CalledProcessError as error:
            if not snapshot_timeout(error.returncode, error.output, error.stderr):
                raise
            active()
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))


def cpu_set(text):
    result = set()
    for part in text.split(","):
        require(re.fullmatch(r"[0-9]+(?:-[0-9]+)?", part), "invalid CPU list")
        ends = [int(value) for value in part.split("-")]
        require(len(ends) == 1 or ends[0] <= ends[1], "descending CPU range")
        result.update(range(ends[0], ends[-1] + 1))
    require(result, "empty CPU list")
    return result


def profile_shape(profile):
    require(profile in ("full-uc", "full-vpn"), "unknown profile")
    return [1_000_000, 230_000]


def wire_stimulus():
    counts = profile_shape("full-uc")
    batch = 80
    chunks = sum((count + batch - 1) // batch for count in counts)
    return {"kind": "bgp-attribute-churn", "batch_size": batch, "origin_base": 4_200_100_000,
            "origin_cardinality": chunks, "eor_messages_per_operation": chunks,
            "baseline_eor_messages": 2, "receiver_receive_buffer_requested_bytes": 4096,
            "receiver_receive_buffer_bytes": 8192}


def fixture_prefix(family, index):
    if family == 0:
        return f"{20 + (index >> 16)}.{(index >> 8) & 255}.{index & 255}.0/24"
    return f"3001:{index >> 16:x}:{index & 65535:x}::/48"


def peer(index):
    return f"127.1.{index // 200}.{index % 200 + 1}"


def generate(directory, profile, receivers, bgp_port, metrics_port, pressure=False):
    directory = Path(directory).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    require(len(str(directory / "grpc.sock").encode()) <= 100, "UDS path exceeds safe length")
    vpn = profile == "full-vpn"
    denied = [fixture_prefix(f, n) for f in range(2) for n in range(2 if vpn else 4)] if pressure else []
    policy = ("dataset asn-set generation_b\n" +
              (f"prefix-set denied {{ {', '.join(denied)} }}\n" if pressure else "") +
              "policy member-out {\n" +
              ("    term deny-b { if route.origin-as in generation_b && route.prefix in denied { reject } }\n" if pressure else "") +
              "    term b { if route.origin-as in generation_b {\n"
              "        add community 65400:2000; accept\n"
              "    } }\n"
              "    term a { add community 65400:1000; accept }\n"
              "}\n")
    (directory / "member.rpol").write_text(policy)
    stimulus = wire_stimulus()
    (directory / "generation.list").write_text("".join(
        f"{stimulus['origin_base'] + 2 * chunk + 1}\n" for chunk in range(stimulus["origin_cardinality"])))
    families = '["l3vpn_ipv4_unicast", "l3vpn_ipv6_unicast"]' if vpn else '["ipv4_unicast", "ipv6_unicast"]'
    lines = ["config_epoch = 2", "", "[global]", "asn = 64512", 'router_id = "10.0.0.1"',
             "ebgp_requires_policy = true",
             'cluster_id = "10.0.0.1"', f"listen_port = {bgp_port}",
             f"runtime_state_dir = {json.dumps(str(directory))}", "",
             "[global.telemetry]", 'log_format = "json"',
             f'prometheus_addr = "127.0.0.1:{metrics_port}"', "",
             "[global.telemetry.grpc_uds]", f"path = {json.dumps(str(directory / 'grpc.sock'))}", "",
             "[policy]", 'rpol_files = ["member.rpol"]', 'export_chain = ["member-out"]', "",
             "[policy.datasets.generation_b]", 'path = "generation.list"', ""]
    for index in range(receivers + 1):
        lines.extend(["[[neighbors]]", f'address = "{peer(index)}"', "remote_asn = 64512",
                      f"families = {families}", "hold_time = 180",
                      f"route_reflector_client = {'true' if index else 'false'}", ""])
    (directory / "config.toml").write_text("\n".join(lines))
    return {name: digest(directory / name) for name in FIXTURE_INPUTS}


SHARING_GUARD = "true"


def sharing_guard(text):
    """Offset of the full-OLD sharing argument that follows `&group.table,`."""
    begin = text.index("    fn capture_group_admitted_keys_inner(")
    end = text.index("    pub(in crate::manager) fn prepare_empty_group_recovery_admission", begin)
    section = text[begin:end]
    require(section.count(".capture_full_old_with_checkpoint(") == 1, "full-OLD helper anchor drift")
    call = section.index(".capture_full_old_with_checkpoint(")
    table = section.index("&group.table,", call) + len("&group.table,")
    guard = table + len(section[table:]) - len(section[table:].lstrip())
    require(section.startswith(SHARING_GUARD + ",", guard), "full-OLD sharing guard anchor drift")
    return begin + guard


def derive_flat(source, output):
    """Wrap only the optional full-OLD attempt; leave flat fallback and all other seams intact."""
    source = Path(source)
    text = source.read_text()
    start = sharing_guard(text)
    close = start + len(SHARING_GUARD)
    expression, replacement = SHARING_GUARD, "false"
    changed = text[:start] + replacement + text[close:]
    source.write_text(changed)
    metadata = {"schema": "rustbgpd.mass-dirty-derivation.v1", "path": str(source.name),
                "source_before_sha256": hashlib.sha256(text.encode()).hexdigest(),
                "source_after_sha256": digest(source), "expression_before": expression,
                "expression_after": replacement, "scope": "optional full-OLD common sharing only",
                "vpn_full_old_already_flat": False,
                "vpn_comparison": "candidate shares unicast and VPN full-OLD; control is exact flat for both"}
    write_json(output, metadata)
    return metadata


def init(args):
    root = Path(args.output)
    require(not root.exists(), "output directory must be fresh")
    require(re.fullmatch(r"[0-9a-f]{40}", args.head), "head must be exact SHA")
    require(args.cohort in ("no-refusal", "cap-pressure"), "unknown cohort")
    daemon, harness = cpu_set(args.daemon_cpus), cpu_set(args.harness_cpus)
    require(not daemon & harness, "daemon and harness CPUs overlap")
    require(daemon | harness <= os.sched_getaffinity(0), "unavailable CPU assignment")
    root.mkdir(parents=True)
    correct = args.correctness_only
    receivers = 2 if correct else 12 if args.cohort == "no-refusal" else 24
    require(time.get_clock_info("monotonic").implementation == "clock_gettime(CLOCK_MONOTONIC)",
            "qualification requires the native CLOCK_MONOTONIC clock")
    manifest = {"schema": "rustbgpd.mass-dirty-campaign.v3", "head": args.head,
                "readiness_clock": "CLOCK_MONOTONIC",
                "wire_stimulus": wire_stimulus(),
                "profile": args.profile, "cohort": args.cohort, "receivers": receivers,
                "family_keys": profile_shape(args.profile), "correctness_only": correct,
                "withdrawals_per_receiver": 8 if args.cohort == "cap-pressure" else 0,
                "repetitions": 1 if correct else 3, "limits": LIMITS,
                "daemon_cpus": args.daemon_cpus, "harness_cpus": args.harness_cpus,
                "schedule": [arm for repeat in range(1 if correct else 3)
                             for arm in (("flat", "candidate") if repeat % 2 == 0 else ("candidate", "flat"))],
                "scope": "actual daemon, TCP, exact wire receivers and public readiness; no release-soak claim",
                "primary_convergence": "source-churn command send to controller observation of exact final fleet fold; includes ingress fill, cold capture and dirty witness",
                "mass_dirty_witness": "two current-episode interval intersections while every target is held pending; actual per-target dirty resync after resume; source stays clean",
                "inputs": {name: digest(HERE / name) for name in OWNED_INPUTS}}
    manifest["support_inputs"] = {name: digest(HERE / name) for name in SUPPORT_INPUTS}
    write_json(root / "campaign.json", manifest)
    (root / "campaign.sha256").write_text(digest(root / "campaign.json") + "\n")
    return manifest


def load_manifest(root):
    root = Path(root)
    require(digest(root / "campaign.json") == (root / "campaign.sha256").read_text().strip(), "campaign changed")
    manifest = json.loads((root / "campaign.json").read_text())
    require(manifest["schema"] == "rustbgpd.mass-dirty-campaign.v3", "campaign schema changed")
    require(manifest["readiness_clock"] == "CLOCK_MONOTONIC" and
            time.get_clock_info("monotonic").implementation == "clock_gettime(CLOCK_MONOTONIC)",
            "readiness clock changed")
    require(type(manifest["correctness_only"]) is bool, "invalid campaign mode")
    require(manifest["wire_stimulus"] == wire_stimulus(), "wire stimulus changed")
    require(re.fullmatch(r"[0-9a-f]{40}", manifest["head"]), "invalid campaign source")
    require(manifest["profile"] in ("full-uc", "full-vpn") and manifest["cohort"] in ("no-refusal", "cap-pressure"), "invalid campaign cell")
    repeats = 1 if manifest["correctness_only"] else 3
    schedule = [arm for repeat in range(repeats)
                for arm in (("flat", "candidate") if repeat % 2 == 0 else ("candidate", "flat"))]
    require(type(manifest["repetitions"]) is int and manifest["repetitions"] == repeats, "campaign repetitions changed")
    require(manifest["schedule"] == schedule and len(schedule) > 0, "campaign schedule changed")
    require(manifest["limits"] == LIMITS, "acceptance/resource bounds changed")
    require(manifest["family_keys"] == profile_shape(manifest["profile"]), "shape changed")
    require(manifest["receivers"] == (2 if manifest["correctness_only"] else 12 if manifest["cohort"] == "no-refusal" else 24), "cohort resized")
    require(manifest["withdrawals_per_receiver"] == (8 if manifest["cohort"] == "cap-pressure" else 0), "withdrawal workload changed")
    require(set(manifest["inputs"]) == set(OWNED_INPUTS), "instrument roster changed")
    require(set(manifest["support_inputs"]) == set(SUPPORT_INPUTS), "support instrument roster changed")
    daemon, harness = cpu_set(manifest["daemon_cpus"]), cpu_set(manifest["harness_cpus"])
    require(not daemon & harness, "daemon and harness CPUs overlap")
    for name, expected in manifest["inputs"].items():
        require(digest(HERE / name) == expected, f"instrument changed: {name}")
    for name, expected in manifest["support_inputs"].items():
        require(digest(HERE / name) == expected, f"support instrument changed: {name}")
    return manifest


def campaign_build_evidence(root, manifest):
    """Validate immutable build inputs independently of their recorded hashes."""
    root = Path(root)
    archived = {"frozen-instrumentation/" + name: expected for name, expected in manifest["inputs"].items()}
    archived.update({"frozen-support/" + os.path.normpath("bench/scale/reloadstall/" + name): expected
                     for name, expected in manifest["support_inputs"].items()})
    for directory in ("frozen-instrumentation", "frozen-support"):
        base = root / directory
        require(stat.S_ISDIR(base.lstat().st_mode), f"missing/non-directory build archive: {directory}")
        actual = set()
        for path in base.rglob("*"):
            mode = path.lstat().st_mode
            require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), f"non-regular build archive entry: {path.name}")
            if stat.S_ISREG(mode):
                actual.add(path.relative_to(root).as_posix())
        require(actual == {name for name in archived if name.startswith(directory + "/")},
                f"build archive roster differs: {directory}")
    names = set(BUILD_EVIDENCE_FILES) | archived.keys()
    for name in names:
        require(stat.S_ISREG((root / name).lstat().st_mode), f"non-regular campaign build evidence: {name}")
    hashes = {name: digest(root / name) for name in sorted(names)}
    for name, expected in archived.items():
        require(hashes[name] == expected, f"archived campaign input changed: {name}")
    for role in BUILD_ROLES:
        require((root / f"build-{role}.exit").read_text() == "0\n", f"campaign build did not succeed: {role}")
        require((root / f"build-{role}.log").stat().st_size > 0, f"empty campaign build log: {role}")
    for name in ("rustc-version.txt", "cargo-version.txt"):
        require((root / name).read_text().strip(), f"empty build toolchain evidence: {name}")
    require((root / "candidate.sha").read_text().strip() == manifest["head"], "candidate source identity differs")
    binaries = verified_binaries(root)
    require(json.loads((root / "binary-validation.json").read_text()) == binaries, "binary validation evidence differs")
    return hashes, binaries


def seal_build(root):
    root = Path(root)
    seal = root / BUILD_EVIDENCE_SEAL
    require(not os.path.lexists(seal), "campaign build evidence is already sealed")
    require(not any(root.glob("leg-*")) and not any(root.glob("controller-*.log"))
            and not (root / "driver.exit").exists() and not (root / "execution.exit").exists(),
            "campaign build evidence must be sealed before the first leg")
    manifest = load_manifest(root)
    hashes, _ = campaign_build_evidence(root, manifest)
    # Exclusive creation makes this a one-time pre-leg record. Consumers only
    # verify it; mutable leg, controller, driver and verdict files stay outside.
    with seal.open("x") as stream:
        stream.write(json.dumps({"schema": "rustbgpd.mass-dirty-build-evidence.v1",
                                 "head": manifest["head"], "files": hashes}, indent=2, sort_keys=True) + "\n")


def verified_build_evidence(root, manifest):
    seal = Path(root) / BUILD_EVIDENCE_SEAL
    require(stat.S_ISREG(seal.lstat().st_mode), "missing/non-regular campaign build evidence seal")
    record = json.loads(seal.read_text())
    require(type(record) is dict and set(record) == {"schema", "head", "files"}
            and record["schema"] == "rustbgpd.mass-dirty-build-evidence.v1"
            and record["head"] == manifest["head"], "campaign build evidence seal identity differs")
    hashes, binaries = campaign_build_evidence(root, manifest)
    require(type(record["files"]) is dict and record["files"] == hashes, "campaign build evidence hash roster differs")
    return binaries


def dirty_receipts(text, receivers):
    expected = {peer(index) for index in range(1, receivers + 1)}
    result = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = json.loads(line).get("fields", {})
        if fields.get("message") != "outbound routes resynced":
            continue
        require(fields.get("peer") in expected and fields.get("dirty") is True and fields.get("force") is False,
                "unexpected peer or non-dirty/forced resync receipt")
        result.append(fields)
    require({item["peer"] for item in result} == expected, "missing actual dirty resync receipt")
    return result


def operation_log_slices(log, cursors, previous_end):
    require(type(cursors) is dict and set(cursors) == {"start", "resume", "end"}, "missing/invalid daemon log byte cursors")
    start, resume, end = (cursors[key] for key in ("start", "resume", "end"))
    require(all(type(value) is int for value in (start, resume, end)) and
            0 <= previous_end <= start <= resume < end <= len(log), "unordered/out-of-bounds daemon log byte cursors")
    require(all(value == 0 or log[value - 1:value] == b"\n" for value in (start, resume, end)),
            "daemon log byte cursors split a record")
    return log[start:end], log[resume:end]


def http_metrics(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as response:
        require(response.status == 200, "metrics HTTP failure")
        return response.read(32 * 1024 * 1024 + 1).decode()


def metric(text, name, labels=""):
    wanted = name + labels
    values = [float(line.split()[1]) for line in text.splitlines() if line.split(" ", 1)[0] == wanted]
    require(len(values) == 1 and math.isfinite(values[0]) and values[0] >= 0, f"missing/invalid metric {wanted}")
    return values[0]


def fallback(text):
    return {cause: integer_metric(text, "bgp_update_group_recovery_fallback_total", f'{{cause="{cause}"}}') for cause in CAUSES}


def fallback_delta(before, after):
    require(all(after[cause] >= before[cause] for cause in CAUSES), "fallback counter regressed")
    return {cause: after[cause] - before[cause] for cause in CAUSES}


def integer_metric(text, name, labels=""):
    value = metric(text, name, labels)
    require(value.is_integer(), f"noninteger metric {name}{labels}")
    return int(value)


def recovery_charge(text):
    charge = {key: integer_metric(text, f"bgp_update_group_recovery_{key}")
              for key in ("entries", "bytes", "peak_bytes")}
    require(charge["bytes"] <= 512 * 1024 ** 2 and charge["peak_bytes"] >= charge["bytes"],
            "invalid retained recovery charge")
    # Peak includes attempted/rolled-back overlapping reservations; it is neither
    # admitted high water nor RSS and is deliberately not capped here.
    return charge


def neighbor_witness(snapshot, receivers, expected=None, pending=None, observe_episode=False):
    rows = []
    for index in range(1, receivers + 1):
        row, begin, end = snapshot(peer(index))
        require(row["address"] == peer(index), "receiver identity changed")
        # The CLI contract omits this boolean while false; true is explicit.
        require(row["state"] == "Established" and row.get("slow_peer", False) is False, "receiver state/isolation changed")
        group = row.get("update_group")
        require(isinstance(group, str) and group.startswith("group:"), "receiver is not grouped")
        require(not rows or group == rows[0]["group"], "receivers do not share one group")
        if expected is not None:
            require(index <= len(expected) and (peer(index), group) == expected[index - 1], "group identity changed")
        observed = {"peer": peer(index), "group": group, "pending": row.get("outbound_resync_pending"),
                    "fallback": row.get("update_group_recovery_fallback", "")}
        if observe_episode:
            observed.update({"dirty_seconds": row.get("outbound_dirty_seconds"), "raw": row,
                             "query_begin_monotonic_seconds": begin, "query_end_monotonic_seconds": end})
            if observed["pending"] is True:
                dirty_interval(observed)
        require(observed["pending"] is pending, "actual dirty overlap/settlement missing")
        rows.append(observed)
    require(rows, "receivers do not share one group")
    if expected is not None:
        require([(row["peer"], row["group"]) for row in rows] == expected, "group identity changed")
    return rows


def dirty_interval(row):
    age = row["dirty_seconds"]
    begin, end = row["query_begin_monotonic_seconds"], row["query_end_monotonic_seconds"]
    require(row["pending"] is True and type(age) is int and age >= 0, "invalid current dirty episode")
    require(all(isinstance(value, (float, int)) and not isinstance(value, bool) and math.isfinite(value)
                for value in (begin, end)) and 0 <= begin <= end, "invalid dirty query clock")
    # The actor samples age inside this RPC. A floored CURRENT age proves
    # that episode covers [query_end-age, query_begin], conservatively.
    return end - age, begin


def dirty_overlap(rows):
    require(rows, "empty dirty witness")
    intervals = [dirty_interval(row) for row in rows]
    begin, end = max(pair[0] for pair in intervals), min(pair[1] for pair in intervals)
    require(begin <= end, "no common current dirty instant")
    return {"begin_monotonic_seconds": begin, "end_monotonic_seconds": end, "proved": True}


def source_witness(snapshot):
    row, begin, end = snapshot(peer(0))
    try:
        validate_source_witness(row)
    except ValueError as error:
        error.add_note("rejected source witness: " + json.dumps({"row": row,
            "query_begin_monotonic_seconds": begin, "query_end_monotonic_seconds": end}, sort_keys=True))
        raise
    return row


def held_dirty_witness(snapshot, receivers, groups, correctness):
    sweeps = [neighbor_witness(snapshot, receivers, expected=groups, pending=True, observe_episode=True)
              for _ in range(2)]
    individual = [dirty_overlap(rows) for rows in sweeps]
    # Combining both sweeps proves the second CURRENT episodes still cover
    # the first common instant; a cleared-and-recreated episode cannot pass.
    stable = dirty_overlap([row for rows in sweeps for row in rows])
    source = source_witness(snapshot)
    if correctness:
        for rows in sweeps:
            for row in rows:
                row["query_begin_monotonic_seconds"] = row["query_end_monotonic_seconds"] = None
        for interval in [*individual, stable]:
            interval["begin_monotonic_seconds"] = interval["end_monotonic_seconds"] = None
    return {"sweeps": sweeps, "overlap": individual, "stable_overlap": stable, "source": source}


def validate_source_witness(row):
    require(row["address"] == peer(0) and row["state"] == "Established" and
            row.get("slow_peer", False) is False and row.get("outbound_resync_pending") is False,
            "source session/pending state changed")


def validate_held_witness(witness, identities, correctness, operation):
    require(len(witness["sweeps"]) == 2 and len(witness["overlap"]) == 2, "dirty sweep count changed")
    all_rows = []
    previous_end = None if correctness else operation["drain_monotonic_seconds"]
    for rows, interval in zip(witness["sweeps"], witness["overlap"], strict=True):
        require([(row["peer"], row["group"]) for row in rows] == identities, "dirty/group witness differs")
        for row in rows:
            raw = row["raw"]
            require(row["pending"] is True and type(row["dirty_seconds"]) is int and row["dirty_seconds"] >= 0 and
                    raw["address"] == row["peer"] and raw["state"] == "Established" and
                    raw.get("slow_peer", False) is False and raw["update_group"] == row["group"] and
                    raw["outbound_resync_pending"] is True and raw["outbound_dirty_seconds"] == row["dirty_seconds"],
                    "current dirty episode derivation differs")
            if correctness:
                require(row["query_begin_monotonic_seconds"] is row["query_end_monotonic_seconds"] is None,
                        "correctness mode published dirty query timing")
            else:
                begin, end = row["query_begin_monotonic_seconds"], row["query_end_monotonic_seconds"]
                require(all(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
                            for value in (begin, end)) and previous_end <= begin <= end <= operation["resume_monotonic_seconds"],
                        "dirty query outside operation or sweep order changed")
                previous_end = end
        if correctness:
            require(interval == {"begin_monotonic_seconds": None, "end_monotonic_seconds": None, "proved": True},
                    "correctness dirty proof missing")
        else:
            require(dirty_overlap(rows) == interval, "dirty interval derivation differs")
        all_rows.extend(rows)
    if correctness:
        require(witness["stable_overlap"] == {"begin_monotonic_seconds": None, "end_monotonic_seconds": None, "proved": True},
                "correctness stable dirty proof missing")
    else:
        require(dirty_overlap(all_rows) == witness["stable_overlap"], "stable dirty interval derivation differs")
        interval = witness["stable_overlap"]
        require(max(interval["begin_monotonic_seconds"], operation["trigger_monotonic_seconds"]) <=
                min(interval["end_monotonic_seconds"], operation["resume_monotonic_seconds"]),
                "common dirty instant outside operation")
    validate_source_witness(witness["source"])


def process_identity(pid, binary):
    proc = Path(f"/proc/{pid}")
    fields = (proc / "stat").read_text().rsplit(")", 1)[1].split()
    require(os.path.samestat((proc / "exe").stat(), Path(binary).stat()), "daemon binary ownership mismatch")
    return {"pid": pid, "starttime": int(fields[19]), "binary_sha256": digest(binary)}


def child_starttime(process):
    return int(Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()[19])


def own_child(process):
    process.qualification_starttime = child_starttime(process)
    return process


def daemon_pid(binary, deadline):
    while time.monotonic() < deadline:
        found = []
        for proc in Path("/proc").iterdir():
            if proc.name.isdigit():
                with contextlib.suppress(FileNotFoundError, PermissionError, ProcessLookupError):
                    if os.path.samestat((proc / "exe").stat(), Path(binary).stat()):
                        found.append(int(proc.name))
        require(len(found) <= 1, "multiple processes run the owned binary")
        if found:
            return found[0]
        time.sleep(0.05)
    raise TimeoutError("owned daemon failed to start")


def snapshot_cgroup(pid, maximum):
    proc = Path(f"/proc/{pid}")
    membership = (proc / "cgroup").read_text().strip()
    require(membership.startswith("0::/") and "\n" not in membership, "ambiguous cgroup ownership")
    group = Path("/sys/fs/cgroup") / membership[4:]
    require(group.name.endswith(".scope"), "daemon lacks dedicated systemd scope")
    require((group / "cgroup.procs").read_text().split() == [str(pid)], "daemon scope contains other processes")
    require(not any(path.read_text().strip() for path in group.glob("*/**/cgroup.procs")), "populated daemon descendants")
    values = {name: int((group / name).read_text()) for name in
              ("memory.current", "memory.peak", "memory.max", "memory.swap.current", "memory.swap.peak", "memory.swap.max")}
    events = dict(line.split() for line in (group / "memory.events").read_text().splitlines())
    require(values["memory.max"] == maximum, "daemon memory cap changed")
    require(values["memory.swap.current"] == values["memory.swap.peak"] == values["memory.swap.max"] == 0, "swap invalidates leg")
    require(all(int(events[name]) == 0 for name in ("oom", "oom_kill", "oom_group_kill")), "OOM invalidates leg")
    return {"path": str(group), **values, "events": events, "boundary_monotonic_ns": time.monotonic_ns()}


def start_harness(args, log, errors):
    # Readiness writes continue while the controller waits for churn/dirty receipts.
    # A regular evidence file has no undrained-pipe dependency on those waits.
    return own_child(subprocess.Popen(args, stdin=subprocess.PIPE, stdout=log,
                                     stderr=errors, text=True, bufsize=1, start_new_session=True))


def read_record(process, records, prefix, deadline):
    pending = ""
    while time.monotonic() < deadline:
        chunk = records.readline()
        if not chunk:
            require(process.poll() is None, f"harness exited before {prefix}: {process.returncode}")
            time.sleep(min(.01, max(0, deadline - time.monotonic())))
            continue
        pending += chunk
        if not pending.endswith("\n"):
            continue
        line, pending = pending, ""
        if line.startswith(prefix + " "):
            return json.loads(line[len(prefix) + 1:])
    raise TimeoutError(f"fixed leg deadline expired waiting for {prefix}")


def stop_owned(process):
    if process is None:
        return
    require(type(process.pid) is int and process.pid > 0, "invalid owned child PID")
    if process.poll() is None:
        require(child_starttime(process) == process.qualification_starttime, "owned child PID identity changed")
        with contextlib.suppress(ProcessLookupError):
            process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            require(child_starttime(process) == process.qualification_starttime, "owned child PID identity changed")
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            process.wait(timeout=15)


def copy_fixture(source, destination):
    def skip_runtime_nodes(directory, names):
        return [name for name in names if not
                (stat.S_ISREG((Path(directory) / name).lstat().st_mode) or
                 stat.S_ISDIR((Path(directory) / name).lstat().st_mode))]

    shutil.copytree(source, destination, ignore=skip_runtime_nodes)


def run_cell(args):
    root = Path(args.output).resolve()
    manifest = load_manifest(root)
    require(args.arm in ("candidate", "flat"), "unknown arm")
    require(0 <= args.index < len(manifest["schedule"]) and manifest["schedule"][args.index] == args.arm, "arm order changed")
    binary, harness_binary, rbgp = [Path(path).resolve(strict=True) for path in (args.daemon, args.harness, args.rbgp)]
    binaries = verified_build_evidence(root, manifest)
    require(digest(binary) == binaries[f"rustbgpd-{args.arm}"] and
            digest(harness_binary) == binaries["reloadstall"] and digest(rbgp) == binaries["rbgp"],
            "run-cell binary identity differs")
    leg = root / f"leg-{args.index}-{args.arm}"
    leg.mkdir()
    snapshot_failures = leg / "ordinary-snapshot-failures.jsonl"
    snapshot_failures.write_text("")
    correct = manifest["correctness_only"]
    if not correct:
        require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "measurement requires fresh hosted runner")
        available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:"))) * 1024
        require(available >= LIMITS["minimum_available_bytes"], "runner capacity insufficient; shape must not shrink")
    # Keep UDS short even when the artifact directory is long. Only this fresh path is removed.
    import tempfile
    scenario = Path(tempfile.mkdtemp(prefix="rmd-", dir="/tmp"))
    scenario.rmdir()
    hashes = generate(scenario, manifest["profile"], manifest["receivers"], 17986, 19186,
                      manifest["cohort"] == "cap-pressure")
    write_json(leg / "fixture.sha256.json", hashes)
    daemon = engine = sampler = None
    result = {"arm": args.arm, "index": args.index, "source": manifest["head"], "operations": [],
              "binary_sha256": digest(binary), "harness_sha256": digest(harness_binary), "rbgp_sha256": digest(rbgp),
              "correctness_only": correct}
    deadline = time.monotonic() + LIMITS["leg_deadline_seconds"]
    result["capture_source_sha256"] = digest(root / "capture-source.rs")
    try:
        with (leg / "daemon.log").open("w") as daemon_log, (leg / "harness.stderr").open("w") as errors, (leg / "harness.log").open("w") as log, (leg / "harness.log").open() as records:
            with (leg / "config-check.log").open("w") as check_log:
                checked = subprocess.run([str(binary), "--check", "--strict", str(scenario / "config.toml")],
                                         stdout=check_log, stderr=subprocess.STDOUT, timeout=30, check=True)
            result["config_check_exit"] = checked.returncode
            daemon_command = ["taskset", "-c", manifest["daemon_cpus"], str(binary), str(scenario / "config.toml")]
            if not correct:
                daemon_command = ["systemd-run", "--user", "--scope", "--quiet", "-p", f"MemoryMax={LIMITS['daemon_bytes']}", "-p", "MemorySwapMax=0", "--", *daemon_command]
            daemon = own_child(subprocess.Popen(daemon_command, stdout=daemon_log, stderr=subprocess.STDOUT, start_new_session=True))
            pid = daemon_pid(binary, min(deadline, time.monotonic() + 120))
            require(pid == daemon.pid, "daemon scope launcher did not retain the owned PID")
            owner = process_identity(pid, binary)
            write_json(leg / "daemon-owner.json", owner)
            while True:
                require(daemon.poll() is None and time.monotonic() < deadline, "daemon startup failed")
                try:
                    http_metrics(19186)
                    break
                except (OSError, ValueError):
                    time.sleep(0.05)
            if not correct:
                result["memory_before"] = snapshot_cgroup(pid, LIMITS["daemon_bytes"])
                sampler_log = (leg / "sampler.log").open("w")
                sampler = own_child(subprocess.Popen([sys.executable, str(HERE / "sample-daemon-cgroup.py"), "--exe", str(binary), "--out", str(leg / "memory.csv"), "--expected-pgid", str(daemon.pid)], stdout=sampler_log, stderr=subprocess.STDOUT, start_new_session=True))
            engine_command = ["taskset", "-c", manifest["harness_cpus"], str(harness_binary), "--recovery-mass-dirty", "--profile", manifest["profile"], "--cohort", manifest["cohort"], "--receivers", str(manifest["receivers"]), "--bgp-port", "17986", "--metrics-addr", "127.0.0.1:19186"]
            if correct:
                engine_command.append("--correctness-only")
            else:
                engine_command = ["systemd-run", "--user", "--scope", "--quiet", "-p", f"MemoryMax={LIMITS['harness_bytes']}", "-p", "MemorySwapMax=0", "--", *engine_command]
            engine = start_harness(engine_command, log, errors)
            engine_pid = daemon_pid(harness_binary, min(deadline, time.monotonic() + 120))
            require(engine_pid == engine.pid, "harness scope launcher did not retain the owned PID")
            result["harness_owner"] = process_identity(engine_pid, harness_binary)
            write_json(leg / "harness-owner.json", result["harness_owner"])
            ready = read_record(engine, records, "mass_dirty_ready", deadline)
            require(ready["family_keys"] == manifest["family_keys"] and ready["receivers"] == manifest["receivers"], "wire population shape changed")
            def snapshot(read, phase):
                return poll_snapshot_witness(read, rbgp, "unix://" + str(scenario / "grpc.sock"), deadline,
                                             snapshot_failures, phase, (daemon, engine))
            initial = snapshot(lambda query: neighbor_witness(query, manifest["receivers"], pending=False), "initial")
            groups = [(row["peer"], row["group"]) for row in initial]
            write_json(leg / "neighbors-initial.json", initial)
            write_json(leg / "source-initial.json", snapshot(source_witness, "initial-source"))
            before = http_metrics(19186)
            (leg / "metrics-initial.prom").write_text(before)
            regroup = metric(before, "bgp_update_group_regroups_total")
            initial_fallback = fallback(before)
            result["fallback_initial"] = initial_fallback
            previous_fallback = initial_fallback
            if manifest["cohort"] == "no-refusal":
                require(not any(initial_fallback.values()), "no-refusal startup entered conservative fallback")
            initial_charge = recovery_charge(before)
            require(initial_charge["entries"] == 0, "initial recovery proof is not empty")
            result["recovery_initial"] = initial_charge
            read_record(engine, records, "mass_dirty_readiness", deadline)
            previous_log_end = 0
            for generation in ("b", "a"):
                engine.stdin.write(f"pause {generation}\n")
                engine.stdin.flush()
                paused = read_record(engine, records, "mass_dirty_paused", deadline)
                require(paused == {"generation": generation, "receivers": manifest["receivers"]}, "pause handshake incomplete")
                validate_fixture(scenario, hashes)
                operation_metrics = http_metrics(19186)
                (leg / f"metrics-before-{generation}.prom").write_text(operation_metrics)
                require(metric(operation_metrics, "bgp_update_group_regroups_total") == regroup, "group changed before churn")
                operation_fallback = fallback(operation_metrics)
                fallback_delta(previous_fallback, operation_fallback)
                if manifest["cohort"] == "no-refusal":
                    require(not any(operation_fallback.values()), "no-refusal cell entered conservative fallback before churn")
                log_offset = (leg / "daemon.log").stat().st_size
                triggered = None if correct else time.monotonic()
                engine.stdin.write(f"churn {generation}\n")
                engine.stdin.flush()
                sent = read_record(engine, records, "mass_dirty_sent", deadline)
                require(sent["generation"] == generation and sent["family_keys"] == manifest["family_keys"] and
                        sent["writer_drained"] is True and
                        all(sent[name] == manifest["wire_stimulus"]["origin_cardinality"] for name in
                            ("announcement_messages", "eor_messages", "origin_cardinality")), "source churn/drain receipt changed")
                drained_at = sent["drained_monotonic_seconds"]
                while True:
                    require(time.monotonic() < deadline and daemon.poll() is None and engine.poll() is None,
                            "actual mass-dirty witness did not arrive within fixed leg deadline")
                    try:
                        witness = snapshot(lambda query: held_dirty_witness(query, manifest["receivers"], groups, correct),
                                           f"held-{generation}")
                        break
                    except ValueError as error:
                        require(str(error) in ("actual dirty overlap/settlement missing", "no common current dirty instant"), str(error))
                        time.sleep(0.05)
                write_json(leg / f"neighbors-paused-{generation}.json", witness)
                current = http_metrics(19186)
                require(metric(current, "bgp_update_group_regroups_total") == regroup, "wire churn regrouped peers")
                (leg / f"metrics-paused-{generation}.prom").write_text(current)
                paused_fallback = fallback(current)
                fallback_delta(operation_fallback, paused_fallback)
                paused_charge = recovery_charge(current)
                require(paused_charge["entries"] > 0 and paused_charge["bytes"] > initial_charge["bytes"],
                        "held dirty recovery proof was not retained")
                if manifest["cohort"] == "no-refusal":
                    require(paused_charge["entries"] == manifest["receivers"] * sum(manifest["family_keys"]),
                            "no-refusal held proof does not cover the full initial fleet")
                # Offset after the held proof: these receipts must witness an
                # actual dirty resync after reader release, not an earlier pass.
                resume_log_offset = (leg / "daemon.log").stat().st_size
                resumed_at = None if correct else time.monotonic()
                engine.stdin.write(f"resume {generation}\n")
                engine.stdin.flush()
                receipt = read_record(engine, records, "mass_dirty_complete", deadline)
                observed_at = None if correct else time.monotonic()
                require(receipt["generation"] == generation and receipt["exact_fold"] and receipt["sessions_continuous"], "wire fold/continuity failed")
                while True:
                    require(time.monotonic() < deadline and daemon.poll() is None and engine.poll() is None,
                            "recovery did not settle within fixed leg deadline")
                    try:
                        settled = snapshot(lambda query: neighbor_witness(query, manifest["receivers"], expected=groups, pending=False),
                                           f"settled-{generation}")
                        break
                    except ValueError as error:
                        require(str(error) == "actual dirty overlap/settlement missing", str(error))
                        time.sleep(0.05)
                write_json(leg / f"neighbors-settled-{generation}.json", settled)
                write_json(leg / f"source-settled-{generation}.json", snapshot(source_witness, f"settled-{generation}-source"))
                while True:
                    log_snapshot = (leg / "daemon.log").read_bytes()
                    log_end = log_snapshot.rfind(b"\n") + 1
                    window = log_snapshot[resume_log_offset:log_end]
                    try:
                        actual_dirty = dirty_receipts(window.decode(), manifest["receivers"])
                        break
                    except ValueError as error:
                        require(str(error) == "missing actual dirty resync receipt" and time.monotonic() < deadline, str(error))
                        time.sleep(0.05)
                log_cursors = {"start": log_offset, "resume": resume_log_offset, "end": log_end}
                operation_log, window = operation_log_slices(log_snapshot, log_cursors, previous_log_end)
                previous_log_end = log_end
                (leg / f"daemon-window-{generation}.jsonl").write_bytes(window)
                (leg / f"daemon-operation-{generation}.jsonl").write_bytes(operation_log)
                write_json(leg / f"dirty-receipts-{generation}.json", actual_dirty)
                after = http_metrics(19186)
                (leg / f"metrics-settled-{generation}.prom").write_text(after)
                require(metric(after, "bgp_update_group_regroups_total") == regroup, "group changed during recovery")
                causes = fallback(after)
                fallback_delta(paused_fallback, causes)
                previous_fallback = causes
                settled_charge = recovery_charge(after)
                require(all(settled_charge[key] == initial_charge[key] for key in ("entries", "bytes")),
                        "settled recovery charge did not return to empty baseline")
                deltas = fallback_delta(operation_fallback, causes)
                if manifest["cohort"] == "no-refusal" or (not correct and args.arm == "candidate"):
                    require(not any(deltas.values()), "indexed/no-refusal cell entered conservative fallback")
                result["operations"].append({**receipt, "daemon_log_bytes": log_cursors,
                    "fallback_before": operation_fallback, "fallback_deltas": deltas,
                    "recovery_paused": paused_charge, "recovery_settled": settled_charge,
                    "trigger_monotonic_seconds": triggered, "drain_monotonic_seconds": drained_at,
                    "resume_monotonic_seconds": resumed_at, "fold_monotonic_seconds": observed_at,
                    "trigger_to_fold_seconds": None if correct else observed_at - triggered,
                    "trigger_to_drain_seconds": None if correct else drained_at - triggered,
                    "drain_to_resume_seconds": None if correct else resumed_at - drained_at,
                    "resume_to_observed_fold_seconds": None if correct else observed_at - resumed_at})
            validate_fixture(scenario, hashes)
            require(process_identity(pid, binary) == owner, "daemon identity changed")
            if not correct:
                result["memory_after"] = snapshot_cgroup(pid, LIMITS["daemon_bytes"])
                harness_pid = daemon_pid(harness_binary, deadline)
                result["harness_owner"] = process_identity(harness_pid, harness_binary)
                result["harness_memory_after"] = snapshot_cgroup(harness_pid, LIMITS["harness_bytes"])
                require(sampler.poll() is None, "memory sampler ended before measurement boundary")
            # Retain a probe after the final controller-observed fold,
            # rather than ending with only samples from before the recovery.
            while True:
                probe = read_record(engine, records, "mass_dirty_readiness", deadline)
                if correct or probe["started_monotonic_seconds"] >= result["operations"][-1]["fold_monotonic_seconds"]:
                    break
            engine.stdin.write("finish\n")
            engine.stdin.flush()
            final = read_record(engine, records, "mass_dirty_exit", deadline)
            require(final["status"] == "PASS" and final["readiness_samples"] > 0, "readiness evidence incomplete")
            engine.wait(timeout=max(0.1, deadline - time.monotonic()))
            require(engine.returncode == 0, "harness failed after final receipt")
            raw_records = harness_records(leg / "harness.log")
            coverage = readiness_coverage(raw_records, result["operations"], correct)
            for operation, evidence in zip(result["operations"], coverage, strict=True):
                operation["readiness_coverage"] = evidence
            if manifest["cohort"] == "cap-pressure" and not correct and args.arm == "flat":
                require(any(operation["fallback_deltas"]["daemon_limit"] for operation in result["operations"]), "pressure control did not exercise daemon cap")
            result["status"] = "CORRECTNESS_ONLY" if correct else "PASS"
            result["snapshot_failure_counts"] = snapshot_failure_counts(snapshot_failures, manifest["receivers"])
            result["raw_sha256"] = {path.name: digest(path) for path in leg.iterdir() if path.is_file() and path.name not in ("memory.csv", "sampler.log")}
            write_json(leg / "result.json", result)
    except BaseException as error:
        # Record the initiating failure before any teardown/snapshot operation
        # can fail as well. The driver retains this with its original traceback.
        write_json(leg / "failure.json", {"type": type(error).__name__, "error": str(error),
                                         "traceback": traceback.format_exc()})
        raise
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cleanup_errors = []
        for name, process in (("harness", engine), ("daemon", daemon)):
            try:
                stop_owned(process)
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                cleanup_errors.append(f"{name}: {error}")
        if sampler is not None:
            try:
                sampler.wait(timeout=30)
            except subprocess.TimeoutExpired:
                try:
                    stop_owned(sampler)
                except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                    cleanup_errors.append(f"sampler: {error}")
            if sampler.returncode != 0:
                cleanup_errors.append(f"sampler exit: {sampler.returncode}")
        if cleanup_errors:
            write_json(leg / "cleanup-error.json", {"errors": cleanup_errors, "retained_fixture": str(scenario)})
            raise RuntimeError("owned cleanup incomplete; fixture/evidence retained")
        if (leg / "result.json").is_file():
            finished = json.loads((leg / "result.json").read_text())
            finished["daemon_exit"] = daemon.returncode
            finished["harness_exit"] = engine.returncode
            require(daemon.returncode == 0 and engine.returncode == 0, "owned process failed during normal teardown")
            finished["raw_sha256"] = {path.name: digest(path) for path in leg.iterdir() if path.is_file() and path.name != "result.json"}
            write_json(leg / "result.json", finished)
        copy_fixture(scenario, leg / "fixture")
        shutil.rmtree(scenario)


def verified_binaries(root):
    root = Path(root)
    hashes = {}
    for line in (root / "binaries.sha256").read_text().splitlines():
        expected, name = line.split(maxsplit=1)
        name = Path(name).name
        require(name not in hashes and digest(root / "bin" / name) == expected, "binary hash changed")
        hashes[name] = expected
    require(set(hashes) == {"rustbgpd-flat", "rustbgpd-candidate", "reloadstall", "rbgp"}, "binary roster differs")
    require(hashes["rustbgpd-candidate"] != hashes["rustbgpd-flat"], "candidate and flat daemon binaries are identical")
    return hashes


def analyze(root):
    root = Path(root)
    manifest = load_manifest(root)
    binary_hashes = verified_build_evidence(root, manifest)
    require((root / "candidate.sha").read_text().strip() == manifest["head"], "candidate source identity differs")
    expected_legs = {f"leg-{index}-{arm}" for index, arm in enumerate(manifest["schedule"])}
    require({path.name for path in root.glob("leg-*")} == expected_legs, "leg roster differs")
    source = (root / "capture-source.rs").read_text()
    source_sha = hashlib.sha256(source.encode()).hexdigest()
    derivation = json.loads((root / "derivation.json").read_text())
    guard = sharing_guard(source)
    expected_flat = source[:guard] + "false" + source[guard + len(SHARING_GUARD):]
    require(derivation["source_before_sha256"] == hashlib.sha256(source.encode()).hexdigest()
            and derivation["source_after_sha256"] == digest(root / "flat-control-source.rs")
            and (root / "flat-control-source.rs").read_text() == expected_flat
            and derivation["expression_before"] == SHARING_GUARD
            and derivation["expression_after"] == "false"
            and derivation["vpn_full_old_already_flat"] is False, "flat source derivation changed")
    rows = []
    failures = []
    readiness = {}
    post_sent = {"flat": [], "candidate": []}
    for index, arm in enumerate(manifest["schedule"]):
        path = root / f"leg-{index}-{arm}" / "result.json"
        require(path.is_file(), f"missing complete leg {index}")
        row = json.loads(path.read_text())
        require(row["arm"] == arm and row["index"] == index and row["source"] == manifest["head"], "leg identity mismatch")
        require(row["capture_source_sha256"] == source_sha and row["binary_sha256"] == binary_hashes[f"rustbgpd-{arm}"]
                and row["harness_sha256"] == binary_hashes["reloadstall"] and row["rbgp_sha256"] == binary_hashes["rbgp"], "compiled leg identity differs")
        require(row["status"] == ("CORRECTNESS_ONLY" if manifest["correctness_only"] else "PASS"), "leg failed")
        require([operation["generation"] for operation in row["operations"]] == ["b", "a"], "operation coverage mismatch")
        probes = validate_leg(path.parent, manifest, row)
        rows.append(row)
        readiness[path.parent.name], leg_failures = readiness_summary(probes, row["operations"])
        failures += [f"{path.parent.name}: {failure}" for failure in leg_failures]
        if not manifest["correctness_only"]:
            post_sent[arm] += post_sent_elapsed(probes, row["operations"])
    verdict = {"status": "CORRECTNESS_ONLY" if manifest["correctness_only"] else "PASS", "cohort": manifest["cohort"],
               "release_soak_qualified": False, "readiness": readiness}
    if manifest["correctness_only"]:
        verdict["readiness_comparison"] = "not_applicable: correctness-only timing is null"
    else:
        verdict["readiness_comparison"], comparison_failures = readiness_comparison(post_sent)
        failures += comparison_failures
    if not manifest["correctness_only"] and manifest["cohort"] == "no-refusal":
        for field in ("trigger_to_fold_seconds",):
            arms = {arm: [operation[field] for row in rows if row["arm"] == arm for operation in row["operations"]] for arm in ("flat", "candidate")}
            require(all(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0 for values in arms.values() for value in values), "invalid convergence durations")
            for statistic in (statistics.median, max):
                limit = statistic(arms["flat"]) * LIMITS["convergence_relative"] + LIMITS["convergence_absolute_seconds"]
                if statistic(arms["candidate"]) > limit:
                    failures.append(f"candidate {field} {statistic.__name__} {statistic(arms['candidate']):.3f} s over {limit:.3f} s bar")
            verdict[field] = arms
    if manifest["cohort"] == "cap-pressure":
        verdict["scope"] = "cap-pressure correctness/resource control; not a pure storage performance comparison"
    if failures:
        verdict["status"] = "FAIL"
        verdict["reason"] = "; ".join(failures)
    else:
        verdict["reason"] = "all predeclared bars met" if verdict["status"] == "PASS" else "correctness-only campaign; no timing bars"
    write_json(root / "verdict.json", verdict)
    return verdict


def harness_records(path):
    prefixes = ("mass_dirty_ready", "mass_dirty_paused", "mass_dirty_sent", "mass_dirty_complete", "mass_dirty_exit", "mass_dirty_readiness")
    records = {prefix: [] for prefix in prefixes}
    for line in Path(path).read_text().splitlines():
        prefix, _, body = line.partition(" ")
        require(prefix in records, "unexpected harness record")
        records[prefix].append(json.loads(body))
    require([len(records[prefix]) for prefix in prefixes[:5]] == [1, 2, 2, 2, 1], "incomplete/duplicate wire records")
    return records


def readiness_coverage(records, operations, correctness):
    final = records["mass_dirty_exit"][0]
    probes = records["mass_dirty_readiness"]
    require(final["status"] == "PASS" and type(final["readiness_samples"]) is int and
            final["readiness_samples"] > 0 and final["readiness_interval_ms"] == LIMITS["readiness_interval_seconds"] * 1000 and
            final["readiness_request_deadline_ms"] == LIMITS["readiness_request_deadline_ms"], "readiness evidence missing")
    require(len(probes) == final["readiness_samples"], "readiness observations missing")
    fields = ("trigger_monotonic_seconds", "drain_monotonic_seconds", "resume_monotonic_seconds", "fold_monotonic_seconds")

    def valid_seconds(value):
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0

    for index, probe in enumerate(probes):
        require(type(probe["sequence"]) is int and probe["sequence"] == index + 1, "readiness sequence changed")
        # Slow and failed samples are evidence for the readiness bars, not driver failures.
        require(probe["request_deadline_ms"] == LIMITS["readiness_request_deadline_ms"] and
                (probe["status"] is None or type(probe["status"]) is int) and
                (probe["phase"] is None or type(probe["phase"]) is str) and
                (probe["status"] == 200 or probe["phase"] is not None), "readiness sample/deadline changed")
        elapsed, start, end = [probe[key] for key in ("elapsed_seconds", "started_monotonic_seconds", "finished_monotonic_seconds")]
        if correctness:
            require(elapsed is start is end is None, "correctness mode published readiness timing")
        else:
            require(all(valid_seconds(value) for value in (elapsed, start, end)) and
                    0 <= end - start, "readiness clock failed")
            if index:
                previous = probes[index - 1]
                require(previous["finished_monotonic_seconds"] <= start, "readiness clock order changed")
                require(start - previous["started_monotonic_seconds"] <= LIMITS["readiness_max_gap_seconds"],
                        "readiness sampling gap exceeded frozen bound")
    coverage = []
    for operation in operations:
        times = [operation[key] for key in fields]
        if correctness:
            require(all(value is None for value in times), "correctness mode published phase timing")
            coverage.append({"sample_count": None, "max_start_gap_seconds": None})
            continue
        require(all(valid_seconds(value) for value in times) and times == sorted(times), "invalid readiness phase clocks")
        trigger, drain, resume, fold = times
        for name, duration in (("trigger_to_drain_seconds", drain - trigger),
                               ("drain_to_resume_seconds", resume - drain),
                               ("resume_to_observed_fold_seconds", fold - resume),
                               ("trigger_to_fold_seconds", fold - trigger)):
            require(math.isclose(operation[name], duration, abs_tol=1e-6), "phase clock/duration mismatch")
        before = [index for index, probe in enumerate(probes) if probe["finished_monotonic_seconds"] <= trigger]
        after = [index for index, probe in enumerate(probes) if probe["started_monotonic_seconds"] >= fold]
        require(before and after, "readiness probes do not bracket the full trigger-to-fold interval")
        selected = probes[before[-1]:after[0] + 1]
        gaps = [right["started_monotonic_seconds"] - left["started_monotonic_seconds"]
                for left, right in zip(selected, selected[1:])]
        require(gaps and max(gaps) <= LIMITS["readiness_max_gap_seconds"], "readiness interval coverage incomplete")
        coverage.append({"sample_count": len(selected), "max_start_gap_seconds": max(gaps)})
    return coverage


def validate_leg(leg, manifest, row):
    require(row["config_check_exit"] == 0 and (leg / "config-check.log").is_file(), "actual strict config validation missing")
    require(row["daemon_exit"] == row["harness_exit"] == 0, "process teardown did not succeed")
    raw_files = {path.name for path in leg.iterdir() if path.is_file() and path.name != "result.json"}
    require(type(row.get("raw_sha256")) is dict and set(row["raw_sha256"]) == raw_files, "raw evidence hash roster differs")
    for name, expected in row["raw_sha256"].items():
        require(Path(name).name == name and digest(leg / name) == expected, "raw evidence changed")
    require(row.get("snapshot_failure_counts") == snapshot_failure_counts(leg / "ordinary-snapshot-failures.jsonl", manifest["receivers"]),
            "ordinary snapshot failure counts differ")
    validate_fixture(leg / "fixture", json.loads((leg / "fixture.sha256.json").read_text()))
    records = harness_records(leg / "harness.log")
    coverage = readiness_coverage(records, row["operations"], manifest["correctness_only"])
    ready = records["mass_dirty_ready"][0]
    require(ready["family_keys"] == manifest["family_keys"] and ready["receivers"] == manifest["receivers"], "raw wire shape differs")
    require(all(ready[name] == manifest["wire_stimulus"][name] for name in
                ("batch_size", "origin_cardinality", "baseline_eor_messages", "receiver_receive_buffer_bytes")),
            "native wire stimulus differs")
    expected_bitmap = manifest["receivers"] * sum((value + 63) // 64 * 8 * 3 for value in manifest["family_keys"])
    require(ready["bitmap_bytes"] == expected_bitmap and ready["correctness_only"] is manifest["correctness_only"], "bitmap/correctness boundary changed")
    initial = json.loads((leg / "neighbors-initial.json").read_text())
    identities = [(peer(index), initial[index - 1]["group"]) for index in range(1, manifest["receivers"] + 1)]
    require(len(initial) == manifest["receivers"] and len({group for _, group in identities}) == 1, "initial group cohort differs")
    require([(item["peer"], item["group"]) for item in initial] == identities and all(item["pending"] is False and item["group"].startswith("group:") for item in initial), "initial group/clean evidence differs")
    validate_source_witness(json.loads((leg / "source-initial.json").read_text()))
    initial_metrics = (leg / "metrics-initial.prom").read_text()
    regroup = metric(initial_metrics, "bgp_update_group_regroups_total")
    initial_causes = fallback(initial_metrics)
    require(row["fallback_initial"] == initial_causes, "startup fallback disclosure differs")
    if manifest["cohort"] == "no-refusal":
        require(not any(initial_causes.values()), "no-refusal startup entered conservative fallback")
    initial_charge = recovery_charge(initial_metrics)
    require(initial_charge["entries"] == 0 and row["recovery_initial"] == initial_charge, "initial recovery charge differs")
    previous_peak = initial_charge["peak_bytes"]
    previous_causes = initial_causes
    full_log = (leg / "daemon.log").read_bytes()
    previous_log_end = 0
    for index, generation in enumerate(("b", "a")):
        before_metrics = (leg / f"metrics-before-{generation}.prom").read_text()
        require(metric(before_metrics, "bgp_update_group_regroups_total") == regroup, "group regrouped")
        operation_causes = fallback(before_metrics)
        fallback_delta(previous_causes, operation_causes)
        require(row["operations"][index]["fallback_before"] == operation_causes, "operation fallback baseline differs")
        if manifest["cohort"] == "no-refusal":
            require(not any(operation_causes.values()), "no-refusal cell entered conservative fallback before churn")
        previous_causes = operation_causes
        require(row["operations"][index]["readiness_coverage"] == coverage[index], "readiness coverage derivation differs")
        wire = records["mass_dirty_complete"][index]
        require(wire["generation"] == generation and wire["receivers"] == manifest["receivers"] and wire["exact_fold"] is True and wire["sessions_continuous"] is True, "wire generation/fold changed")
        require(wire["withdrawals"] == manifest["receivers"] * manifest["withdrawals_per_receiver"], "exact withdrawal duties differ")
        require(all(row["operations"][index][key] == value for key, value in wire.items()), "derived convergence does not match wire record")
        operation_log, window = operation_log_slices(full_log, row["operations"][index].get("daemon_log_bytes"), previous_log_end)
        previous_log_end = row["operations"][index]["daemon_log_bytes"]["end"]
        require((leg / f"daemon-operation-{generation}.jsonl").read_bytes() == operation_log, "operation log slice differs")
        require((leg / f"daemon-window-{generation}.jsonl").read_bytes() == window, "post-resume log slice differs")
        receipts = dirty_receipts(window.decode(), manifest["receivers"])
        require(receipts == json.loads((leg / f"dirty-receipts-{generation}.json").read_text()), "dirty receipt derivation differs")
        require(records["mass_dirty_paused"][index] == {"generation": generation, "receivers": manifest["receivers"]},
                "pause receipt differs")
        sent = records["mass_dirty_sent"][index]
        require(sent["generation"] == generation and sent["family_keys"] == manifest["family_keys"] and
                sent["writer_drained"] is True and
                all(sent[name] == manifest["wire_stimulus"]["origin_cardinality"] for name in
                    ("announcement_messages", "eor_messages", "origin_cardinality")) and
                sent["drained_monotonic_seconds"] == row["operations"][index]["drain_monotonic_seconds"],
                "source churn/drain receipt differs")
        validate_held_witness(json.loads((leg / f"neighbors-paused-{generation}.json").read_text()),
                              identities, manifest["correctness_only"], row["operations"][index])
        peers = json.loads((leg / f"neighbors-settled-{generation}.json").read_text())
        require([(item["peer"], item["group"]) for item in peers] == identities and
                all(item["pending"] is False for item in peers), "settled group witness differs")
        validate_source_witness(json.loads((leg / f"source-settled-{generation}.json").read_text()))
        for phase in ("paused", "settled"):
            metrics = (leg / f"metrics-{phase}-{generation}.prom").read_text()
            require(metric(metrics, "bgp_update_group_regroups_total") == regroup, "group regrouped")
            causes = fallback(metrics)
            fallback_delta(previous_causes, causes)
            previous_causes = causes
            charge = recovery_charge(metrics)
            require(row["operations"][index][f"recovery_{phase}"] == charge, "recovery charge derivation differs")
            if phase == "settled":
                require(all(charge[key] == initial_charge[key] for key in ("entries", "bytes")),
                        "settled recovery charge did not return to empty baseline")
            else:
                require(charge["entries"] > 0 and charge["bytes"] > initial_charge["bytes"],
                        "held dirty recovery proof was not retained")
                if manifest["cohort"] == "no-refusal":
                    require(charge["entries"] == manifest["receivers"] * sum(manifest["family_keys"]),
                            "no-refusal held proof does not cover the full initial fleet")
            require(charge["peak_bytes"] >= previous_peak, "recovery reservation peak regressed")
            previous_peak = charge["peak_bytes"]
        deltas = fallback_delta(operation_causes, causes)
        require(row["operations"][index]["fallback_deltas"] == deltas, "fallback derivation differs")
        if manifest["cohort"] == "no-refusal" or (not manifest["correctness_only"] and row["arm"] == "candidate"):
            require(not any(deltas.values()), "indexed/no-refusal cohort refused proof")
        if manifest["correctness_only"]:
            require(all(row["operations"][index][name] is None for name in ("trigger_to_fold_seconds", "trigger_to_drain_seconds", "drain_to_resume_seconds", "resume_to_observed_fold_seconds", "resume_to_fold_p50_seconds", "resume_to_fold_max_seconds")), "correctness mode published timing")
        else:
            operation = row["operations"][index]
            parts = [operation[name] for name in ("trigger_to_drain_seconds", "drain_to_resume_seconds", "resume_to_observed_fold_seconds")]
            require(all(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0 for value in parts), "invalid timing interval")
            require(math.isclose(sum(parts), operation["trigger_to_fold_seconds"], abs_tol=1e-6), "whole capture interval excludes work")
    if manifest["cohort"] == "cap-pressure" and not manifest["correctness_only"] and row["arm"] == "flat":
        require(any(operation["fallback_deltas"]["daemon_limit"] > 0 for operation in row["operations"]), "pressure control never reached cap")
    if not manifest["correctness_only"]:
        with (leg / "memory.csv").open() as stream:
            samples = list(csv.DictReader(stream))
        require(samples, "no daemon memory samples")
        peaks = [int(sample["peak_bytes"]) for sample in samples if int(sample["monotonic_ns"]) <= row["memory_after"]["boundary_monotonic_ns"]]
        require(peaks and max(peaks) <= row["memory_after"]["memory.peak"], "sampled/whole-scope peak boundary differs")
        for key, maximum in (("memory_after", LIMITS["daemon_bytes"]), ("harness_memory_after", LIMITS["harness_bytes"])):
            memory = row[key]
            require(memory["memory.max"] == maximum and memory["memory.peak"] >= memory["memory.current"], "memory cap/peak changed")
            require(memory["memory.swap.max"] == memory["memory.swap.peak"] == memory["memory.swap.current"] == 0, "swap invalidates receipt")
            require(all(int(memory["events"][name]) == 0 for name in ("oom", "oom_kill", "oom_group_kill")), "OOM invalidates receipt")
    return records["mass_dirty_readiness"]


def percentile(values, fraction):
    # Nearest rank: always an observed sample, never an interpolation.
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def post_sent_elapsed(probes, operations):
    # The window each comparative bar judges: source writer drained to observed fold.
    windows = [(operation["drain_monotonic_seconds"], operation["fold_monotonic_seconds"]) for operation in operations]
    values = [probe["elapsed_seconds"] for probe in probes
              if any(start <= probe["started_monotonic_seconds"] <= end for start, end in windows)]
    require(values, "no readiness samples after sent")
    return values


def readiness_summary(probes, operations):
    """Per-leg readiness distribution and its absolute-ceiling failures."""
    failed = sum(probe["status"] != 200 or probe["phase"] is not None for probe in probes)
    summary = {"samples": len(probes), "non_200_or_failed": failed}
    failures = [f"{failed} non-200 or failed /readyz samples"] if failed else []
    elapsed = [probe["elapsed_seconds"] for probe in probes]
    if None in elapsed:
        return summary, failures
    run = longest = 0
    for value in elapsed:
        run = run + 1 if value > LIMITS["readiness_slow_seconds"] else 0
        longest = max(longest, run)

    def distribution(values):
        return {"p50_ms": percentile(values, .5) * 1000, "p99_ms": percentile(values, .99) * 1000,
                "max_ms": max(values) * 1000}

    post_sent = post_sent_elapsed(probes, operations)
    summary.update(distribution(elapsed), over_250ms=sum(value > LIMITS["readiness_slow_seconds"] for value in elapsed),
                   longest_run_over_250ms=longest, post_sent={"samples": len(post_sent), **distribution(post_sent)})
    if max(elapsed) > LIMITS["readiness_ceiling_seconds"]:
        failures.append(f"/readyz max {max(elapsed) * 1000:.1f} ms over 1 s")
    if longest >= LIMITS["readiness_slow_run"]:
        failures.append(f"{longest} consecutive /readyz samples over 250 ms")
    return summary, failures


def readiness_comparison(arms):
    """Pooled candidate post-sent readiness against the flat control."""
    detail, failures = {}, []
    for name, fraction in (("p99", .99), ("max", 1.0)):
        control, candidate = percentile(arms["flat"], fraction), percentile(arms["candidate"], fraction)
        limit = control * LIMITS[f"readiness_{name}_relative"] + LIMITS[f"readiness_{name}_absolute_seconds"]
        detail[f"{name}_ms"] = {"flat": control * 1000, "candidate": candidate * 1000, "limit": limit * 1000}
        if candidate > limit:
            failures.append(f"candidate post-sent /readyz {name} {candidate * 1000:.1f} ms over {limit * 1000:.1f} ms bar")
    return detail, failures


def finalize(root):
    root = Path(root)
    try:
        require((root / "execution.exit").read_text().strip() == "0", "driver failed or was interrupted")
        driver_status = (root / "driver.exit").read_text().strip()
        result = analyze(root)
        require(driver_status == ("1" if result["status"] == "FAIL" else "0"),
                "driver exit differs from replayed acceptance verdict")
        return result
    except (ValueError, OSError, KeyError, TypeError, IndexError) as error:
        result = {"status": "INVALID", "reason": str(error), "release_soak_qualified": False}
        if root.is_dir():
            write_json(root / "verdict.json", result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    initial = sub.add_parser("init")
    initial.add_argument("output")
    initial.add_argument("--head", required=True)
    initial.add_argument("--profile", choices=("full-uc", "full-vpn"), required=True)
    initial.add_argument("--cohort", choices=("no-refusal", "cap-pressure"), required=True)
    initial.add_argument("--daemon-cpus", required=True)
    initial.add_argument("--harness-cpus", required=True)
    initial.add_argument("--correctness-only", action="store_true")
    derive = sub.add_parser("derive-flat")
    derive.add_argument("source")
    derive.add_argument("metadata")
    cell = sub.add_parser("run-cell")
    cell.add_argument("output")
    cell.add_argument("--arm", required=True)
    cell.add_argument("--index", type=int, required=True)
    for name in ("daemon", "harness", "rbgp"):
        cell.add_argument("--" + name, required=True)
    binaries = sub.add_parser("check-binaries")
    binaries.add_argument("output")
    seal = sub.add_parser("seal-build")
    seal.add_argument("output")
    verdict = sub.add_parser("analyze")
    verdict.add_argument("output")
    final = sub.add_parser("finalize")
    final.add_argument("output")
    args = parser.parse_args()
    if args.command == "init":
        init(args)
    elif args.command == "derive-flat":
        derive_flat(args.source, args.metadata)
    elif args.command == "run-cell":
        run_cell(args)
    elif args.command == "check-binaries":
        print(json.dumps(verified_binaries(args.output)))
    elif args.command == "seal-build":
        seal_build(args.output)
    else:
        result = finalize(args.output) if args.command == "finalize" else analyze(args.output)
        print(json.dumps(result))
        return int(result["status"] in ("FAIL", "INVALID"))
    return 0


if __name__ == "__main__":
    def canceled(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, canceled)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"mass-dirty qualification: {error}", file=sys.stderr)
        sys.exit(1)
