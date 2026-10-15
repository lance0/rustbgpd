#!/usr/bin/env python3
"""Strict instrumentation and evidence checks for the recovery memory receipt."""

from __future__ import annotations

import argparse
import hashlib
import difflib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

BASELINE = "c862af9338aa828b7462f3cf85781f63b0e79fe8"
INTERMEDIATE = "bdb7bc34dfe0e6a66fc8c0f1d56d3e57184dea00"
SCAN_SCHEMA = "rustbgpd.recovery-scan.v2"
SCAN_PROFILES = {"full-uc": 1_230_000, "full-vpn": 1_230_000, "evpn-soak": 37_500}
SCAN_DISPATCH = (
    "mod recovery_scan;\n",
    '    if mode == "recovery-scan" {\n        recovery_scan::main(&args[2..]);\n        return;\n    }\n',
)
CELLS = ("dataset-reevaluate", "peer-down", "widen", "unsynchronized-dirty")
FAMILIES = ("ipv4_unicast", "ipv6_unicast", "vpnv4", "vpnv6")
PROFILES = {
    "ipv4-100k": ((100000, 0, 0, 0), (0, 0, 0, 0)),
    "full-uc": ((1000000, 230000, 0, 0), (0, 0, 0, 0)),
    "full-vpn": ((0, 0, 1000000, 230000), (0, 0, 100000, 23000)),
    "mixed-widen": ((1000000, 230000, 0, 0), (0, 0, 100000, 23000)),
    "smoke-uc": ((160, 40, 0, 0), (0, 0, 0, 0)),
    "smoke-vpn": ((0, 0, 160, 40), (0, 0, 16, 4)),
    "smoke-mixed": ((160, 40, 0, 0), (0, 0, 16, 4)),
}


def campaign_cases(
    phase: str, profiles: list[str] | None = None, selected_cell: str = "all"
) -> list[dict]:
    require(phase in ("pilot", "qualified"), "unknown campaign phase")
    require(selected_cell in ("all", *CELLS), "unknown campaign cell")
    selected = (
        profiles
        if profiles is not None
        else (
            ["full-uc", "full-vpn"]
            if phase == "pilot"
            else ["ipv4-100k", "full-uc", "full-vpn", "mixed-widen"]
        )
    )
    require(
        isinstance(selected, list)
        and bool(selected)
        and len(selected) == len(set(selected))
        and set(selected) <= {"ipv4-100k", "full-uc", "full-vpn", "mixed-widen"},
        "invalid campaign profiles",
    )
    cases = []
    for profile in selected:
        clients = 4 if phase == "pilot" else (256 if profile == "ipv4-100k" else 100)
        cells = ["widen"] if profile == "mixed-widen" else ["dataset-reevaluate", "peer-down"]
        if profile == "full-vpn" and phase == "qualified":
            cells.append("widen")
        if profile in ("full-uc", "full-vpn"):
            cells.append("unsynchronized-dirty")
        require(
            selected_cell == "all" or selected_cell in cells, "unsupported profile/cell selection"
        )
        for cell in cells:
            if selected_cell != "all" and cell != selected_cell:
                continue
            cases.append({"profile": profile, "clients": clients, "cell": cell})
    require(bool(cases), "empty campaign selection")
    return cases


PHASES = ("population_ready", "retained", "operation_end", "settled")
GAUGES = (
    "bgp_update_group_recovery_entries",
    "bgp_update_group_recovery_bytes",
    "bgp_update_group_recovery_peak_bytes",
)
SCALARS = (
    "memory.current",
    "memory.peak",
    "memory.swap.max",
    "memory.swap.current",
    "memory.swap.peak",
)
FILES = (*SCALARS, "memory.max", "memory.stat", "memory.events")
INSTRUMENT_INPUTS = (
    "bench/scale/rrharness/src/main.rs",
    "bench/scale/rrharness/src/recovery_memory.rs",
    "bench/scale/rrharness/Cargo.toml",
    "bench/scale/compare-recovery-memory.sh",
    "bench/scale/recovery_memory.py",
    "bench/scale/cgroup-memory.sh",
    "bench/scale/provenance.sh",
)
VARIANT = """    TestQueryOutboundHealth {
        /// Response channel: dirty peers, forced peers, group-dirty members,
        /// group tombstones, regroup baselines, and carried extra-withdraw
        /// residue, respectively.
        reply: oneshot::Sender<(usize, usize, usize, usize, usize, usize)>,
    },"""
HANDLER = """            RibUpdate::TestQueryOutboundHealth { reply } => {
                let group_dirty = self
                    .group_ribs
                    .values()
                    .map(|group| group.dirty_members.len())
                    .sum();
                let group_tombstones = self
                    .group_ribs
                    .values()
                    .map(|group| group.tombstones.len() + group.vpn_tombstones.len())
                    .sum();
                let _ = reply.send((
                    self.dirty_peers.len(),
                    self.force_outbound_peers.len(),
                    group_dirty,
                    group_tombstones,
                    self.pending_regroup_baseline.len(),
                    self.pending_extra_withdraws.len(),
                ));
            }"""

RIB_UPDATE_DECLARATION = (
    "/// Messages sent from peer sessions to the RIB manager.\npub enum RibUpdate {"
)
BENCH_ACKNOWLEDGEMENT = """// The actor input is borrowed across awaits, so its owned bench receiver needs Sync.
#[cfg(feature = "bench-internals")]
type BenchCreditAcknowledgement = std::sync::Mutex<std::sync::mpsc::Receiver<Result<(), String>>>;"""

BENCH_VARIANT = """    /// Benchmark-only transaction: grant one owned receiver credit, then run
    /// the ordinary VPN receipt handler without an intervening retry timer.
    #[cfg(feature = "bench-internals")]
    BenchVpnAdmissionWithCredit {
        /// Each receiver acknowledges exactly one harmless queue filler drain.
        grants: Vec<(oneshot::Sender<()>, BenchCreditAcknowledgement)>,
        /// Must be an ordinary `VpnRoutesReceived` input, never a nested transaction.
        update: Box<RibUpdate>,
        /// Reply after the ordinary handler has observed queue admission.
        reply: oneshot::Sender<Result<(), RibCommandError>>,
    },"""
BENCH_HANDLER = """            #[cfg(feature = "bench-internals")]
            RibUpdate::BenchVpnAdmissionWithCredit {
                grants,
                update,
                reply,
            } => {
                let result = (|| {
                    if !matches!(&*update, RibUpdate::VpnRoutesReceived { .. }) {
                        return Err(crate::update::RibCommandError::internal(
                            "benchmark credit requires a VPN receipt",
                        ));
                    }
                    for (grant, acknowledged) in grants {
                        grant.send(()).map_err(|()| {
                            crate::update::RibCommandError::internal("benchmark receiver closed")
                        })?;
                        // Benchmark consumers run on a separate runtime. This bounded
                        // one-shot wait prevents a retry timer stealing the granted credit.
                        acknowledged
                            .lock()
                            .map_err(|error| {
                                crate::update::RibCommandError::internal(error.to_string())
                            })?
                            .recv_timeout(std::time::Duration::from_secs(30))
                            .map_err(|error| {
                                crate::update::RibCommandError::internal(error.to_string())
                            })?
                            .map_err(crate::update::RibCommandError::internal)?;
                    }
                    self.handle_update(*update);
                    Ok(())
                })();
                let _ = reply.send(result);
            }"""


class InvalidReceipt(ValueError):
    """An input is insufficient to qualify the fixed memory receipt."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidReceipt(message)


def uint(value: object, name: str) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0,
        f"missing or invalid {name}",
    )
    return value


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def instrument_observer(tree: Path) -> None:
    """Freeze two observer gates and one feature-only atomic credit transaction."""
    changes = []
    for name, anchor, indent in (
        ("crates/rib/src/update.rs", VARIANT, "    "),
        ("crates/rib/src/manager/mod.rs", HANDLER, "            "),
    ):
        path = tree / name
        text = path.read_text(encoding="utf-8")
        require(text.count(anchor) == 1, f"unexpected observer body in {name}")
        old = indent + "#[cfg(test)]\n" + anchor
        new = indent + '#[cfg(any(test, feature = "bench-internals"))]\n' + anchor
        require(text.count(old) + text.count(new) == 1, f"unexpected observer gate in {name}")
        text = text.replace(old, new)
        if name.endswith("update.rs"):
            require(text.count(RIB_UPDATE_DECLARATION) == 1, "unexpected RibUpdate declaration")
            installed = "BenchVpnAdmissionWithCredit" in text
            has_alias = "type BenchCreditAcknowledgement" in text
            require(
                installed == has_alias
                and (not has_alias or text.count(BENCH_ACKNOWLEDGEMENT) == 1),
                "unexpected credit acknowledgement alias",
            )
            if not installed:
                text = text.replace(
                    RIB_UPDATE_DECLARATION, BENCH_ACKNOWLEDGEMENT + "\n\n" + RIB_UPDATE_DECLARATION
                )
        seam = BENCH_VARIANT if name.endswith("update.rs") else BENCH_HANDLER
        if "BenchVpnAdmissionWithCredit" in text:
            require(text.count(seam) == 1, f"unexpected credit transaction body in {name}")
        else:
            text = text.replace(anchor, anchor + "\n" + seam)
        changes.append((path, text))
    # Validate both before changing either file.
    for path, text in changes:
        path.write_text(text, encoding="utf-8")


def key_values(text: str, name: str) -> dict[str, int]:
    result = {}
    for line in text.splitlines():
        words = line.split()
        require(
            len(words) == 2 and words[1].isdigit() and words[0] not in result, f"malformed {name}"
        )
        result[words[0]] = int(words[1])
    return result


def scope_values(path: Path) -> dict[str, int]:
    values = {}
    for name in SCALARS:
        text = (path / name).read_text(encoding="utf-8").strip()
        require(text.isdigit(), f"missing numeric cgroup capability {name}")
        values[name] = int(text)
    # memory.max may be unbounded; retain it but do not confuse it with swap.max.
    limit = (path / "memory.max").read_text(encoding="utf-8").strip()
    require(limit == "max" or (limit.isdigit() and int(limit) > 0), "invalid memory.max")
    require(values["memory.swap.max"] == 0, "missing swap fence")
    require(
        values["memory.swap.current"] == values["memory.swap.peak"] == 0,
        "actual swap invalidates the receipt",
    )
    require(values["memory.peak"] >= values["memory.current"], "invalid memory.peak")
    for name, keys in (
        ("memory.stat", ("anon", "file", "file_mapped")),
        ("memory.events", ("oom", "oom_kill", "oom_group_kill")),
    ):
        parsed = key_values((path / name).read_text(encoding="utf-8"), name)
        for key in keys:
            require(key in parsed, f"missing {name} {key}")
            require(name != "memory.events" or parsed[key] == 0, "OOM invalidates the receipt")
            values[f"{name}.{key}"] = parsed[key]
    return values


def snapshot_scope(path: Path, output: Path) -> dict[str, int]:
    output.mkdir(parents=True, exist_ok=False)
    # Keep every raw file even when capability/OOM validation fails.
    for name in FILES:
        source = path / name
        if source.is_file():
            shutil.copyfile(source, output / name)
    values = scope_values(path)
    write_json(output / "values.json", values)
    return values


def file_digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def proc_identity(pid: int, *, executable_digest: bool = False) -> dict[str, object]:
    stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    fields = stat.rsplit(")", 1)[1].split()
    identity = {
        "pid": pid,
        "parent_pid": int(fields[1]),
        "start_ticks": int(fields[19]),
        "cgroup": Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8"),
        "executable": os.readlink(f"/proc/{pid}/exe"),
    }
    if executable_digest:
        identity["exe_sha256"] = file_digest(Path(f"/proc/{pid}/exe"))
    return identity


def check_ownership(sample: dict, expected: dict[int, dict], cgroup: str) -> None:
    """Compare raw membership against frozen process/start identities."""
    members = sample["members"]
    require(
        [int(line) for line in sample["cgroup_procs_raw"].splitlines()] == members,
        "scope membership raw evidence differs",
    )
    require(set(members) == set(expected), "foreign or missing scoped process")
    require(len(members) == len(set(members)), "duplicate scope process identity")
    actual = {row["pid"]: row for row in sample["processes"]}
    require(
        set(actual) == set(expected) and len(sample["processes"]) == len(expected),
        "incomplete scope process identities",
    )
    for pid, prior in expected.items():
        row = actual[pid]
        require(
            row["start_ticks"] == prior["start_ticks"]
            and row["executable"] == prior["executable"]
            and row["cgroup"].strip() == "0::" + cgroup.removeprefix("/sys/fs/cgroup"),
            "scoped process identity or membership changed",
        )
    require(
        all(
            not row["procs"].strip() and not row["threads"].strip() for row in sample["descendants"]
        ),
        "populated descendant cgroup",
    )


def require_workload_exit(workload: subprocess.Popen) -> None:
    """Distinguish a disappearing exited child from a live child leaving its scope."""
    if workload.poll() is None:
        try:
            status = workload.wait(timeout=0.25)
        except subprocess.TimeoutExpired as error:
            raise InvalidReceipt("missing scoped workload did not exit") from error
        require(isinstance(status, int), "missing scoped workload lacks terminal status")


def capture_ownership(
    cgroup: Path,
    output: Path,
    expected: dict[int, dict],
    phase: str,
    workload: subprocess.Popen | None = None,
    previous: dict | None = None,
) -> dict:
    sample = {
        "phase": phase,
        "cgroup_procs_raw": "",
        "members": [],
        "processes": [],
        "descendants": [],
    }

    def read_membership() -> list[int]:
        raw = (cgroup / "cgroup.procs").read_text(encoding="utf-8")
        members = [int(line) for line in raw.splitlines()]
        sample.update({"cgroup_procs_raw": raw, "members": members, "descendants": []})
        for path in sorted(cgroup.rglob("cgroup.procs")):
            if path.parent == cgroup:
                continue
            sample["descendants"].append(
                {
                    "path": str(path.parent.relative_to(cgroup)),
                    "procs": path.read_text(encoding="utf-8"),
                    "threads": path.with_name("cgroup.threads").read_text(encoding="utf-8"),
                }
            )
        required = set(expected)
        if workload is not None:
            required.discard(workload.pid)
        require(required <= set(members) <= set(expected), "foreign or missing scoped process")
        require(
            all(
                not row["procs"].strip() and not row["threads"].strip()
                for row in sample["descendants"]
            ),
            "populated descendant cgroup",
        )
        return members

    try:
        members = read_membership()
        if workload is not None and workload.pid not in members:
            require_workload_exit(workload)
            expected = {pid: row for pid, row in expected.items() if pid != workload.pid}
            sample["phase"] = "after"
            members = read_membership()
        try:
            sample["processes"] = [proc_identity(pid) for pid in members]
        except FileNotFoundError:
            # The one owned child may exit between membership and its stat read.
            if workload is None:
                raise
            require_workload_exit(workload)
            expected = {pid: row for pid, row in expected.items() if pid != workload.pid}
            sample["phase"] = "after"
            members = read_membership()
            sample["processes"] = [proc_identity(pid) for pid in members]
        check_ownership(sample, expected, str(cgroup))
    finally:

        def stable_view(row: dict) -> dict:
            return {
                "phase": row["phase"],
                "members": sorted(row["members"]),
                "processes": sorted(row["processes"], key=lambda process: process["pid"]),
                "descendants": row["descendants"],
            }

        # Validate every poll, retaining raw changes instead of charging an
        # ownership log whose page-cache growth depends on operation duration.
        if previous is None or stable_view(sample) != stable_view(previous):
            with (output / "ownership.jsonl").open("a", encoding="utf-8") as log:
                log.write(json.dumps(sample, sort_keys=True) + "\n")
    return sample


def run_scope(
    binary: Path,
    output: Path,
    cell: str,
    cgroup: Path,
    expected_digest: str,
    profile: str,
    clients: int,
    scan: bool = False,
    shuffled_old: bool = False,
) -> None:
    """Run inside the already fenced scope; capture before its owner exits."""
    output.mkdir(parents=True, exist_ok=True)
    require(bool(re.fullmatch(r"[0-9a-f]{64}", expected_digest)), "invalid expected binary digest")
    checker = proc_identity(os.getpid(), executable_digest=True)
    launcher = proc_identity(os.getppid(), executable_digest=True)
    require(
        launcher["executable"] == str(Path(shutil.which("bash")).resolve()),
        "scoped launcher is not Bash",
    )
    require(
        checker["executable"] == str(Path(sys.executable).resolve()), "scope checker is not Python"
    )
    write_json(output / "scope-process.json", checker)
    write_json(output / "launcher-process.json", launcher)
    owned = {checker["pid"]: checker, launcher["pid"]: launcher}
    (output / "cgroup-path.txt").write_text(str(cgroup) + "\n", encoding="utf-8")
    snapshot_scope(cgroup, output / "before")
    capture_ownership(cgroup, output, owned, "before")
    if scan:
        require(profile in SCAN_PROFILES and cell == "capture-scan", "invalid scan profile")
        command = [str(binary), "recovery-scan", profile]
        if shuffled_old:
            command.append("--shuffled-old")
    else:
        require(not shuffled_old, "shuffled OLD is only valid for component scans")
        require(profile in PROFILES and clients > 0, "invalid workload profile")
        command = [str(binary), "recovery-memory", cell, str(clients), profile]
    write_json(output / "command.json", command)
    env = dict(os.environ, RRHARNESS_RECOVERY_CGROUP=str(cgroup))
    status = {"exit": None, "timeout": False, "cgroup_valid": False, "ownership_valid": False}
    try:
        with (output / "harness.log").open("w", encoding="utf-8") as log:
            with subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT) as child:
                try:
                    workload = proc_identity(child.pid, executable_digest=True)
                    write_json(output / "binary-process.json", workload)
                    require(
                        workload["exe_sha256"] == expected_digest, "executed binary digest mismatch"
                    )
                    require(
                        workload["parent_pid"] == checker["pid"], "workload has a foreign parent"
                    )
                    active = owned.copy()
                    active[child.pid] = workload
                    deadline = time.monotonic() + 1830
                    previous = capture_ownership(cgroup, output, active, "active", child)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(command, 1830)
                        try:
                            status["exit"] = child.wait(timeout=min(0.25, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            previous = capture_ownership(
                                cgroup, output, active, "active", child, previous
                            )
                    capture_ownership(cgroup, output, owned, "after")
                    status["ownership_valid"] = True
                except subprocess.TimeoutExpired:
                    status["timeout"] = True
                    child.terminate()
                    try:
                        child.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
                    status["exit"] = child.returncode
                except BaseException:
                    # Identity capture must not leave a started cell running.
                    if child.poll() is None:
                        child.kill()
                    child.wait()
                    raise
    finally:
        try:
            snapshot_scope(cgroup, output / "after")
            status["cgroup_valid"] = True
        finally:
            write_json(output / "status.json", status)
    require(status["exit"] == 0 and not status["timeout"], "harness did not complete")


def validate_log(
    path: Path, role: str, cell: str, clients: int = 256, profile: str = "ipv4-100k"
) -> dict[str, object]:
    samples, completed, identities, unsynchronized = [], [], [], []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("recovery_sample "):
            samples.append(json.loads(line.removeprefix("recovery_sample ")))
        elif line.startswith("recovery_complete "):
            completed.append(json.loads(line.removeprefix("recovery_complete ")))
        elif line.startswith("recovery_identity "):
            identities.append(json.loads(line.removeprefix("recovery_identity ")))
        elif line.startswith("recovery_unsynchronized "):
            require(len(samples) == 1 and not completed, "unsynchronized pass outside retained preparation")
            unsynchronized.append(json.loads(line.removeprefix("recovery_unsynchronized ")))
    require(
        [row.get("phase") for row in samples] == list(PHASES),
        "missing, duplicate or unordered phase barriers",
    )
    require(len(completed) == 1, "missing completion barrier")
    require(len(identities) == 1, "missing workload identity")
    identity = identities[0]
    require(
        uint(identity.get("pid"), "workload PID") > 0
        and uint(identity.get("start_ticks"), "workload start time") > 0,
        "invalid workload identity",
    )
    require(
        isinstance(identity.get("cgroup"), str)
        and identity["cgroup"].startswith("/sys/fs/cgroup/")
        and identity["cgroup"].endswith(".scope"),
        "workload is not in a scope",
    )
    require(
        bool(re.fullmatch(r"[0-9a-f]{40}", identity.get("source_sha", "")))
        and bool(re.fullmatch(r"[0-9a-f]{64}", identity.get("instrumentation_sha256", ""))),
        "missing compiled source/instrumentation identity",
    )
    require(profile in PROFILES and cell in CELLS and clients > 0, "unknown receipt shape")
    seed, additions = PROFILES[profile]
    additions = additions if cell == "widen" else (0, 0, 0, 0)
    pulse_family = next(f for f, n in enumerate(seed) if n)
    if cell == "unsynchronized-dirty":
        additions = tuple(clients if f == pulse_family else 0 for f in range(4))
        require(len(unsynchronized) == clients, "missing unsynchronized dirty pass barriers")
        for index, progress in enumerate(unsynchronized):
            paused = index + 1
            for name in ("pass", "clients", "dirty_peers", "group_dirty_members"):
                uint(progress.get(name), name)
            require(
                progress.get("pass") == index
                and progress.get("clients") == clients
                and progress.get("profile") == profile
                and progress.get("dirty_peers") == progress.get("group_dirty_members") == paused,
                "missing actual progressive dirty overlap",
            )
            for field, expected in (
                ("paused_families", tuple(paused * seed[f] + (paused * (paused - 1) // 2 if f == pulse_family else 0) for f in range(4))),
                ("active_families", tuple((clients - paused) * (seed[f] + (paused if f == pulse_family else 0)) for f in range(4))),
            ):
                values = progress.get(field)
                require(isinstance(values, dict) and set(values) == set(FAMILIES), "missing unsynchronized family inventory")
                for name, value in values.items():
                    uint(value, name)
                require(values == dict(zip(FAMILIES, expected)), "wrong unsynchronized actual receiver inventory")
    else:
        require(not unsynchronized, "unexpected unsynchronized pass barriers")
    require(cell != "widen" or sum(additions) > 0, "profile cannot widen")
    limits = tuple(a + b for a, b in zip(seed, additions))
    gauges_absent = role == "baseline"
    require(
        identity["source_sha"] == (BASELINE if role == "baseline" else INTERMEDIATE)
        if role in ("baseline", "intermediate")
        else identity["source_sha"] not in (BASELINE, INTERMEDIATE),
        "wrong role source identity",
    )
    previous_peak = 0
    for row in samples:
        require(
            row.get("schema") == "rustbgpd.recovery-memory.v2" and row.get("cell") == cell,
            "wrong sample schema or cell",
        )
        require(
            row.get("clients") == clients
            and row.get("profile") == profile
            and row.get("seed") == dict(zip(FAMILIES, seed))
            and row.get("additions") == dict(zip(FAMILIES, additions)),
            "wrong receipt shape",
        )
        require(row.get("receiver_queue_capacity") == 8, "wrong receiver queue capacity")
        require(
            row.get("receiver_bitmap_bytes") == clients * sum((n + 63) // 64 * 8 for n in limits),
            "unexpected receiver storage",
        )
        phase = row["phase"]
        families = row.get("families")
        require(
            isinstance(families, dict) and set(families) == set(FAMILIES),
            "missing exact family inventory",
        )
        for f, name in enumerate(FAMILIES):
            actual = families[name]
            present = uint(actual.get("present"), "family present")
            announces = uint(actual.get("announces"), "family announces")
            withdrawals = uint(actual.get("withdrawals"), "family withdrawals")
            target = (
                0
                if phase == "settled" and cell == "peer-down"
                else clients * (limits[f] if phase == "settled" else seed[f])
            )
            if cell == "unsynchronized-dirty" and phase in ("retained", "operation_end") and f == pulse_family:
                target += clients * (clients - 1) // 2
            require(present == target, "nonconverged exact family receiver inventory")
            require(
                withdrawals
                == (clients * seed[f] if phase == "settled" and cell == "peer-down" else 0),
                "withdrawal inventory mismatch or unchanged-policy flap",
            )
            require(
                announces >= max(target, clients * seed[f]),
                "population did not deliver all family routes",
            )
            if limits[f] == 0:
                require(announces == 0, "unexpected family announcement")
        for scalar, field in (
            ("folded_routes", "present"),
            ("announces", "announces"),
            ("withdrawals", "withdrawals"),
        ):
            require(
                uint(row.get(scalar), scalar) == sum(families[name][field] for name in FAMILIES),
                "nonconverged aggregate/family inventory mismatch",
            )
        dirty = clients if phase in ("retained", "operation_end") else 0
        require(
            row.get("dirty_peers") == row.get("group_dirty_members") == dirty,
            "missing actual simultaneous dirty overlap",
        )
        metrics = row.get("metrics")
        require(isinstance(metrics, dict), "missing metrics")
        for name, value in metrics.items():
            uint(value, name)
        causes = row.get("fallback_causes")
        require(
            isinstance(causes, dict)
            and set(causes)
            == {"peer_limit", "daemon_limit", "allocation_failure", "missing_proof"},
            "missing fixed fallback causes",
        )
        require(
            sum(uint(value, name) for name, value in causes.items())
            == metrics.get("bgp_update_group_recovery_fallback_total", 0),
            "fallback causes do not match the scalar total",
        )
        require(
            metrics.get("bgp_evpn_recovery_provenance_exhausted_total", 0) == 0,
            "unexpected EVPN recovery activation in the plain RR cell",
        )
        if gauges_absent:
            require(
                not any(name in metrics for name in GAUGES),
                "baseline unexpectedly includes candidate gauges",
            )
        else:
            for name in GAUGES:
                uint(metrics.get(name), name)
            if phase in ("population_ready", "settled"):
                require(metrics[GAUGES[0]] == 0, "recovery keys remain in a healthy phase")
            if phase == "settled":
                require(
                    metrics[GAUGES[1]] == samples[0]["metrics"][GAUGES[1]],
                    "settled recovery charge did not restore the initial empty-proof charge",
                )
        if role == "candidate":
            require(sum(causes.values()) == 0, "candidate budget/proof fallback disqualifies shape")
            if phase in ("retained", "operation_end"):
                require(
                    metrics[GAUGES[0]] == (
                        clients * sum(seed) + clients * (clients - 1) // 2
                        if cell == "unsynchronized-dirty" else clients * sum(limits)
                    ),
                    "candidate lacks complete admitted recovery proofs",
                )
        elif (
            role == "intermediate"
            and profile in ("full-uc", "full-vpn", "mixed-widen")
            and phase in ("retained", "operation_end")
        ):
            require(
                sum(causes.values()) > 0, "intermediate full-table refusal control did not refuse"
            )
        require("bgp_update_group_residue_entries" in metrics, "missing ordinary residue gauge")
        if phase == "settled":
            require(
                metrics["bgp_update_group_residue_entries"] == 0,
                "ordinary residue remains after settlement",
            )
        cg = row.get("cgroup")
        require(isinstance(cg, dict), "missing cgroup accounting")
        for name in (
            "memory.current",
            "memory.peak",
            "memory.swap.max",
            "memory.swap.current",
            "memory.swap.peak",
            "memory.stat.anon",
            "memory.stat.file",
            "memory.stat.file_mapped",
            "memory.events.oom",
            "memory.events.oom_kill",
            "memory.events.oom_group_kill",
        ):
            uint(cg.get(name), name)
        require(cg["memory.peak"] >= cg["memory.current"], "invalid phase peak")
        require(cg["memory.peak"] >= previous_peak, "decreasing phase memory peak")
        previous_peak = cg["memory.peak"]
        require(
            cg["memory.swap.current"] == cg["memory.swap.peak"] == 0,
            "phase swap invalidates the receipt",
        )
        require(cg["memory.swap.max"] == 0, "phase swap fence missing")
        require(
            all(cg[f"memory.events.{key}"] == 0 for key in ("oom", "oom_kill", "oom_group_kill")),
            "phase OOM invalidates the receipt",
        )
    terminal = (0, 0, 0, 0) if cell == "peer-down" else limits
    require(
        completed[0]
        == {
            "cell": cell,
            "profile": profile,
            "expected_families_per_receiver": dict(zip(FAMILIES, terminal)),
            "actual_receivers": clients,
        },
        "wrong terminal completion",
    )
    return {
        "cell": cell,
        "role": role,
        "profile": profile,
        "recovery_gauges": "absent-baseline" if gauges_absent else "required-present",
        "evpn_reset_counter": "present-inactive-zero"
        if "bgp_evpn_recovery_provenance_exhausted_total" in samples[0]["metrics"]
        else "absent",
        "workload_identity": identity,
        "unsynchronized_passes": len(unsynchronized),
        "samples": samples,
    }


def check_peak_coverage(before: dict, samples: list[dict], after: dict) -> None:
    # This runs even when a historical control failed its route/proof contract.
    # A failed route assertion never licenses invalid phase memory accounting.
    previous = before["memory.peak"]
    for row in samples:
        cg = row.get("cgroup")
        require(isinstance(cg, dict), "missing phase cgroup accounting")
        for name in (
            *SCALARS,
            "memory.events.oom",
            "memory.events.oom_kill",
            "memory.events.oom_group_kill",
        ):
            uint(cg.get(name), name)
        require(
            cg["memory.peak"] >= cg["memory.current"] and cg["memory.peak"] >= previous,
            "decreasing phase memory peak",
        )
        previous = cg["memory.peak"]
        require(
            cg["memory.swap.max"] == cg["memory.swap.current"] == cg["memory.swap.peak"] == 0,
            "phase swap invalidates the receipt",
        )
        require(
            all(cg[f"memory.events.{key}"] == 0 for key in ("oom", "oom_kill", "oom_group_kill")),
            "phase OOM invalidates the receipt",
        )
    require(
        after["memory.peak"]
        >= max([before["memory.peak"], *(row["cgroup"]["memory.peak"] for row in samples)]),
        "scope peak lost a before/phase high-water mark",
    )


def validate_ownership_log(directory: Path, cgroup: str, workload: dict) -> None:
    checker = json.loads((directory / "scope-process.json").read_text(encoding="utf-8"))
    launcher = json.loads((directory / "launcher-process.json").read_text(encoding="utf-8"))
    require(
        checker["parent_pid"] == launcher["pid"] and workload["parent_pid"] == checker["pid"],
        "foreign scoped parent chain",
    )
    require(
        len({launcher["pid"], checker["pid"], workload["pid"]}) == 3, "reused process role identity"
    )
    for row in (launcher, checker, workload):
        require(
            uint(row["start_ticks"], "process start time") > 0
            and bool(re.fullmatch(r"[0-9a-f]{64}", row["exe_sha256"])),
            "invalid scoped executable/start identity",
        )
    require(Path(launcher["executable"]).name == "bash", "launcher is not Bash")
    require(Path(checker["executable"]).name.startswith("python"), "checker is not Python")
    owned = {row["pid"]: row for row in (launcher, checker)}
    active = owned.copy()
    active[workload["pid"]] = workload
    samples = [
        json.loads(line)
        for line in (directory / "ownership.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    require(
        samples
        and samples[0]["phase"] == "before"
        and samples[-1]["phase"] == "after"
        and any(row["phase"] == "active" for row in samples),
        "missing ownership lifetime evidence",
    )
    ended = False
    for row in samples:
        require(row["phase"] in ("before", "active", "after"), "unknown ownership phase")
        require(not ended or row["phase"] == "after", "workload ownership restarted after exit")
        check_ownership(row, active if row["phase"] == "active" else owned, cgroup)
        ended = ended or row["phase"] == "after"


def summarize(root: Path) -> None:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    require(
        manifest.get("schema") == "rustbgpd.recovery-memory.campaign.v2", "wrong campaign schema"
    )
    require(
        manifest["baseline"] == BASELINE and manifest["intermediate"] == INTERMEDIATE,
        "wrong historical controls",
    )
    require(
        bool(re.fullmatch(r"[0-9a-f]{40}", manifest["candidate"]))
        and manifest["candidate"] not in (BASELINE, INTERMEDIATE),
        "candidate is not a distinct source SHA",
    )
    cases = campaign_cases(manifest["phase"], manifest["profiles"], manifest.get("selected_cell"))
    require(
        manifest.get("cases") == cases
        and manifest.get("build_jobs") == 4
        and manifest.get("comparators") == ["baseline", "intermediate"]
        and manifest.get("order_per_cell") == ["control", "candidate", "candidate", "control"],
        "campaign shape or build/order fence differs",
    )
    inputs = root / "instrumentation.sha256"
    require(
        hashlib.sha256(inputs.read_bytes()).hexdigest()
        == manifest.get("instrumentation_manifest_sha256"),
        "instrumentation manifest hash mismatch",
    )
    entries = {}
    for line in inputs.read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        require(
            name in INSTRUMENT_INPUTS and name not in entries, "unknown or duplicate frozen input"
        )
        require(
            hashlib.sha256((root / "frozen-instrumentation" / name).read_bytes()).hexdigest()
            == digest,
            "frozen instrumentation hash mismatch",
        )
        entries[name] = digest
    require(set(entries) == set(INSTRUMENT_INPUTS), "incomplete frozen instrumentation")
    if "memory_entrypoint_derivation_sha256" in manifest:
        validate_memory_derivation(root, manifest["memory_entrypoint_derivation_sha256"])
    binary_hashes = {}
    for role in ("baseline", "intermediate", "candidate"):
        require(
            (root / f"{role}.sha").read_text(encoding="utf-8").strip() == manifest[role],
            "source SHA receipt mismatch",
        )
        require(
            (root / f"{role}-build.exit").read_text(encoding="utf-8").strip() == "0", "build failed"
        )
        require(
            bool(
                re.fullmatch(
                    r"[0-9a-f]{64}",
                    (root / f"{role}-binary.sha256").read_text(encoding="utf-8").strip(),
                )
            ),
            "missing binary hash",
        )
        binary_hashes[role] = (root / f"{role}-binary.sha256").read_text(encoding="utf-8").strip()
        for name in ("build.log", "build-inputs.sha256", "instrumentation.patch", "observer.patch"):
            require((root / f"{role}-{name}").is_file(), f"missing {role} {name}")
    before_oom = (root / "host-oom.before").read_text(encoding="utf-8").strip()
    after_oom = (root / "host-oom.after").read_text(encoding="utf-8").strip()
    require(before_oom.isdigit() and before_oom == after_oom, "host OOM invalidates the receipt")
    rows = []
    scopes, workloads = set(), set()
    candidate_failures = []
    legs = (
        (case, comparator, index, role)
        for case in cases
        for comparator in ("baseline", "intermediate")
        for index, role in enumerate((comparator, "candidate", "candidate", comparator))
    )
    for case, comparator, index, role in legs:
        cell, profile, clients = case["cell"], case["profile"], case["clients"]
        directory = root / f"{profile}-{cell}-{comparator}-{index + 1}-{role}"
        status = json.loads((directory / "status.json").read_text(encoding="utf-8"))
        require(
            set(status) == {"exit", "timeout", "cgroup_valid", "ownership_valid"}
            and status["timeout"] is False
            and status["cgroup_valid"] is True
            and status["ownership_valid"] is True
            and isinstance(status["exit"], int),
            f"invalid scope lifetime {directory.name}",
        )
        strict_error = None
        try:
            require(status["exit"] == 0, f"workload failed with exit {status['exit']}")
            result = validate_log(directory / "harness.log", role, cell, clients, profile)
        except InvalidReceipt as error:
            strict_error = str(error)
            lines = (directory / "harness.log").read_text(encoding="utf-8").splitlines()
            identities = [
                json.loads(line.removeprefix("recovery_identity "))
                for line in lines
                if line.startswith("recovery_identity ")
            ]
            require(len(identities) == 1, "failed control lacks workload identity")
            result = {
                "cell": cell,
                "profile": profile,
                "role": role,
                "samples": [
                    json.loads(line.removeprefix("recovery_sample "))
                    for line in lines
                    if line.startswith("recovery_sample ")
                ],
                "workload_identity": identities[0],
            }
            if role == "candidate":
                candidate_failures.append(f"{directory.name}: {error}")
        result["strict_validation"] = {"passed": strict_error is None, "error": strict_error}
        identity = result["workload_identity"]
        process = json.loads((directory / "binary-process.json").read_text(encoding="utf-8"))
        require(
            identity["source_sha"] == manifest[role]
            and identity["instrumentation_sha256"] == manifest["instrumentation_manifest_sha256"],
            "compiled role source/instrumentation identity mismatch",
        )
        require(process["exe_sha256"] == binary_hashes[role], "executed binary digest mismatch")
        require(
            (identity["pid"], identity["start_ticks"]) == (process["pid"], process["start_ticks"]),
            "workload identity differs from the launched binary",
        )
        expected_cgroup = (directory / "cgroup-path.txt").read_text(encoding="utf-8").strip()
        require(
            identity["cgroup"] == expected_cgroup,
            "workload scope differs from the observed scope",
        )
        require(
            process["cgroup"].strip() == "0::" + expected_cgroup.removeprefix("/sys/fs/cgroup"),
            "launched binary is not in the observed unified scope",
        )
        validate_ownership_log(directory, expected_cgroup, process)
        workload_key = (identity["pid"], identity["start_ticks"])
        require(
            expected_cgroup not in scopes and workload_key not in workloads,
            "reused scope or workload identity across legs",
        )
        scopes.add(expected_cgroup)
        workloads.add(workload_key)
        launcher_exit = (directory / "launcher.exit").read_text(encoding="utf-8").strip()
        require(
            launcher_exit.isdigit() and (launcher_exit == "0" or strict_error is not None),
            "scope launcher failed without retained workload failure",
        )
        before = scope_values(directory / "before")
        end = scope_values(directory / "after")
        check_peak_coverage(before, result["samples"], end)
        result.update(
            {
                "leg": index + 1,
                "comparator": comparator,
                "clients": clients,
                "scope_memory_peak_bytes": end["memory.peak"],
                "scope_memory_current_bytes": end["memory.current"],
            }
        )
        write_json(directory / "validated.json", result)
        rows.append(result)
    summaries = []
    for case in cases:
        for comparator in ("baseline", "intermediate"):
            selected = [
                row
                for row in rows
                if row["cell"] == case["cell"]
                and row["profile"] == case["profile"]
                and row["comparator"] == comparator
            ]
            peaks = {
                role: [row["scope_memory_peak_bytes"] for row in selected if row["role"] == role]
                for role in (comparator, "candidate")
            }
            require(
                all(value > 0 for values in peaks.values() for value in values),
                "missing positive scope peaks",
            )
            summaries.append(
                {
                    **case,
                    "comparator": comparator,
                    "peaks_bytes": peaks,
                    "candidate_to_control_mean_peak_ratio": sum(peaks["candidate"])
                    / sum(peaks[comparator])
                    if all(row["strict_validation"]["passed"] for row in selected)
                    else None,
                    "all_strict_checks_passed": all(
                        row["strict_validation"]["passed"] for row in selected
                    ),
                    "verdict": "feasibility only"
                    if manifest["phase"] == "pilot"
                    else "measured memory only; strict candidate qualification required",
                }
            )
    write_json(
        root / "comparison.json",
        {
            "schema": "rustbgpd.recovery-memory.comparison.v2",
            "phase": manifest["phase"],
            "primary": "scope memory.peak bytes",
            "scope": "manager-direct RIB, production exact-export preflight, harness consumers; no final wire/TCP",
            "rows": rows,
            "summaries": summaries,
            "candidate_failures": candidate_failures,
        },
    )
    require(
        not candidate_failures, "candidate qualification failed: " + "; ".join(candidate_failures)
    )


def summarize_failed(root: Path, driver_exit: int, *, scan: bool = False) -> None:
    """Retain an explicitly unqualified envelope after an aborted invocation."""
    require(1 <= driver_exit <= 255, "failure finalization requires a nonzero driver exit")
    root.mkdir(parents=True, exist_ok=True)
    error = f"driver invocation failed with exit {driver_exit}; raw evidence is unqualified"
    # Do not validate partial legs or preserve ratios from an earlier summary.
    # Failure finalization is evidence retention, never a qualification fallback.
    comparison = {
        "schema": "rustbgpd.recovery-memory.comparison.v2",
        "phase": None,
        "primary": "scope memory.peak bytes",
        "scope": "manager-direct RIB, production exact-export preflight, harness consumers; no final wire/TCP",
        "rows": [],
        "summaries": [],
        "candidate_failures": [error],
        "qualification_passed": False,
        "driver_invocation_exit": driver_exit,
    }
    if scan:
        comparison = {
            "schema": SCAN_SCHEMA,
            "scope": "component scans/capture only; no daemon, fleet, readiness or wire qualification",
            "samples": [],
            "comparisons": [],
            "candidate_failures": [error],
            "qualification_passed": False,
            "driver_invocation_exit": driver_exit,
        }
    write_json(root / "comparison.json", comparison)
    raise InvalidReceipt(error)


def normalize_memory_entrypoint(path: Path, output: Path) -> None:
    """Derive the same memory-only main for all historical/candidate roles."""
    original = path.read_text()
    derived = original
    for block in SCAN_DISPATCH:
        require(derived.count(block) == 1, "component dispatch anchor drift")
        derived = derived.replace(block, "", 1)
    patch = "".join(difflib.unified_diff(original.splitlines(True), derived.splitlines(True),
                                       fromfile="committed/main.rs", tofile="memory/main.rs"))
    path.write_text(derived)
    output.with_suffix(".source.rs").write_text(original)
    output.with_suffix(".patch").write_text(patch)
    write_json(output, {"source_sha256": hashlib.sha256(original.encode()).hexdigest(),
                        "derived_sha256": hashlib.sha256(derived.encode()).hexdigest(),
                        "patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
                        "removed_exact_snippets": list(SCAN_DISPATCH)})


def validate_memory_derivation(root: Path, digest: str) -> None:
    metadata = root / "memory-entrypoint-derivation.json"
    require(hashlib.sha256(metadata.read_bytes()).hexdigest() == digest,
            "memory entrypoint derivation metadata mismatch")
    details = json.loads(metadata.read_text())
    original = metadata.with_suffix(".source.rs").read_text()
    derived = original
    for block in SCAN_DISPATCH:
        require(derived.count(block) == 1, "memory derivation source anchor drift")
        derived = derived.replace(block, "", 1)
    actual = (root / "frozen-instrumentation/bench/scale/rrharness/src/main.rs").read_text()
    patch = "".join(difflib.unified_diff(original.splitlines(True), derived.splitlines(True),
                                       fromfile="committed/main.rs", tofile="memory/main.rs"))
    require(actual == derived and metadata.with_suffix(".patch").read_text() == patch
            and details == {"source_sha256": hashlib.sha256(original.encode()).hexdigest(),
                            "derived_sha256": hashlib.sha256(derived.encode()).hexdigest(),
                            "patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
                            "removed_exact_snippets": list(SCAN_DISPATCH)},
            "memory entrypoint is not the exact recorded derivation")


def validate_scan_log(path: Path, profile: str, old_order: str = "sorted") -> dict:
    """A distinct component schema: never infer daemon or memory qualification."""
    require(profile in SCAN_PROFILES, "unknown scan profile")
    require(old_order in ("sorted", "shuffled"), "unknown OLD key order")
    groups = {name: [] for name in (
        "recovery_scan", "recovery_scan_environment", "recovery_scan_complete", "recovery_identity"
    )}
    for line in path.read_text(encoding="utf-8").splitlines():
        prefix, _, body = line.partition(" ")
        if prefix in groups:
            groups[prefix].append(json.loads(body))
    environment = groups["recovery_scan_environment"]
    require(len(environment) == 1 and environment[0].get("schema") == SCAN_SCHEMA,
            "missing scan environment")
    require(environment[0].get("old_order") == old_order, "scan environment OLD order mismatch")
    require(environment[0].get("phase_passes") == "independent shape and capture invocations"
            and environment[0].get("credit_scope") ==
            "logical daemon ledger reservation; excludes input fixtures, allocator overhead and RSS",
            "scan phases or credit scope are not qualified")
    ticks = uint(environment[0].get("cpu_ticks_per_second"), "CPU tick rate")
    require(ticks > 0, "missing measured CPU tick rate")
    require(len(groups["recovery_identity"]) == 1, "missing scan process identity")
    require(groups["recovery_scan_complete"] == [{"profile": profile, "cells": 6, "legs": 24}],
            "incomplete scan campaign")
    samples = groups["recovery_scan"]
    require(len(samples) == 24, "wrong scan leg count")
    summaries = []
    cursor = 0
    for records in (2, 64, 480):
        for layout in ("dense", "older-sparse"):
            rows = samples[cursor:cursor + 4]
            cursor += 4
            for leg, (row, arm) in enumerate(zip(rows, ("flat", "shared", "shared", "flat"))):
                require(row.get("schema") == SCAN_SCHEMA and row.get("profile") == profile
                        and row.get("old_order") == old_order
                        and row.get("keys") == SCAN_PROFILES[profile]
                        and row.get("records") == records and row.get("layout") == layout
                        and row.get("leg") == leg and row.get("arm") == arm
                        and row.get("measured") is True, "scan shape/order/mode mismatch")
                refusal = row.get("refusal")
                require(refusal is None or refusal in (
                    "peer_limit", "daemon_limit", "allocation_failure", "missing_proof",
                    "capture_unavailable", "admission_invariant", "anchor_not_shared"
                ), "unknown scan refusal")
                for key in ("old_keys", "additions", "shape_callbacks", "comparisons", "proof_keys",
                            "retained_bytes", "peak_bytes", "empty_bytes", "settled_bytes"):
                    uint(row.get(key), key)
                if refusal is not None:
                    continue  # Retain the row; never give a refused proof a ratio.
                keys = SCAN_PROFILES[profile]
                require(row["old_keys"] == row["proof_keys"] == keys,
                        "incomplete scan proof")
                require(row.get("shared") is (arm == "shared"), "flat/share control was bypassed")
                require(row["additions"] == (records if layout == "older-sparse" and arm == "shared" else 0),
                        "incorrect OLD sparse classification")
                require(row["shape_callbacks"] == keys + row["comparisons"],
                        "comparison count is not separate from key visits")
                require((keys <= row["comparisons"] <= 2 * keys + keys.bit_length() + 2)
                        if arm == "shared" else row["comparisons"] == 0,
                        "missing sorted merge work or non-linear classification")
                require(row["settled_bytes"] == row["empty_bytes"] > 0
                        and row["empty_bytes"] < row["retained_bytes"] <= row["peak_bytes"],
                        "proof charge or last-owner retirement differs")
                phases = row.get("phases")
                require(isinstance(phases, dict) and set(phases) == {"shape", "capture"},
                        "missing measured capture phases")
                for phase in phases.values():
                    require(set(phase) == {"wall_ns", "cpu_ticks"}, "unknown phase fields")
                    require(uint(phase["wall_ns"], "phase wall") > 0, "empty timing phase")
                    uint(phase["cpu_ticks"], "phase CPU")
                # These are independent invocations, not nested timings. Tick
                # quantization and scheduling permit shape > complete capture.
            eligible = all(row.get("refusal") is None for row in rows)
            ratios = {}
            if eligible:
                for phase in ("shape", "capture"):
                    ratios[phase] = {}
                    for quantity in ("wall_ns", "cpu_ticks"):
                        flat = sum(rows[i]["phases"][phase][quantity] for i in (0, 3))
                        shared = sum(rows[i]["phases"][phase][quantity] for i in (1, 2))
                        ratios[phase][quantity] = shared / flat if flat else None
            summaries.append({"records": records, "layout": layout, "eligible": eligible,
                              "shared_over_flat": ratios if eligible else None})
    return {"schema": SCAN_SCHEMA, "profile": profile, "old_order": old_order, "samples": samples,
            "comparisons": summaries, "cpu_ticks_per_second": ticks,
            "phase_passes": environment[0]["phase_passes"],
            "credit_scope": environment[0]["credit_scope"],
            "workload_identity": groups["recovery_identity"][0],
            "scope": "component scans/capture only; no daemon, fleet, readiness or wire qualification"}


def summarize_scan(root: Path) -> None:
    manifest = json.loads((root / "manifest.json").read_text())
    require(manifest.get("schema") == "rustbgpd.recovery-scan.campaign.v2", "wrong scan manifest")
    require(manifest.get("profile") in SCAN_PROFILES and manifest.get("build_jobs") == 4,
            "wrong scan profile/build")
    require(manifest.get("old_order") in ("sorted", "shuffled"), "wrong scan OLD order")
    require(manifest.get("order_per_cell") == ["flat", "shared", "shared", "flat"],
            "wrong scan comparison order")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", manifest.get("candidate", ""))), "wrong scan source")
    inputs = root / "instrumentation.sha256"
    require(hashlib.sha256(inputs.read_bytes()).hexdigest() == manifest["instrumentation_manifest_sha256"],
            "scan instrumentation manifest mismatch")
    names = set()
    for line in inputs.read_text().splitlines():
        digest, name = line.split("  ", 1)
        require(name in (*INSTRUMENT_INPUTS, "bench/scale/rrharness/src/recovery_scan.rs")
                and name not in names, "unexpected scan instrumentation")
        require(hashlib.sha256((root / "frozen-instrumentation" / name).read_bytes()).hexdigest() == digest,
                "scan frozen source mismatch")
        names.add(name)
    require(names == {*INSTRUMENT_INPUTS, "bench/scale/rrharness/src/recovery_scan.rs"},
            "missing scan instrumentation")
    require((root / "candidate-build.exit").read_text().strip() == "0", "scan build failed")
    require((root / "candidate.sha").read_text().strip() == manifest["candidate"], "scan source mismatch")
    directory = root / "scan"
    require((directory / "launcher.exit").read_text().strip() == "0", "scan launcher failed")
    status = json.loads((directory / "status.json").read_text())
    require(status == {"exit": 0, "timeout": False, "cgroup_valid": True, "ownership_valid": True},
            "scan workload/scope failed")
    result = validate_scan_log(directory / "harness.log", manifest["profile"], manifest["old_order"])
    identity = result["workload_identity"]
    process = json.loads((directory / "binary-process.json").read_text())
    digest = (root / "candidate-binary.sha256").read_text().strip()
    require(bool(re.fullmatch(r"[0-9a-f]{64}", digest)) and process["exe_sha256"] == digest,
            "scan executed binary mismatch")
    require(identity["source_sha"] == manifest["candidate"]
            and identity["instrumentation_sha256"] == manifest["instrumentation_manifest_sha256"]
            and (identity["pid"], identity["start_ticks"]) == (process["pid"], process["start_ticks"]),
            "scan compiled/process identity mismatch")
    cgroup = (directory / "cgroup-path.txt").read_text().strip()
    require(identity["cgroup"] == cgroup
            and process["cgroup"].strip() == "0::" + cgroup.removeprefix("/sys/fs/cgroup"),
            "scan scope identity mismatch")
    validate_ownership_log(directory, cgroup, process)
    check_peak_coverage(scope_values(directory / "before"), [], scope_values(directory / "after"))
    before = (root / "host-oom.before").read_text().strip()
    require(before.isdigit() and before == (root / "host-oom.after").read_text().strip(),
            "host OOM invalidates scan receipt")
    refused_legs = sum(row["refusal"] is not None for row in result["samples"])
    result["qualification_passed"] = (
        len(result["samples"]) == 24 and len(result["comparisons"]) == 6
        and refused_legs == 0 and all(cell["eligible"] for cell in result["comparisons"])
    )
    if not result["qualification_passed"]:
        write_json(root / "unqualified-comparison.json", result)
    write_json(root / "comparison.json", result)
    require(result["qualification_passed"],
            "all 6 scan cells must have complete, proof-checked non-refused comparisons")
    print(json.dumps({"schema": SCAN_SCHEMA, "profile": manifest["profile"],
                      "old_order": manifest["old_order"],
                      "component_cells": 6, "timed_legs": 24, "refused_legs": refused_legs,
                      "qualification_passed": result["qualification_passed"]}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    observer = sub.add_parser("instrument-observer")
    observer.add_argument("tree", type=Path)
    normalize = sub.add_parser("normalize-memory-entrypoint")
    normalize.add_argument("path", type=Path)
    normalize.add_argument("output", type=Path)
    scope = sub.add_parser("scope-check")
    scope.add_argument("path", type=Path)
    snapshot = sub.add_parser("scope-snapshot")
    snapshot.add_argument("path", type=Path)
    snapshot.add_argument("output", type=Path)
    run = sub.add_parser("run-scope")
    run.add_argument("binary", type=Path)
    run.add_argument("output", type=Path)
    run.add_argument("cell", choices=(*CELLS, "capture-scan"))
    run.add_argument("cgroup", type=Path)
    run.add_argument("expected_digest")
    run.add_argument("profile", choices=(*PROFILES, "evpn-soak"))
    run.add_argument("clients", type=int)
    run.add_argument("--scan", action="store_true")
    run.add_argument("--shuffled-old", action="store_true")
    scan = sub.add_parser("summarize-scan")
    scan.add_argument("root", type=Path)
    scan.add_argument("--failed-driver-exit", type=int)
    compare = sub.add_parser("summarize")
    compare.add_argument("root", type=Path)
    compare.add_argument("--failed-driver-exit", type=int)
    args = parser.parse_args()
    try:
        if args.command == "instrument-observer":
            instrument_observer(args.tree)
        elif args.command == "normalize-memory-entrypoint":
            normalize_memory_entrypoint(args.path, args.output)
        elif args.command == "scope-check":
            print(json.dumps(scope_values(args.path), sort_keys=True))
        elif args.command == "scope-snapshot":
            snapshot_scope(args.path, args.output)
        elif args.command == "run-scope":
            run_scope(
                args.binary,
                args.output,
                args.cell,
                args.cgroup,
                args.expected_digest,
                args.profile,
                args.clients,
                scan=args.scan,
                shuffled_old=args.shuffled_old,
            )
        elif args.command == "summarize-scan":
            if args.failed_driver_exit is not None:
                summarize_failed(args.root, args.failed_driver_exit, scan=True)
            else:
                summarize_scan(args.root)
        else:
            if args.failed_driver_exit is not None:
                summarize_failed(args.root, args.failed_driver_exit)
            else:
                summarize(args.root)
    except (InvalidReceipt, OSError, ValueError, KeyError) as error:
        print(f"invalid recovery receipt: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
