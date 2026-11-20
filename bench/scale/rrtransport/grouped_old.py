"""Run the grouped OLD probe in its systemd scope or grade its saved receipt."""

import errno
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import subprocess
import sys
import time

# Use the same quiet-host receipt contract as the other actor campaign.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "reloadstall"))
from converged_rejoin import quiet_problem  # noqa: E402


SMOKES = {"smoke": (4, 64), "smoke-chunked": (12, 2049)}
SHAPES = {**SMOKES, "150x37000": (150, 37_000), "700x400000": (700, 400_000)}
LIMIT_BYTES = 64 << 30
COMPILERS = {"cargo", "rustc", "rustdoc", "clippy-driver"}
SAMPLE_SECONDS = 0.25


def require(condition, message):
    if not condition:
        raise ValueError(message)


def memory(scope):
    values = {key: int((scope / key).read_text()) for key in (
        "memory.max", "memory.peak", "memory.swap.max", "memory.swap.peak",
    )}
    events = dict(line.split() for line in (scope / "memory.events").read_text().splitlines())
    values["oom_kill"] = int(events["oom_kill"])
    require(values["memory.max"] == LIMIT_BYTES and values["memory.swap.max"] == 0,
            "scope does not have the expected 64 GiB and zero-swap limits")
    return values


def compiler_sample(watch):
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / "comm").read_text().strip()
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.ESRCH):
                continue
            raise
        if name in COMPILERS:
            watch["first_compiler"] = f"{entry.name} {name}"
            raise ValueError(f"concurrent compiler: {entry.name} {name}")
    watch["samples"] += 1


def run(binary, directory, shape, unit):
    peers, rows = SHAPES[shape]
    watch = {"samples": 0, "first_compiler": None}
    host = {"shape": shape, "unit": unit, "compiler_watch": watch, "exit": None}
    child = None
    try:
        cgpath, = (line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
                   if line.startswith("0::"))
        scope = Path("/sys/fs/cgroup") / cgpath.lstrip("/")
        require(scope.name == unit, f"unexpected systemd scope {scope}")
        host["memory_before"] = memory(scope)
        timeout = int(os.environ.get("RRTRANSPORT_GROUPED_OLD_TIMEOUT_SECS", "3600"))
        require(timeout > 0, "timeout must be positive")
        deadline = time.monotonic() + timeout
        try:
            compiler_sample(watch)
            with (directory / "cell.log").open("w") as log:
                child = subprocess.Popen(
                    [binary, "grouped-old-capture", directory, "--peers", str(peers), "--rows", str(rows)],
                    stdout=log, stderr=subprocess.STDOUT,
                )
                while child.poll() is None:
                    compiler_sample(watch)
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, f"cell exceeded its {timeout}s deadline")
                    try:
                        child.wait(timeout=min(SAMPLE_SECONDS, remaining))
                    except subprocess.TimeoutExpired:
                        continue
            compiler_sample(watch)
        finally:
            if child is not None:
                if child.poll() is None:
                    child.kill()
                host["exit"] = child.wait()
            host["memory_after"] = memory(scope)
    except (ValueError, OSError, KeyError) as error:
        host["error"] = str(error)
    (directory / "host.json").write_text(json.dumps(host, indent=2) + "\n")


def checked_host(host, shape):
    require(host.get("shape") == shape, "host shape mismatch")
    unit = host["unit"]
    require(isinstance(unit, str) and unit.startswith("rrtransport-grouped-old-") and unit.endswith(".scope"),
            "missing dedicated systemd scope")
    if host.get("error"):
        raise ValueError(host["error"])
    watch = host["compiler_watch"]
    require(type(watch["samples"]) is int and watch["samples"] >= 2 and watch["first_compiler"] is None,
            "missing compiler coverage or concurrent compiler")
    for point in ("memory_before", "memory_after"):
        values = host[point]
        require(all(type(values[k]) is int and values[k] >= 0 for k in (
            "memory.peak", "memory.max", "memory.swap.max", "memory.swap.peak", "oom_kill",
        )), "invalid cgroup counters")
        require(values["memory.max"] == LIMIT_BYTES and 0 < values["memory.peak"] <= LIMIT_BYTES,
                "invalid cgroup memory peak or cap")
        require(values["memory.swap.max"] == values["memory.swap.peak"] == 0, "scope used swap or lacks fence")
        require(values["oom_kill"] == 0, "cgroup OOM killed the workload")
    peak = host["memory_after"]["memory.peak"]
    require(peak >= host["memory_before"]["memory.peak"], "inconsistent cgroup peak")
    return peak


def count(mapping, key):
    value = mapping[key]
    require(type(value) is int and value >= 0, f"invalid {key}")
    return value


def wire_failure(raw, peers, rows):
    transport = raw["transport"]
    if count(raw, "reset_count") or count(transport, "resets"):
        return "transport reset"
    if raw["policy_denied_winner_absent_on_receivers"] is not True:
        return "policy-denied route appeared on a receiver"
    for key in ("sessions", "established", "seed_fences", "final_fences"):
        require(count(transport, key) == peers, f"incomplete transport {key}")
    for count_source, key in (
        (raw, "exact_receivers_before_trigger"), (raw, "exact_receivers_after_recovery"),
        (raw, "wire_exact_receivers"), (transport, "wire_exact_receivers"),
    ):
        exact = count(count_source, key)
        require(exact <= peers, "exactness count exceeds receiver count")
        if exact != peers:
            return f"{key}: {exact}/{peers} exact receivers"

    members = transport["receivers"]
    require(isinstance(members, list) and len(members) == peers, "missing per-receiver wire counts")
    base = IPv4Address("127.32.0.1")
    sessions = set()
    for member in members:
        session = count(member, "session_id")
        require(1 <= session <= peers and session not in sessions
                and member["peer"] == str(base + session - 1), "wrong receiver or session identity")
        sessions.add(session)
        wire = member["wire"]
        if not (count(wire, "present") == rows + 1 and count(wire, "withdrawals") == 1
                and count(wire, "empty_initial_eors") == 1 and count(wire, "announcements") >= rows + 4
                and count(wire, "replacement_version") == 3 and wire["intermediate_fill_seen"] is True
                and wire["trigger_present"] is True and wire["probe_present"] is True):
            return f"{member['peer']}: incomplete or incorrect decoded wire inventory"
    return None


def grade(raw, host, shape, peak):
    peers, rows = SHAPES[shape]
    require(raw["cell"] == "grouped-old-capture", "wrong cell")
    require((count(raw, "peers"), count(raw, "rows")) == (peers, rows), "wrong workload shape")
    if "wire_failure" in raw:
        require(isinstance(raw["wire_failure"], str) and raw["wire_failure"].strip()
                and type(host["exit"]) is int and host["exit"] != 0, "unconfirmed wire failure")
        return "FAIL", raw["wire_failure"]
    require(raw["debug_assertions"] is False and raw["checkpoint_tally_compiled_in"] is False,
            "need an optimized binary with the checkpoint tally compiled out")
    require(raw["probe_winner_boundary"] == "first_matching_query_reply", "unknown winner observation boundary")
    if failure := wire_failure(raw, peers, rows):
        return "FAIL", failure
    for key, expected in (
        ("established_group_members", peers), ("full_receivers_before_trigger", peers),
        ("first_refused_receivers", peers), ("fresh_captures", peers),
    ):
        value = count(raw, key)
        require(value == expected, f"{key}: observed {value}, expected {expected}")
    walks = count(raw, "walks")
    projections = count(raw, "projections")
    require(walks >= peers, f"{walks} completed walks for {peers} fresh captures")
    require(projections == walks * rows,
            f"{projections} projections disagree with {walks} completed walks of {rows} occupied rows")
    ns = raw["clocks_ns"]
    ts = {k: count(ns, k) for k in (
        "trigger_admission", "poll_start", "pass_start", "capture_start", "probe_admission",
        "capture_end", "pass_end", "poll_end", "probe_dispatch", "probe_winner",
    )}
    require(ts["trigger_admission"] <= ts["pass_start"], "trigger admitted after capture pass start")
    require(ts["poll_start"] <= ts["pass_start"] <= ts["capture_start"] <= ts["probe_admission"]
            < ts["capture_end"] <= ts["pass_end"] <= ts["poll_end"],
            "missing probe admission during capture or capture outside physical poll")
    require(raw["probe_overlapped_capture"] is True and ts["pass_end"] <= ts["probe_dispatch"] <= ts["probe_winner"],
            "probe service outside expected order")
    for key, start, end in (
        ("capture_turn_poll_ns", "poll_start", "poll_end"),
        ("capture_pass_ns", "pass_start", "pass_end"),
        ("capture_loop_ns", "capture_start", "capture_end"),
        ("probe_admission_to_dispatch_ns", "probe_admission", "probe_dispatch"),
        ("probe_admission_to_winner_ns", "probe_admission", "probe_winner"),
    ):
        elapsed = count(raw, key)
        require(elapsed > 0 and elapsed == ts[end] - ts[start], f"{key} inconsistent with timestamps")
    require(count(raw, "actor_polls") > 0, "no physical RIB polls observed")
    longest = count(raw, "longest_actor_poll_ns")
    require(longest >= raw["capture_turn_poll_ns"], "longest actor poll shorter than capture poll")
    require(type(host["exit"]) is int and host["exit"] == 0, f'unexplained workload exit {host["exit"]}')
    mode = "correctness smoke" if shape in SMOKES else "report-only measurement"
    return "PASS", (
        f"{mode}, {peers} peers × {rows} rows, {raw['fresh_captures']} fresh captures, "
        f"{raw['walks']} walks, {raw['projections']} projections; "
        f"longest actor poll {longest/1e6:.3f} ms, capture poll {raw['capture_turn_poll_ns']/1e6:.3f} ms, "
        f"pass {raw['capture_pass_ns']/1e6:.3f} ms, capture loop {raw['capture_loop_ns']/1e6:.3f} ms, "
        f"unrelated admission to dispatch {raw['probe_admission_to_dispatch_ns']/1e6:.3f} ms "
        f"and to first matching winner query reply {raw['probe_admission_to_winner_ns']/1e6:.3f} ms; "
        f"cgroup memory.peak {peak} bytes (includes harness), swap 0"
    )


def check(directory, shape):
    try:
        host = json.loads((directory / "host.json").read_text())
        # Preserve the reason when a fence, compiler or OOM stopped the binary
        # before it could write its raw observations.
        peak = checked_host(host, shape)
        if shape not in SMOKES:
            why = quiet_problem((directory / "quiet.tsv").read_text())
            require(why is None, f"quiet-host gate: {why}")
        digest = (directory / "binary.sha256").read_text().split()[0]
        require(len(digest) == 64 and all(c in "0123456789abcdef" for c in digest), "invalid binary SHA-256")
        raw = json.loads((directory / "grouped-old.json").read_text())
        return grade(raw, host, shape, peak)
    except (IndexError, KeyError, OSError, TypeError, ValueError) as error:
        return "INVALID", str(error)


def main(args):
    if len(args) == 5 and args[0] == "run" and args[3] in SHAPES:
        run(Path(args[1]), Path(args[2]), args[3], args[4])
        return 0
    if len(args) == 3 and args[0] == "check" and args[2] in SHAPES:
        verdict, reason = check(Path(args[1]), args[2])
        print(f"{verdict} {reason}")
        return {"PASS": 0, "FAIL": 1, "INVALID": 2}[verdict]
    print("usage: grouped_old.py check OUTPUT_DIR smoke|smoke-chunked|150x37000|700x400000", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
