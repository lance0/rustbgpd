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
# The quiet gate's compilers and linkers, shared with the credit cells' watch.
COMPILERS = frozenset(Path(__file__).with_name("compiler-names.txt").read_text().split())
SAMPLE_SECONDS = 0.25
PHASES = ("setup", "refusal", "dirty", "recovery", "settled")


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


def compiler_sample(watch, measured):
    """A compiler stops a measured run. A correctness smoke only records it."""
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
            watch["observed"] += 1
            watch["first_compiler"] = watch["first_compiler"] or f"{entry.name} {name}"
            if measured:
                raise ValueError(f"concurrent compiler: {entry.name} {name}")
            break
    watch["samples"] += 1


def run(binary, directory, shape, unit):
    peers, rows = SHAPES[shape]
    measured = shape not in SMOKES
    watch = {"samples": 0, "observed": 0, "first_compiler": None}
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
            compiler_sample(watch, measured)
            with (directory / "cell.log").open("w") as log:
                child = subprocess.Popen(
                    [binary, "grouped-old-capture", directory, "--peers", str(peers), "--rows", str(rows)],
                    stdout=log, stderr=subprocess.STDOUT,
                )
                while child.poll() is None:
                    compiler_sample(watch, measured)
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, f"cell exceeded its {timeout}s deadline")
                    try:
                        child.wait(timeout=min(SAMPLE_SECONDS, remaining))
                    except subprocess.TimeoutExpired:
                        continue
            compiler_sample(watch, measured)
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
    require(type(watch["samples"]) is int and watch["samples"] >= 2 and type(watch["observed"]) is int
            and 0 <= watch["observed"] <= watch["samples"]
            and (watch["observed"] == 0) == (watch["first_compiler"] is None),
            "missing or inconsistent compiler coverage")
    # Only a measured shape is invalidated by a compiler. A smoke grades wire
    # correctness and counts, which a busy host does not change.
    require(shape in SMOKES or watch["observed"] == 0, f"concurrent compiler: {watch['first_compiler']}")
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
    # A reset is the daemon's unless the runtime carrying the sessions and
    # their peers went unscheduled for a keepalive interval (a third of the
    # hold time): then the harness could not keep its own side of the timer.
    hold = count(raw, "hold_time_secs")
    stall = count(raw, "session_runtime_max_stall_ns")
    require(hold > 0 and stall * 3 < hold * 1_000_000_000,
            f"session runtime stalled {stall / 1e9:.1f} s against a {hold} s hold time")
    if count(raw, "reset_count") or count(transport, "resets"):
        return "transport reset"
    for key in ("sessions", "established", "seed_fences", "final_fences"):
        require(count(transport, key) == peers, f"incomplete transport {key}")
    for count_source, key in ((raw, "wire_exact_receivers"), (transport, "wire_exact_receivers")):
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
        if not (count(wire, "present") == rows + 2 and count(wire, "withdrawals") == 1
                and count(wire, "empty_initial_eors") == 1
                and count(wire, "replacement_version") == 3 and wire["intermediate_fill_seen"] is True
                and wire["trigger_present"] is True and wire["probe_present"] is True
                and wire["recovery_probe_present"] is True):
            return f"{member['peer']}: incomplete or incorrect decoded wire inventory"
    return None


def announcements(raw, rows):
    """Exact: the seed once, the two fills, one whole-table replay (a resync is
    one envelope and the dirty flag clears only when it is admitted), and the
    recovery probe once, inside that replay or as an ordinary send after it."""
    expected = 2 * rows + 4
    for member in raw["transport"]["receivers"]:
        seen = count(member["wire"], "announcements")
        require(seen == expected,
                f"{member['peer']}: {seen} announcements, expected exactly {expected} "
                "(seed, two fills, one recovery replay, recovery probe)")
    return expected


def proofs(raw, peers, rows):
    """Strategy and ledger charge of each capture; walks and rows are exact."""
    ledger = raw["proof_ledger"]
    before, after, peak, member_limit, daemon_limit = (count(ledger, key) for key in (
        "before_bytes", "after_bytes", "peak_bytes", "member_limit_bytes", "daemon_limit_bytes"))
    require(0 < member_limit and before < after <= peak <= daemon_limit, "inconsistent recovery ledger charge")
    entries = raw["proofs"]
    require(isinstance(entries, list) and len(entries) == peers,
            f"{len(entries)} capture records for {peers} fresh captures")
    kinds = {}
    for proof in entries:
        kind = (proof["strategy"], proof["pool"])
        require(kind in (("indexed", "built"), ("indexed", "reused"), ("flat", "none")),
                f"unknown proof strategy {kind}")
        kinds[kind] = kinds.get(kind, 0) + 1
        # Both strategies size the proof in one walk and populate it in a second.
        require(count(proof, "walks") == 2 and count(proof, "projections") == 2 * rows
                and count(proof, "keys") == rows,
                f"capture made {proof['walks']} walks, {proof['projections']} projections and {proof['keys']} keys; "
                f"expected 2, {2 * rows} and {rows}")
        # Vacant slab slots depend on the table's reuse order, not on this fixture.
        require(count(proof, "slots") >= rows, "fewer slab slots than occupied rows")
        require(0 < count(proof, "member_charge_bytes") <= member_limit
                and before < count(proof, "daemon_bytes") <= peak, "capture charge outside the ledger's record")
    largest = max(proof["member_charge_bytes"] for proof in entries)
    split = ", ".join(f"{n} {strategy}/{pool}" for (strategy, pool), n in sorted(kinds.items()))
    return (f"proofs {split}; largest member charge {largest} of {member_limit} bytes, "
            f"daemon charge {after} (peak {peak}) of {daemon_limit} bytes")


def polls(raw):
    """Every poll carries one phase label; the whole-run maximum names its own."""
    phases = raw["phases"]
    require(isinstance(phases, dict) and set(phases) == set(PHASES), "missing or unknown poll phases")
    longest = {name: count(phases[name], "longest_poll_ns") for name in PHASES}
    counts = {name: count(phases[name], "polls") for name in PHASES}
    require(all((counts[name] == 0) == (longest[name] == 0) for name in PHASES), "phase polls disagree with their longest")
    # One trigger pass in one poll; later phases take as many polls and resync
    # slices as the harness's draining and the 10 ms resync tick interleave to.
    require(counts["refusal"] == 1 and longest["refusal"] == raw["capture_turn_poll_ns"],
            "refusal phase is not the single capture poll")
    # The actor is joined before the receipt, so `settled` holds at least its last poll.
    require(all(counts[name] > 0 for name in PHASES), "a phase has no physical RIB poll")
    require(count(phases["dirty"], "refused_resync_slices") > 0, "no resync retry against a full receiver in the dirty period")
    require(count(phases["recovery"], "resync_slices") > 0, "no resync slice in recovery")
    require(count(raw, "actor_polls") == sum(counts.values()), "phase polls do not sum to the actor's polls")
    whole, where, touched = count(raw, "longest_actor_poll_ns"), raw["longest_actor_poll_phase"], raw["longest_actor_poll_touched"]
    require(whole == max(longest.values()) and where in PHASES and longest[where] == whole,
            "whole-run longest poll disagrees with its phase")
    require(isinstance(touched, list) and where in touched and set(touched) <= set(PHASES), "invalid phases for the longest poll")
    retirement = raw["retirement"]
    retired = retirement["longest_poll_ns"]
    # Every member recovers, so the last one releases the shared proof.
    require(retirement["reached"] is True and type(retired) is int and 0 < retired <= whole,
            "last-owner retirement of the proof was not observed")
    return (", ".join(f"{name} {longest[name] / 1e6:.3f}" for name in PHASES)
            + f" ms; whole run {whole / 1e6:.3f} ms in {where}; retirement within {retired / 1e6:.3f} ms")


def grade(raw, host, shape, peak):
    peers, rows = SHAPES[shape]
    require(raw["cell"] == "grouped-old-capture", "wrong cell")
    require((count(raw, "peers"), count(raw, "rows")) == (peers, rows), "wrong workload shape")
    if "wire_failure" in raw:
        require(isinstance(raw["wire_failure"], str) and raw["wire_failure"].strip()
                and type(host["exit"]) is int and host["exit"] != 0, "unconfirmed wire failure")
        return "FAIL", raw["wire_failure"]
    if "harness_invalid" in raw:
        require(isinstance(raw["harness_invalid"], str) and raw["harness_invalid"].strip()
                and type(host["exit"]) is int and host["exit"] != 0, "unconfirmed harness refusal")
        raise ValueError(raw["harness_invalid"])
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
    require(walks == 2 * peers, f"{walks} completed walks for {peers} fresh captures, expected exactly {2 * peers}")
    require(count(raw, "group_capture_walks") == walks,
            f"{walks - raw['group_capture_walks']} walks outside a sealed grouped capture")
    require(projections == walks * rows,
            f"{projections} projections disagree with {walks} completed walks of {rows} occupied rows")
    proof_summary = proofs(raw, peers, rows)
    sent = announcements(raw, rows)
    ns = raw["clocks_ns"]
    ts = {k: count(ns, k) for k in (
        "trigger_admission", "poll_start", "pass_start", "capture_start", "probe_admission",
        "capture_end", "pass_end", "poll_end", "probe_dispatch", "probe_winner",
        "recovery_start", "recovery_probe_admission", "recovery_probe_dispatch",
        "recovery_probe_winner", "recovery_end",
    )}
    require(ts["trigger_admission"] <= ts["pass_start"], "trigger admitted after capture pass start")
    require(ts["poll_start"] <= ts["pass_start"] <= ts["capture_start"] <= ts["probe_admission"]
            < ts["capture_end"] <= ts["pass_end"] <= ts["poll_end"],
            "missing probe admission during capture or capture outside physical poll")
    require(ts["pass_end"] <= ts["probe_dispatch"] <= ts["probe_winner"], "probe service outside expected order")
    require(ts["probe_winner"] <= ts["recovery_start"] <= ts["recovery_probe_admission"]
            <= ts["recovery_probe_dispatch"] <= ts["recovery_probe_winner"]
            and ts["recovery_start"] <= ts["recovery_end"], "recovery probe outside recovery")
    require(raw["recovery_probe_slice_recovered"] is True,
            "the recovery probe's resync slice did not recover a receiver")
    for key, start, end in (
        ("capture_turn_poll_ns", "poll_start", "poll_end"),
        ("capture_pass_ns", "pass_start", "pass_end"),
        ("capture_loop_ns", "capture_start", "capture_end"),
        ("probe_admission_to_dispatch_ns", "probe_admission", "probe_dispatch"),
        ("probe_admission_to_winner_ns", "probe_admission", "probe_winner"),
        ("recovery_probe_admission_to_dispatch_ns", "recovery_probe_admission", "recovery_probe_dispatch"),
        ("recovery_probe_admission_to_winner_ns", "recovery_probe_admission", "recovery_probe_winner"),
    ):
        elapsed = count(raw, key)
        require(elapsed > 0 and elapsed == ts[end] - ts[start], f"{key} inconsistent with timestamps")
    require(count(raw, "actor_polls") > 0, "no physical RIB polls observed")
    poll_summary = polls(raw)
    require(type(host["exit"]) is int and host["exit"] == 0, f'unexplained workload exit {host["exit"]}')
    mode = "correctness smoke" if shape in SMOKES else "report-only measurement"
    sighting = host["compiler_watch"]["first_compiler"]
    return "PASS", (
        f"{mode}, {peers} peers × {rows} rows, {raw['fresh_captures']} fresh captures, "
        f"{raw['walks']} walks, {raw['projections']} projections, {sent} announcements per receiver; "
        f"{proof_summary}; longest poll by phase: {poll_summary}; "
        f"capture pass {raw['capture_pass_ns']/1e6:.3f} ms, capture loop {raw['capture_loop_ns']/1e6:.3f} ms; "
        f"unrelated admission to dispatch {raw['probe_admission_to_dispatch_ns']/1e6:.3f} ms in the capture walk "
        f"and {raw['recovery_probe_admission_to_dispatch_ns']/1e6:.3f} ms in recovery "
        f"(to first matching winner query reply {raw['probe_admission_to_winner_ns']/1e6:.3f} "
        f"and {raw['recovery_probe_admission_to_winner_ns']/1e6:.3f} ms); "
        f"cgroup memory.peak {peak} bytes (includes harness), swap 0"
        + (f"; compiler seen during the smoke ({sighting}), timings not usable" if sighting else "")
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
