#!/usr/bin/env python3
"""Extract a headline campaign's values into summary.csv and a per-arm table.

Usage: summarize.py SOURCE [--out DIR] [--exclude GLOB ...]

SOURCE is either a campaign output directory written by run-campaign.sh, a
compact receipt bundle under docs/perf/artifacts/ (legs under matrix/, irr/
and rr1000/), or a cross-daemon queue directory (legs under legs/). Leg
directories are named matrix-ARM-rN-sK, irr-ovF-ARM-rN and rr1000-ARM-cN; a
cross-daemon queue names them matrix-sK-rN-DAEMON, whose arm is the daemon,
and irr-ovF-rN, whose arm is rustbgpd.

An optional SOURCE/EXCLUDED file lists leg IDs to drop, one per line (`#`
starts a comment), and --exclude GLOB adds more. Each entry must match a leg;
report.md lists the excluded legs under the table, whose counts n are what
remains.

Only finished legs count: a matrix leg whose status is `pass`, an IRR root
whose COMPLETED status is `pass`, and an RR1000 campaign whose COMPLETED is
`pass`. Matrix values come from the labelled reloadstall.log lines, not the
CSV rows. A finished leg that lacks a labelled value it must carry is an
error, not an empty cell: a renamed label would otherwise drop a whole row
from the receipt table without notice.

The daemon's own reload intervals come from its JSON log (daemon.log in each
rustbgpd matrix S2 cell and IRR rustbgpd-sighup cell), one set per SIGHUP: SIGHUP
received to "config source loaded" and to "config reload complete", the
logged validate_ms, and the RIB transition (cohort_rib_transition_us). A
daemon log must hold exactly as many completed reloads as the harness
measured, SIGHUP and completion must alternate strictly, and every completed
reload must carry all four values. A campaign
directory must keep those daemon logs; a receipt bundle
does not carry them, so it has no daemon rows.

Memory rows keep each source separate: the 5 s process-tree RSS samples
(peak_rss_sample is a sample, not a peak), rustbgpd's VmHWM (matrix legs and
IRR SIGHUP cells), the cgroup memory.peak of rustbgpd's own scope
(daemon_cg_peak) and of a competitor's container (container_cg_peak).
report.md names the source of every memory metric in its table.

Writes to DIR (default SOURCE, which must then be a campaign directory;
a bundle needs --out so a committed receipt is never rewritten): summary.csv,
one row per run, round and metric; establishment-span.csv, the first-to-Nth
`session established` span from each matrix leg's daemon log, when the
daemon logs are present; and report.md, the per-arm range, median and count
for every metric. S1 values are read from the convergence phase of the S2
and S3 legs.
"""

import argparse
import csv
import fnmatch
import json
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

MATRIX = re.compile(r"^matrix-(.+)-r(\d+)-(s\d)$")
IRR = re.compile(r"^irr-ov([\d.]+)-(.+)-r(\d+)$")
# The run-matrix.sh cells. A competitor's daemon.log is its own text log, not
# rustbgpd's JSON, so it yields no daemon rows.
DAEMONS = ("rustbgpd", "bird", "openbgpd")
# A cross-daemon queue's leg names, normalised to MATRIX's and IRR's groups.
QUEUE_MATRIX = (re.compile(rf"^matrix-(s\d)-r(\d+)-({'|'.join(DAEMONS)})$"),
                lambda scenario, run, daemon: (daemon, run, scenario))
QUEUE_IRR = (re.compile(r"^irr-ov([\d.]+)-r(\d+)$"), lambda overlap, run: (overlap, "rustbgpd", run))
RR = re.compile(r"^rr1000-(.+)-c(\d+)$")

# (metric, labelled-line pattern, unit, scenarios where a pass must carry it).
# flap_* patterns capture the round number first; their rows are keyed by it.
MATRIX_LINES = [
    ("established", r"^established \d+ at ([\d.]+)s", "s", {"s2", "s3"}),
    ("cold_convergence", r"^converged \(>= \d+/observer\) at ([\d.]+)s", "s", {"s2", "s3"}),
    ("reload_completion_p50", r"^reload \d+ completion_s: p50=([\d.]+)", "s", {"s2"}),
    ("reload_changed_maxgap_p50", r"^reload \d+ maxgap_ms: p50=([\d.]+)", "ms", {"s2"}),
    ("flap_withdraw_p50", r"^flap (\d+) withdraw_s: p50=([\d.]+)", "s", {"s3"}),
    ("flap_reannounce_p50", r"^flap (\d+) reannounce_s: p50=([\d.]+)", "s", {"s3"}),
    ("flap_first_reannounce_p50", r"^flap (\d+) first_reann_s: p50=([\d.]+)", "s", {"s3"}),
    ("flap_post_round_rss", r"^flap (\d+) sessions_up \d+/\d+ rss_mib=(\d+)", "MiB", {"s3"}),
]
# Optional `flap N heap key=value ...` lines: older harnesses print none. When
# present there is one per round like the flap metrics above, whatever their
# values; a gauge the daemon does not export reads `absent` and emits no row.
HEAP_LINE = re.compile(r"^flap (\d+) heap\b(.*)$", re.M)
HEAP_FIELDS = [("flap_heap_allocated", "allocated_mib"), ("flap_heap_resident", "resident_mib")]


class ExtractionError(Exception):
    pass


def legs(source, subdir, pattern, exclusions, queue=None):
    """Leg directories directly under SOURCE (campaign), SOURCE/SUBDIR (bundle)
    or, named by QUEUE's (pattern, normalise) pair, SOURCE/legs (queue).

    EXCLUSIONS is (globs, excluded): a leg matching a glob is appended to
    `excluded` instead of being returned."""
    globs, excluded = exclusions
    found = []
    for base in (source, source / subdir, source / "legs"):
        if not base.is_dir():
            continue
        for path in sorted(base.iterdir()):
            match = pattern.match(path.name)
            groups = match.groups() if match else None
            if queue and not match and (match := queue[0].match(path.name)):
                groups = queue[1](*match.groups())
            if not (path.is_dir() and groups):
                continue
            if any(fnmatch.fnmatch(path.name, glob) for glob in globs):
                excluded.append(path.name)
            else:
                found.append((path, groups))
    return found


def read_text(path):
    return path.read_text(errors="replace")


# run-matrix.sh's record_scope_memory output, byte for byte.
CGROUP_MEMORY = re.compile(
    r"cg_peak: (\d+) kB\ncg_current: \d+ kB\ncg_swap_max: 0\n"
    r"(?:cg_last_sample_anon: \d+ kB\ncg_last_sample_file: \d+ kB\n"
    r"cg_last_sample_file_mapped: \d+ kB\ncg_teardown_anon: \d+ kB\n"
    r"cg_teardown_file: \d+ kB\ncg_teardown_file_mapped: \d+ kB\n)?"
)


# Native IRR readouts additionally prove the actual swap peak and window.
IRR_SCOPE_MEMORY = re.compile(
    r"cg_peak: (\d+) kB\ncg_current: \d+ kB\ncg_swap_max: 0\ncg_swap_peak: 0 kB\n"
)
IRR_MEMORY_WINDOW = "through_harness_completion_before_lifecycle\n"

# cgroup-memory.sh's shared container readout, byte for byte. A cell's
# cgroup peak is complete only if nothing was swapped out during the cell.
CONTAINER_MEMORY = re.compile(r"container_cg_peak: (\d+) kB\ncontainer_cg_swap_peak: 0 kB\n")

# Where each memory metric comes from, printed under report.md's table. Only
# the two cgroup peaks are like for like across arms: the native scope and a
# competitor's container are both cgroup v2 memory.peak, which charges anon,
# page cache and kernel socket buffers. VmHWM is one process's resident peak.
MEMORY_SOURCES = {
    "peak_rss_sample": "KiB; the largest 5 s process-tree RSS sample; it misses transients shorter than the interval, so a reload peak depends on sampling phase",
    "settled_rss_last_sample": "KiB; the last 5 s process-tree RSS sample",
    "daemon_vmhwm": "KiB; the kernel's VmHWM for the rustbgpd process at cell end, its resident peak over the whole cell",
    "daemon_cg_peak": "KiB; memory.peak of rustbgpd's own swap-fenced scope: resident anon and page cache plus kernel socket buffers",
    "irr_daemon_cg_peak": "KiB; memory.peak of rustbgpd's own swap-fenced scope through harness completion, before transaction lifecycle probes; actual memory.swap.peak is zero",
    "irr_container_cg_peak": "KiB; memory.peak of the competitor's container through harness completion, before teardown, with zero swap peak; includes the `docker exec` reload clients",
    "container_cg_peak": "KiB; memory.peak of the competitor's container cgroup (same kind as daemon_cg_peak), with zero swap peak; it also charges the `docker exec` reload clients",
    "settled_cg_current_last_sample": "KiB; memory.current of rustbgpd's scope at the last 5 s sample",
    "flap_post_round_rss": "MiB; the harness's per-round RSS of the daemon PID; 0 for containerised arms, whose PID the harness is not given",
    "flap_heap_allocated": "MiB; jemalloc allocated bytes after each flap round (rustbgpd only)",
    "flap_heap_resident": "MiB; jemalloc resident bytes after each flap round (rustbgpd only)",
    "wire_vmrss": "KiB; the RR1000 target process's own VmRSS (direct PID, not its process tree) at the wire checkpoint",
    "wire_vmhwm": "KiB; the RR1000 target process's own VmHWM (direct PID, not its process tree) at the wire checkpoint, its resident peak up to then",
}


def format_value(metric, value):
    """Memory sizes as trimmed fixed-point, which never switches to exponent
    form; timings and counts to seven significant digits."""
    if metric in MEMORY_SOURCES:
        return f"{value:.3f}".rstrip("0").rstrip(".")
    return f"{value:.7g}"


def vmhwm_rows(path, phase, arm, run):
    """The daemon_vmhwm row from a `vmhwm` readout (VmHWM/VmRSS status lines), if any."""
    hwm = re.search(r"VmHWM:\s+(\d+)", read_text(path)) if path.exists() else None
    return [[phase, arm, run, "daemon_vmhwm", "", hwm.group(1), "KiB"]] if hwm else []


def rss_column(path):
    return [int(row["total_rss_kib"]) for row in csv.DictReader(path.read_text().splitlines())]


def cg_current_column(path):
    """The optional cgroup column; a sample whose read raced scope teardown is blank."""
    return [int(row["cg_current_kib"]) for row in csv.DictReader(path.read_text().splitlines())
            if row.get("cg_current_kib")]


def log_time(record):
    return datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00")).timestamp()


RELOAD_MESSAGES = ("SIGHUP received", "config source loaded", "reload generation phase timing",
                   "config reload complete")
RELOAD_METRICS = ("daemon_sighup_to_loaded", "daemon_sighup_to_complete", "daemon_validate",
                  "daemon_rib_transition")
# Where each value comes from, for the error that names a missing one.
RELOAD_SOURCES = ("'config source loaded'", "'config reload complete'",
                  "validate_ms ('config source loaded')",
                  "cohort_rib_transition_us ('reload generation phase timing')")


def daemon_reloads(daemon_log, name):
    """[(sighup_to_loaded_ms, sighup_to_complete_ms, validate_ms, rib_transition_ms)] per completed SIGHUP.

    SIGHUP and "config reload complete" must alternate strictly: a second
    SIGHUP before the first completes, a completion with no SIGHUP pending, or
    a SIGHUP still pending at the end of the log is an error naming NAME and
    the line, because any of them would shift every later interval."""
    reloads, start, started_at = [], None, 0
    for number, line in enumerate(read_text(daemon_log).splitlines(), 1):
        if not any(message in line for message in RELOAD_MESSAGES):
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        fields = record.get("fields", {})
        message = fields.get("message", "")
        where = f"{name}: {daemon_log.name} line {number}"
        if message.startswith("SIGHUP received"):
            if start is not None:
                raise ExtractionError(f"{where}: SIGHUP while the one at line {started_at} is still pending")
            start, started_at, loaded, validate, rib = log_time(record), number, None, None, None
        elif start is None:
            if message.startswith("config reload complete"):
                raise ExtractionError(f"{where}: reload complete with no SIGHUP pending")
            continue
        elif message == "config source loaded":
            loaded, validate = log_time(record), fields.get("validate_ms")
        elif message == "reload generation phase timing":
            rib = fields.get("cohort_rib_transition_us")
        elif message.startswith("config reload complete"):
            reloads.append((round((loaded - start) * 1000, 1) if loaded is not None else None,
                            round((log_time(record) - start) * 1000, 1), validate,
                            round(rib / 1000, 1) if rib is not None else None))
            start = None
    if start is not None:
        raise ExtractionError(f"{name}: {daemon_log.name} line {started_at}: SIGHUP never completed")
    return reloads


def reload_rows(leg, phase, arm, run, daemon_log, expected, campaign):
    if not daemon_log.exists():
        if campaign:
            raise ExtractionError(f"{leg.name}: {daemon_log.name} is missing, so its reload intervals are lost")
        return []
    reloads = daemon_reloads(daemon_log, leg.name)
    if len(reloads) != expected:
        raise ExtractionError(f"{leg.name}: daemon log has {len(reloads)} completed reloads, harness measured {expected}")
    rows = []
    for index, values in enumerate(reloads, 1):
        missing = [source for source, value in zip(RELOAD_SOURCES, values) if value is None]
        if missing:
            raise ExtractionError(f"{leg.name}: daemon log reload {index} lacks {', '.join(missing)}")
        for metric, value in zip(RELOAD_METRICS, values):
            rows.append([phase, arm, run, metric, index, value, "ms"])
    return rows


def cell_daemon(leg, cell):
    """The daemon a matrix cell measured, as its runner provenance names it.

    Legs without provenance.json predate it and measured rustbgpd."""
    provenance = cell / "provenance.json"
    daemon = json.loads(read_text(provenance)).get("cell") if provenance.exists() else "rustbgpd"
    if daemon not in DAEMONS:
        raise ExtractionError(f"{leg.name}: provenance.json names cell {daemon!r}, not one of {', '.join(DAEMONS)}")
    return daemon


def matrix_rows(source, exclusions, campaign):
    rows, spans = [], []
    for leg, (arm, run, scenario) in legs(source, "matrix", MATRIX, exclusions, QUEUE_MATRIX):
        cell = next((leg / d for d in DAEMONS if (leg / d).is_dir()), leg)
        status = cell / "status"
        if not status.exists() or read_text(status).strip() != "pass":
            continue
        log = read_text(cell / "reloadstall.log")
        phase = f"matrix-{scenario}"
        rustbgpd = cell_daemon(leg, cell) == "rustbgpd"
        counts, flap_rounds = {}, {}
        for metric, pattern, unit, required in MATRIX_LINES:
            values = re.findall(pattern, log, re.M)
            if scenario in required and not values:
                raise ExtractionError(f"{leg.name}: passing {scenario} leg has no '{metric}' line")
            counts[metric] = len(values)
            if metric.startswith("flap_"):
                values = [(int(round_), value) for round_, value in values]
                rounds = [round_ for round_, _ in values]
                if len(set(rounds)) != len(rounds):
                    raise ExtractionError(f"{leg.name}: duplicate flap round in '{metric}' lines")
                if scenario in required or values:
                    flap_rounds[metric] = frozenset(rounds)
            else:
                values = list(enumerate(values, 1))
            for index, value in values:
                rows.append([phase, arm, run, metric, index, value, unit])
        if scenario == "s2" and counts["reload_completion_p50"] != counts["reload_changed_maxgap_p50"]:
            raise ExtractionError(f"{leg.name}: reload completion and maxgap line counts differ")
        if scenario == "s2" and rustbgpd:
            rows += reload_rows(leg, phase, arm, run, cell / "daemon.log", counts["reload_completion_p50"], campaign)
        heap = [(int(round_), rest) for round_, rest in HEAP_LINE.findall(log)]
        if heap:
            rounds = [round_ for round_, _ in heap]
            if len(set(rounds)) != len(rounds):
                raise ExtractionError(f"{leg.name}: duplicate flap round in 'heap' lines")
            flap_rounds["heap"] = frozenset(rounds)
        for round_, rest in heap:
            fields = dict(token.partition("=")[::2] for token in rest.split())
            for metric, key in HEAP_FIELDS:
                value = fields.get(key)
                if value == "absent":
                    continue
                if value is None or not re.fullmatch(r"[0-9]+", value):
                    raise ExtractionError(f"{leg.name}: flap {round_} heap {key}={value!r} is neither an integer nor 'absent'")
                rows.append([phase, arm, run, metric, round_, value, "MiB"])
        if scenario == "s3" and len(set(flap_rounds.values())) != 1:
            raise ExtractionError(f"{leg.name}: flap metric rounds differ")
        rss = rss_column(cell / "rss.csv")
        if not rss:
            raise ExtractionError(f"{leg.name}: rss.csv has no samples")
        rows.append([phase, arm, run, "settled_rss_last_sample", "", rss[-1], "KiB"])
        rows.append([phase, arm, run, "peak_rss_sample", "", max(rss), "KiB"])
        rows += vmhwm_rows(cell / "vmhwm", phase, arm, run)
        # Legs recorded before the daemon ran in a swap-fenced scope have no cg_peak.
        # A leg run without a usable scope says so exactly; any other readout
        # must be the complete producer format, including the swap fence.
        if (cell / "cgroup-memory").exists():
            text = read_text(cell / "cgroup-memory")
            readout = CGROUP_MEMORY.fullmatch(text)
            if readout:
                rows.append([phase, arm, run, "daemon_cg_peak", "", readout.group(1), "KiB"])
            elif text != "cg_scope: unavailable\n":
                raise ExtractionError(
                    f"{leg.name}: cgroup-memory must be 'cg_scope: unavailable', the legacy peak/current/swap-fence readout, or the extended readout with all cg_last_sample_* and cg_teardown_* fields"
                )
        # Competitor cells recorded before the container readout have none.
        if (cell / "container-memory").exists():
            text = read_text(cell / "container-memory")
            readout = CONTAINER_MEMORY.fullmatch(text)
            if readout:
                rows.append([phase, arm, run, "container_cg_peak", "", readout.group(1), "KiB"])
            elif text != "container_cg: unavailable\n":
                raise ExtractionError(
                    f"{leg.name}: container-memory must be 'container_cg: unavailable' or the peak readout with a zero swap peak"
                )
        cg_current = cg_current_column(cell / "rss.csv")
        if cg_current:
            rows.append([phase, arm, run, "settled_cg_current_last_sample", "", cg_current[-1], "KiB"])
        daemon_log = cell / "daemon.log"
        if rustbgpd and daemon_log.exists():
            established = re.search(r"^established (\d+) at", log, re.M)
            if established is None:
                raise ExtractionError(f"{leg.name}: reloadstall.log has no 'established N at' line")
            spans.append([arm, run, scenario, *establishment_span(daemon_log, int(established.group(1)))])
    return rows, spans


def establishment_span(daemon_log, peers):
    stamps = []
    for line in read_text(daemon_log).splitlines():
        if '"session established"' in line:
            stamps.append(log_time(json.loads(line)))
    stamps.sort()
    span = f"{stamps[peers - 1] - stamps[0]:.3f}" if len(stamps) >= peers else ""
    return len(stamps), peers, span


def irr_rows(source, exclusions, campaign):
    rows = []
    for leg, (overlap, arm, run) in legs(source, "irr", IRR, exclusions, QUEUE_IRR):
        completed = leg / "COMPLETED"
        if not completed.exists() or json.loads(read_text(completed)).get("status") != "pass":
            continue
        phase = f"irr-ov{overlap}"
        provenance_path = leg / "provenance.json"
        if provenance_path.is_symlink() or not provenance_path.is_file():
            raise ExtractionError(f"{leg.name}: IRR provenance must be a regular file")
        provenance = json.loads(read_text(provenance_path))
        if not isinstance(provenance, dict) or provenance.get("schema") not in (2, 3):
            raise ExtractionError(f"{leg.name}: unknown IRR provenance schema")
        require_memory = provenance["schema"] == 3
        selected_cells = set()
        if require_memory:
            inputs = provenance.get("inputs")
            selected = inputs.get("cells") if isinstance(inputs, dict) else None
            if not isinstance(selected, str) or not selected:
                raise ExtractionError(f"{leg.name}: schema3 requires the selected cell roster")
            selected_cells = set(selected.split(","))
            if "rustbgpd-sighup" not in selected_cells or not selected_cells <= {"rustbgpd-sighup", "bird", "openbgpd"}:
                raise ExtractionError(f"{leg.name}: schema3 has an invalid headline cell roster")
        sighup = [r for r in csv.DictReader(read_text(leg / "rows.csv").splitlines()) if r["cell"] == "rustbgpd-sighup"]
        if not sighup:
            raise ExtractionError(f"{leg.name}: completed root has no rustbgpd-sighup rows")
        for row in sighup:
            rows.append([phase, arm, run, "completion_p50", row["reload"], row["completion_p50_s"], "s"])
            rows.append([phase, arm, run, "changed_maxgap_p50", row["reload"], row["changed_maxgap_p50_ms"], "ms"])
        rows += reload_rows(leg, phase, arm, run, leg / "rustbgpd-sighup" / "daemon.log", len(sighup), campaign)
        rss = leg / "rustbgpd-sighup" / "rss.csv"
        if rss.exists():
            rows.append([phase, arm, run, "peak_rss_sample", "", max(rss_column(rss)), "KiB"])
        rows += vmhwm_rows(leg / "rustbgpd-sighup" / "vmhwm", phase, arm, run)
        for cell, metric, filename, pattern, row_arm in (
            ("rustbgpd-sighup", "irr_daemon_cg_peak", "cgroup-memory", IRR_SCOPE_MEMORY, arm),
            ("bird", "irr_container_cg_peak", "container-memory", CONTAINER_MEMORY, "bird"),
            ("openbgpd", "irr_container_cg_peak", "container-memory", CONTAINER_MEMORY, "openbgpd"),
        ):
            path = leg / cell / filename
            window = leg / cell / "memory-window"
            if path.is_symlink() or window.is_symlink():
                raise ExtractionError(f"{leg.name}: {cell} memory readout/window must be regular files")
            if require_memory and cell not in selected_cells:
                if path.exists() or window.exists():
                    raise ExtractionError(f"{leg.name}: {cell} memory evidence is outside the selected cell roster")
                continue
            if not path.is_file():
                if (require_memory and cell in selected_cells) or path.exists() or window.exists():
                    raise ExtractionError(f"{leg.name}: {cell} requires its cgroup memory readout")
                continue  # Schema2 receipts may predate cgroup readouts.
            if not window.is_file() or read_text(window) != IRR_MEMORY_WINDOW:
                raise ExtractionError(f"{leg.name}: {cell} memory-window is not the measured harness window")
            text = read_text(path)
            if filename == "container-memory" and text == "container_cg: unavailable\n":
                continue
            readout = pattern.fullmatch(text)
            if not readout:
                raise ExtractionError(f"{leg.name}: {cell} {filename} requires an exact readout with zero actual swap peak")
            rows.append([phase, row_arm, run, metric, "", readout[1], "KiB"])
    return rows


def rr_rows(source, exclusions):
    rows = []
    for leg, (arm, campaign) in legs(source, "rr1000", RR, exclusions):
        completed = leg / "COMPLETED"
        if not completed.exists() or read_text(completed).split()[:1] != ["pass"]:
            continue
        attempts = sorted(leg.glob("run-*/phase.json"))
        if not attempts:
            raise ExtractionError(f"{leg.name}: completed campaign has no run-*/phase.json")
        for path in attempts:
            phase = json.loads(read_text(path))
            wire = phase["resource_observer"]["wire"]
            run = f"c{campaign}r{path.parent.name.removeprefix('run-')}"
            for key in ("injection_ms", "staged_ms", "wire_ms"):
                rows.append(["rr1000", arm, run, key, "", phase[key], "ms"])
            rows.append(["rr1000", arm, run, "wire_vmrss", "", wire["direct_pid_vmrss_kib"], "KiB"])
            rows.append(["rr1000", arm, run, "wire_vmhwm", "", wire["direct_pid_vmhwm_kib"], "KiB"])
    return rows


def extract(source, excludes=()):
    """Return (rows, spans, excluded leg names)."""
    listed = source / "EXCLUDED"
    lines = read_text(listed).splitlines() if listed.exists() else []
    globs = [entry for line in lines if (entry := line.split("#", 1)[0].strip())] + list(excludes)
    exclusions = (globs, [])
    campaign = (source / "arms.txt").exists() or (source / "legs").is_dir()
    matrix, spans = matrix_rows(source, exclusions, campaign)
    rows = matrix + irr_rows(source, exclusions, campaign) + rr_rows(source, exclusions)
    for glob in globs:
        if not any(fnmatch.fnmatch(name, glob) for name in exclusions[1]):
            raise ExtractionError(f"exclusion '{glob}' matches no leg")
    return rows, spans, exclusions[1]


def aggregate(rows, spans):
    """{(phase, metric): {arm: [values]}}, with S1 read from the S2 and S3 legs."""
    table = defaultdict(lambda: defaultdict(list))
    for phase, arm, _run, metric, _round, value, _unit in rows:
        if metric in ("established", "cold_convergence"):
            phase = "matrix-s1"
        table[(phase, metric)][arm].append(float(value))
    for arm, _run, _scenario, _count, _peers, span in spans:
        if span:
            table[("matrix-s1", "establishment_span")][arm].append(float(span))
    return table


def arm_order(source, table):
    arms_file = source / "arms.txt"
    if arms_file.exists():
        configured = [line.split("=", 1)[0] for line in read_text(arms_file).splitlines() if line]
        return configured + sorted({arm for cells in table.values() for arm in cells} - set(configured))
    return sorted({arm for cells in table.values() for arm in cells})


def report(table, arms, smoke, excluded):
    lines = []
    if smoke:
        lines += ["SMOKE run: pipeline check at a reduced shape, not a measurement.", ""]
    lines += ["| Phase | Metric | " + " | ".join(arms) + " |", "|---|---|" + "---:|" * len(arms)]
    for phase, metric in sorted(table):
        cells = []
        for arm in arms:
            values = table[(phase, metric)].get(arm)
            cells.append(
                f"{format_value(metric, min(values))}–{format_value(metric, max(values))} "
                f"(median {format_value(metric, statistics.median(values))}, n={len(values)})"
                if values else "-")
        lines.append(f"| {phase} | {metric} | " + " | ".join(cells) + " |")
    sources = sorted({metric for _phase, metric in table} & MEMORY_SOURCES.keys())
    if sources:
        lines += ["", "Memory sources:"]
        lines += [f"- `{metric}`: {MEMORY_SOURCES[metric]}." for metric in sources]
    lines += ["", "Excluded legs, not counted in n above:" if excluded else "Excluded legs: none."]
    lines += [f"- `{name}`" for name in excluded]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Extract a headline campaign's summary and table.")
    parser.add_argument("source", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--exclude", action="append", default=[])
    args = parser.parse_args(argv)
    if args.out is None and not (args.source / "arms.txt").exists():
        # A receipt bundle is history: write its re-extraction elsewhere.
        print(f"summarize: {args.source} is not a campaign directory; pass --out", file=sys.stderr)
        return 2
    out = args.out or args.source
    try:
        rows, spans, excluded = extract(args.source, args.exclude)
    except (ExtractionError, OSError, KeyError, ValueError) as error:
        print(f"summarize: {error}", file=sys.stderr)
        return 1
    if not rows:
        print(f"summarize: no finished legs under {args.source}", file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    with (out / "summary.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["phase", "arm", "run", "metric", "round", "value", "unit"])
        writer.writerows(rows)
    if spans:
        with (out / "establishment-span.csv").open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["arm", "run", "scenario", "session_established_log_lines", "peers",
                             "first_to_nth_established_s"])
            writer.writerows(spans)
    table = aggregate(rows, spans)
    text = report(table, arm_order(args.source, table), (args.source / "SMOKE").exists(), excluded)
    (out / "report.md").write_text(text)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
