#!/usr/bin/env python3
"""Fail-closed process inventory for the retained reload-stall receipt.

The receipt needs an idle host, but executable names alone are insufficient:
interpreters hide script names and Linux truncates ``comm`` to 15 bytes.  This
module therefore inspects argv, cwd, and descendant relationships for every
visible process.  It intentionally has no third-party dependencies so the
exact copy retained in the source archive can run before the measurement.
"""

from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


BUILD_NAMES = {
    "cargo",
    "cc",
    "ccache",
    "clang",
    "clang++",
    "cmake",
    "g++",
    "gcc",
    "go",
    "ld",
    "ld.lld",
    "lld",
    "make",
    "meson",
    "mold",
    "ninja",
    "rustc",
    "rustdoc",
    "sccache",
}
DAEMON_AND_BENCH_NAMES = {
    "bgperf2",
    "bird",
    "bird6",
    "codec",
    "event_history_producer",
    "evpn-monitor",
    "evpn-tester",
    "explain_snapshot",
    "fanout",
    "inbound_attrs",
    "nlri_build",
    "perf",
    "policy_eval",
    "rbgp",
    "reloadstall",
    "rib_nlri_build",
    "rib_ops",
    "route_paging",
    "rrharness",
    "rustbgpd",
    "validate",
}
INTERPRETER_NAMES = {"bash", "dash", "python", "python3", "sh", "zsh"}
KNOWN_NAMES = BUILD_NAMES | DAEMON_AND_BENCH_NAMES
RUSTBGPD_TREE_RE = re.compile(r"(?:^|/)rustbgpd(?:-[^/]*)?/")
TARGET_BINARY_RE = re.compile(r"/target/(?:debug|release)/(?:deps/)?[^/]+$")
HASH_SUFFIX_RE = re.compile(r"-[0-9a-f]{7,32}$")


@dataclass(frozen=True)
class Process:
    pid: int
    ppid: int
    comm: str
    argv: tuple[str, ...]
    cwd: str
    exe: str = ""

    @property
    def command(self) -> str:
        rendered = " ".join(self.argv) if self.argv else f"[{self.comm}]"
        return rendered.replace("\t", " ").replace("\n", " ")


def normalized_name(value: str) -> str:
    name = Path(value).name
    for suffix in (".py", ".sh"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return HASH_SUFFIX_RE.sub("", name)


def is_within(path: str, roots: tuple[str, ...]) -> bool:
    if not path:
        return False
    candidate = os.path.realpath(path)
    return any(candidate == root or candidate.startswith(root + os.sep) for root in roots)


def argument_path(process: Process, argument: str) -> str:
    if argument.startswith("/"):
        return os.path.realpath(argument)
    if "/" in argument and process.cwd:
        return os.path.realpath(os.path.join(process.cwd, argument))
    return ""


def direct_reason(process: Process, roots: tuple[str, ...]) -> str | None:
    names = {process.comm, normalized_name(process.comm)}
    names.update(normalized_name(argument) for argument in process.argv[:2])
    known = sorted(names & KNOWN_NAMES)
    if known:
        return f"known-executable:{known[0]}"

    argv0 = normalized_name(process.argv[0]) if process.argv else ""
    # New native tools must fail closed without first being added to a name
    # inventory. `/proc/<pid>/exe` is authoritative; argv[0] covers the same
    # case when procfs hides the executable symlink.
    executable_paths = [process.exe]
    if process.argv:
        executable_paths.append(argument_path(process, process.argv[0]))
    for normalized in executable_paths:
        if not normalized:
            continue
        if is_within(normalized, roots) or RUSTBGPD_TREE_RE.search(normalized):
            return "rustbgpd-root-executable"

    # Interpreters and launchers hide the executable in argv[1+]. Catch repo
    # benchmark scripts without classifying an editor merely because it opened
    # a source file under bench/.
    if argv0 in INTERPRETER_NAMES:
        for argument in process.argv[1:]:
            script_name = normalized_name(argument)
            if script_name in DAEMON_AND_BENCH_NAMES:
                return f"interpreted-benchmark:{script_name}"
            script_path = argument_path(process, argument)
            if script_path and (
                is_within(script_path, roots) or RUSTBGPD_TREE_RE.search(script_path)
            ) and "/bench/" in script_path:
                return "interpreted-rustbgpd-benchmark"

    # An unfamiliar binary launched from a Cargo target directory in one of
    # the exact source/build roots is still benchmark load and must fail closed.
    argv_path = argument_path(process, process.argv[0]) if process.argv else ""
    if argv_path and is_within(argv_path, roots) and TARGET_BINARY_RE.search(argv_path):
        return "source-target-binary"
    return None


def find_competitors(
    processes: Iterable[Process],
    ignored_pids: set[int],
    roots: Iterable[str],
) -> list[tuple[Process, str]]:
    records = {process.pid: process for process in processes}
    canonical_roots = tuple(sorted({os.path.realpath(root) for root in roots if root}))
    reasons: dict[int, str] = {}
    for process in records.values():
        if process.pid in ignored_pids:
            continue
        reason = direct_reason(process, canonical_roots)
        if reason:
            reasons[process.pid] = reason

    # Include every visible descendant of a competing process. This catches
    # helpers whose names/argv are generic after a benchmark launcher forks.
    changed = True
    while changed:
        changed = False
        for process in records.values():
            if process.pid in ignored_pids or process.pid in reasons:
                continue
            if process.ppid in reasons:
                reasons[process.pid] = f"descendant-of:{process.ppid}"
                changed = True

    return [(records[pid], reasons[pid]) for pid in sorted(reasons)]


def read_process(pid: int, proc_root: Path = Path("/proc")) -> Process | None:
    base = proc_root / str(pid)
    try:
        stat = (base / "stat").read_text(encoding="utf-8")
        close = stat.rfind(")")
        fields = stat[close + 2 :].split()
        if close < 0 or len(fields) < 2:
            return None
        ppid = int(fields[1])
        comm = (base / "comm").read_text(encoding="utf-8").strip()
        raw_argv = (base / "cmdline").read_bytes().split(b"\0")
        argv = tuple(
            value.decode("utf-8", errors="replace") for value in raw_argv if value
        )
        try:
            cwd = os.readlink(base / "cwd")
        except OSError:
            cwd = ""
        try:
            exe = os.readlink(base / "exe")
        except OSError:
            exe = ""
    except (OSError, UnicodeError, ValueError):
        return None
    return Process(pid=pid, ppid=ppid, comm=comm, argv=argv, cwd=cwd, exe=exe)


def scan_processes(proc_root: Path = Path("/proc")) -> list[Process]:
    records = []
    for entry in proc_root.iterdir():
        if entry.name.isdigit():
            record = read_process(int(entry.name), proc_root)
            if record is not None:
                records.append(record)
    return records


def ancestry(pid: int, records: Iterable[Process]) -> set[int]:
    by_pid = {process.pid: process for process in records}
    result: set[int] = set()
    while pid > 0 and pid not in result:
        result.add(pid)
        process = by_pid.get(pid)
        if process is None:
            break
        pid = process.ppid
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", action="append", default=[])
    args = parser.parse_args()
    records = scan_processes()
    competitors = find_competitors(records, ancestry(os.getpid(), records), args.root)
    for process, reason in competitors:
        print(f"{reason}\t{process.pid}\t{process.command}")
    return int(bool(competitors))


if __name__ == "__main__":
    raise SystemExit(main())
