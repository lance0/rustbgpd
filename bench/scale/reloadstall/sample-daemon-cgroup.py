#!/usr/bin/env python3
"""Fine-grained daemon-scope memory and scheduling trace, without metric scrapes."""

import argparse
import csv
import json
import os
import re
import subprocess
from pathlib import Path
import time


STAT_KEYS = ("anon", "sock", "file", "kernel", "slab", "pagetables")


def proc_stat(text):
    # comm may itself contain spaces and ')'; state is field 3.
    fields = text[text.rindex(")") + 2 :].split()
    return int(fields[19]), int(fields[11]) + int(fields[12])


def key_values(text):
    values = {}
    for line in text.splitlines():
        key, *fields = line.replace(":", " ").split()
        if key in values:
            raise ValueError(f"duplicate field: {key}")
        # /proc/status includes legitimate empty optional fields.
        values[key] = fields[0] if fields else ""
    return values


def find_pid(exe):
    found = []
    for proc in Path("/proc").iterdir():
        if proc.name.isdigit():
            try:
                if (proc / "exe").readlink() == exe:
                    found.append(int(proc.name))
            except OSError:
                pass
    if len(found) > 1:
        raise ValueError("multiple matching daemons; use a dedicated experimental binary")
    return found[0] if found else None


def container_owner(cid, image, exe):
    if not re.fullmatch(r"[0-9a-f]{64}", cid):
        raise ValueError("container ownership requires a full container ID")
    inspected = json.loads(subprocess.check_output(
        ["docker", "inspect", cid], text=True, timeout=10))
    if len(inspected) != 1:
        raise ValueError("ambiguous container identity")
    data = inspected[0]
    pid = data["State"]["Pid"]
    host = data["HostConfig"]
    if (data["Id"] != cid or data["Image"] != image or not data["State"]["Running"]
            or pid <= 0 or host["NetworkMode"] != "none" or host["PidMode"]
            or host["Memory"] <= 0 or host["MemorySwap"] != host["Memory"]):
        raise ValueError("container identity, isolation or equal memory/swap caps differ")
    proc = Path(f"/proc/{pid}")
    binary = exe.stat()
    if not os.path.samestat((proc / "exe").stat(), binary):
        raise ValueError("container is not running the owned daemon binary")
    identity, _ = proc_stat((proc / "stat").read_text())
    unified = (proc / "cgroup").read_text().strip()
    if not unified.startswith("0::/") or "\n" in unified:
        raise ValueError("container must have one cgroup v2 membership")
    cgroup = Path("/sys/fs/cgroup") / unified[4:]
    if cgroup.name not in {cid, f"docker-{cid}.scope"}:
        raise ValueError("cgroup does not belong to the exact owned container")
    if int((cgroup / "memory.max").read_text()) != host["Memory"]:
        raise ValueError("container cgroup memory cap differs from Docker")
    return {"kind": "container-daemon-only", "cid": cid, "image": image,
            "pid": pid, "starttime": identity, "cgroup": str(cgroup),
            "binary_device": binary.st_dev, "binary_inode": binary.st_ino,
            "inspect": data}


def verify_container_membership(proc, cgroup, pid, owner):
    if (proc_stat((proc / "stat").read_text())[0] != owner["starttime"]
            or str(cgroup) != owner["cgroup"]
            or (proc / "cgroup").read_text().strip() != "0::" + str(cgroup).removeprefix("/sys/fs/cgroup")):
        raise ValueError("container daemon PID/start/cgroup ownership changed")
    if (cgroup / "memory.swap.max").read_text().strip() != "0":
        raise ValueError("container daemon must be swap fenced")
    if {int(p) for p in (cgroup / "cgroup.procs").read_text().split()} != {pid}:
        raise ValueError("container daemon must be the sole process in its cgroup")
    if any(p.read_text().strip() for p in cgroup.glob("*/**/cgroup.procs")):
        raise ValueError("container daemon cgroup has populated descendants")


def sample(pid, out, interval, expected_pgid=None, owner=None):
    proc = Path(f"/proc/{pid}")
    identity, _ = proc_stat((proc / "stat").read_text())
    memberships = (proc / "cgroup").read_text().splitlines()
    unified = [line.removeprefix("0::") for line in memberships if line.startswith("0::")]
    if len(unified) != 1:
        raise ValueError("daemon must have exactly one cgroup v2 membership")
    cgroup = Path("/sys/fs/cgroup") / unified[0].lstrip("/")
    if owner is not None:
        verify_container_membership(proc, cgroup, pid, owner)
    elif not cgroup.name.endswith(".scope") or (cgroup / "memory.swap.max").read_text().strip() != "0":
        raise ValueError("daemon must run in its own swap-fenced systemd scope")
    if {int(member) for member in (cgroup / "cgroup.procs").read_text().split()} != {pid}:
        raise ValueError("daemon must be the sole process in its measurement scope")
    pgid = os.getpgid(pid)
    if expected_pgid is not None and pgid != expected_pgid:
        raise ValueError("daemon escaped the owned matrix process group")
    print(f"pid={pid} pgid={pgid} starttime={identity} cgroup={cgroup}", flush=True)
    clock_ticks = os.sysconf("SC_CLK_TCK")
    if clock_ticks <= 0:
        raise ValueError("invalid SC_CLK_TCK")
    # Retain vanished threads' last observed counters, and distinguish TID reuse.
    switches = {}
    with out.open("x", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow([
            "epoch_us", "monotonic_ns", "read_us", "vmrss_kib", "vmhwm_kib",
            "current_before_bytes", "current_after_bytes", "peak_bytes",
            *[f"{key}_bytes" for key in STAT_KEYS], "cpu_seconds",
            "voluntary_switches", "involuntary_switches", "threads_read", "threads_raced",
        ])
        deadline = time.monotonic()
        while proc.exists():
            epoch_us, started = time.time_ns() // 1000, time.monotonic_ns()
            try:
                current_identity, cpu_ticks = proc_stat((proc / "stat").read_text())
                if current_identity != identity:
                    if owner is not None:
                        raise ValueError("container daemon PID was reused")
                    break
                status = key_values((proc / "status").read_text())
                if status["State"] == "Z":
                    break
                if owner is not None:
                    verify_container_membership(proc, cgroup, pid, owner)
                before = int((cgroup / "memory.current").read_text())
                stat = key_values((cgroup / "memory.stat").read_text())
                after = int((cgroup / "memory.current").read_text())
                peak = int((cgroup / "memory.peak").read_text())
                threads_read, threads_raced = 0, 0
                for task in (proc / "task").iterdir():
                    try:
                        starttime, _ = proc_stat((task / "stat").read_text())
                        thread = key_values((task / "status").read_text())
                        switches[(task.name, starttime)] = (
                            int(thread["voluntary_ctxt_switches"]),
                            int(thread["nonvoluntary_ctxt_switches"]),
                        )
                        threads_read += 1
                    except FileNotFoundError:
                        threads_raced += 1
                writer.writerow([
                    epoch_us, started, (time.monotonic_ns() - started) // 1000,
                    int(status["VmRSS"]), int(status["VmHWM"]), before, after, peak,
                    *[int(stat[key]) for key in STAT_KEYS], cpu_ticks / clock_ticks,
                    sum(pair[0] for pair in switches.values()),
                    sum(pair[1] for pair in switches.values()), threads_read, threads_raced,
                ])
                stream.flush()
            except FileNotFoundError:
                if not proc.exists():
                    break
                try:
                    state = key_values((proc / "status").read_text())["State"]
                except FileNotFoundError:
                    break
                if state == "Z":
                    break
                raise
            deadline += interval
            time.sleep(max(0, deadline - time.monotonic()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=0.025)
    parser.add_argument("--wait", type=float, default=600)
    parser.add_argument("--expected-pgid", type=int)
    parser.add_argument("--container-cidfile", type=Path)
    parser.add_argument("--image-id")
    args = parser.parse_args()
    if not 0.01 <= args.interval <= 0.1 or not 0 < args.wait <= 600:
        parser.error("interval must be 0.01–0.1 s and wait must be > 0 and <= 600 s")
    exe, deadline = args.exe.resolve(strict=True), time.monotonic() + args.wait
    if args.container_cidfile:
        if args.expected_pgid is not None or not args.image_id:
            parser.error("container mode needs image-id and cannot use expected-pgid")
        cid = args.container_cidfile.read_text().strip()
        owner = container_owner(cid, args.image_id, exe)
        verify_container_membership(Path(f"/proc/{owner['pid']}"), Path(owner["cgroup"]), owner["pid"], owner)
        args.out.with_suffix(".owner.json").write_text(json.dumps(owner, indent=2) + "\n")
        sample(owner["pid"], args.out, args.interval, owner=owner)
        return
    while (pid := find_pid(exe)) is None:
        if time.monotonic() >= deadline:
            raise TimeoutError("experimental daemon did not start")
        time.sleep(0.05)
    sample(pid, args.out, args.interval, args.expected_pgid)


if __name__ == "__main__":
    main()
