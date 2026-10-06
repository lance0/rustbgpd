#!/usr/bin/env python3
"""Run a command with observer TCP delayed on private loopback ingress."""

import argparse
import json
from pathlib import Path
import re
import signal
import subprocess
import time


DEVICE = "rbgpifb"
FLOWS = (("127.0.0.1", "127.1.0.0/16"), ("127.1.0.0/16", "127.0.0.1"))


def command(*args):
    return subprocess.check_output(args, text=True, timeout=10)


def private_namespace(host):
    current = str(Path("/proc/self/ns/net").readlink())
    if not re.fullmatch(r"net:\[[0-9]+\]", host) or current == host:
        raise ValueError("refusing netem in the host network namespace")
    return current


def configure(rtt):
    command("ip", "link", "set", "lo", "up")
    command("ip", "link", "add", "dev", DEVICE, "type", "ifb")
    command("ip", "link", "set", "dev", DEVICE, "up")
    command("tc", "qdisc", "add", "dev", DEVICE, "root", "netem",
            "delay", f"{rtt / 2:.3f}ms", "limit", "100000")
    command("tc", "qdisc", "add", "dev", "lo", "clsact")
    for priority, (source, destination) in enumerate(FLOWS, 10):
        command("tc", "filter", "add", "dev", "lo", "ingress", "protocol", "ip",
                "pref", str(priority), "flower", "skip_hw", "ip_proto", "tcp",
                "src_ip", source, "dst_ip", destination,
                "action", "mirred", "egress", "redirect", "dev", DEVICE)


def snapshot(out, phase):
    values = {}
    for name, args in (("qdisc", ("qdisc", "show")),
                       ("filters", ("filter", "show", "dev", "lo", "ingress"))):
        raw = command("tc", "-j", "-s", *args)
        (out / f"{phase}-{name}.json").write_text(raw)
        values[name] = json.loads(raw)
    return values


def verify(snapshot, rtt, traffic=False):
    queues = [q for q in snapshot["qdisc"] if q["kind"] == "netem"]
    if len(queues) != 1 or queues[0].get("dev") != DEVICE:
        raise ValueError("missing or unexpected netem queue")
    queue = queues[0]
    if abs(queue["options"]["delay"]["delay"] - rtt / 2000) > 0.000001:
        raise ValueError("netem delay differs from requested RTT")
    if queue["drops"] != 0 or (traffic and queue["packets"] <= 0):
        raise ValueError("netem queue dropped packets or carried no traffic")
    # iproute2 emits a classifier header followed by its concrete rule.
    filters = [rule for rule in snapshot["filters"] if "options" in rule]
    if len(filters) != 2:
        raise ValueError("expected exactly two observer ingress filters")
    for rule, (source, destination) in zip(sorted(filters, key=lambda f: f["pref"]), FLOWS):
        keys = rule["options"]["keys"]
        if (rule["kind"] != "flower" or rule["protocol"] != "ip"
                or set(keys) != {"eth_type", "ip_proto", "src_ip", "dst_ip"}
                or keys.get("eth_type") != "ipv4"
                or keys.get("ip_proto") != "tcp"
                or keys.get("src_ip", "").removesuffix("/32") != source
                or keys.get("dst_ip", "").removesuffix("/32") != destination):
            raise ValueError("wrong observer ingress filter")
        actions = rule["options"]["actions"]
        if len(actions) != 1:
            raise ValueError("unexpected ingress actions")
        action = actions[0]
        if (action["kind"], action["mirred_action"], action["direction"], action["to_dev"]) != (
                "mirred", "redirect", "egress", DEVICE):
            raise ValueError("wrong ingress redirect")
        if action["stats"]["drops"] != 0 or (traffic and action["stats"]["packets"] <= 0):
            raise ValueError("ingress filter dropped packets or carried no traffic")


def verify_rtt(text, rtt):
    values = [float(value) for value in re.findall(r"\brtt:([0-9.]+)/", text)]
    if not values or max(values) < rtt * 0.8:
        raise ValueError("no live observer TCP RTT evidence for the requested delay")


def run(args):
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    (out / "namespace").write_text(private_namespace(args.host_netns) + "\n")
    (out / "tcp_notsent_lowat").write_text(Path("/proc/sys/net/ipv4/tcp_notsent_lowat").read_text())
    configure(args.rtt)
    verify(snapshot(out, "before"), args.rtt)
    child = None
    interrupted = 0

    def stop(signum, _frame):
        nonlocal interrupted
        interrupted = signum
        if child is not None and child.poll() is None:
            child.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        child = subprocess.Popen(args.command)
        deadline = None
        next_socket_sample = 0.0
        observed_rtt = 0.0
        with (out / "ss-tcp-rtt.log").open("w") as stream:
            while child.poll() is None:
                if time.monotonic() >= next_socket_sample:
                    sockets = command("ss", "-tinH", "state", "established",
                                      "src", "127.0.0.1", "dst", "127.1.0.0/16")
                    stream.write(f"epoch_ns={time.time_ns()}\n{sockets}")
                    stream.flush()
                    values = [float(value) for value in re.findall(r"\brtt:([0-9.]+)/", sockets)]
                    observed_rtt = max([observed_rtt, *values])
                    next_socket_sample = time.monotonic() + 1
                if interrupted:
                    if deadline is None:
                        deadline = time.monotonic() + 5
                    if time.monotonic() >= deadline:
                        child.kill()
                time.sleep(0.1)
        rc = child.wait()
        (out / "workload.exit").write_text(f"{rc}\n")
        verify(snapshot(out, "after"), args.rtt, traffic=True)
        verify_rtt(f"rtt:{observed_rtt}/", args.rtt)
        return 128 + interrupted if interrupted else rc
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        # The caller owns namespace destruction, including partial setup.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtt", type=int, required=True)
    parser.add_argument("--host-netns", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command.pop(0)
    if not 0 < args.rtt <= 1000 or not args.command:
        parser.error("RTT must be 1–1000 ms and a command is required")
    raise SystemExit(run(args))


if __name__ == "__main__":
    main()
