#!/usr/bin/env python3
"""Run one isolated controlled-peer sequence-adoption proof; always tear it down."""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import time
import uuid
from dataclasses import asdict
from pathlib import Path

from evpn_peer_sync_oracle import Oracle, Route, duplicate_totals
from evpn_peer_sync_peer import CONTROLS, DUT, DUT_RD, IPS, LOCAL, MACS
from m94_as4_oracle import write_receipt

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "tests/interop/peer-sync/compose.yml"


def receipt_oracle(receipt: dict, run_id: str, command: int) -> Oracle:
    if (receipt.get("run_id") != run_id or not receipt.get("established")
            or receipt.get("error") or receipt.get("ack") != command
            or not 0 <= time.time() - receipt.get("heartbeat", 0) < 5):
        raise AssertionError("missing, stale, failed, or wrong-phase peer receipt")
    oracle = Oracle()
    oracle.events = receipt["events"]
    for row in receipt["live"]:
        route = Route(**{name: row[name] for name in asdict(LOCAL[0])})
        oracle.live[route.key()] = row
    return oracle


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="local DUT image with OCI revision label")
    parser.add_argument("--source-revision", required=True, help="exact DUT source commit")
    parser.add_argument("--raw-image", default="bmpsink:m102", help="existing Dockerfile.bmpsink image")
    parser.add_argument("--output", type=Path, required=True, help="new receipt directory")
    args = parser.parse_args()
    if not re.fullmatch("[0-9a-f]{40}", args.source_revision):
        parser.error("--source-revision must be a full commit SHA")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    run_id = uuid.uuid4().hex
    project = "evpn-peer-sync-" + run_id[:12]
    environment = {**os.environ, "PEER_SYNC_RECEIPT": str(output), "PEER_SYNC_RUN_ID": run_id}
    compose = ["docker", "compose", "-p", project, "-f", str(COMPOSE)]
    ledger = {"run_id": run_id, "project": project, "source_revision": args.source_revision,
              "harness_revision": subprocess.check_output(
                  ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "passed": False}

    def run(command: list[str], *, check: bool = True) -> str:
        try:
            result = subprocess.run(command, cwd=ROOT, env=environment, text=True,
                                    capture_output=True, timeout=60, check=False)
        except subprocess.TimeoutExpired as error:
            with (output / "commands.jsonl").open("a") as log:
                log.write(json.dumps({"command": command, "timeout": 60,
                                      "stdout": str(error.stdout), "stderr": str(error.stderr)}) + "\n")
            raise
        with (output / "commands.jsonl").open("a") as log:
            log.write(json.dumps({"command": command, "exit": result.returncode,
                                  "stdout": result.stdout, "stderr": result.stderr}) + "\n")
        if check and result.returncode:
            raise RuntimeError(f"command exited {result.returncode}: {command}; see commands.jsonl")
        return result.stdout

    def dut(*command: str) -> None:
        run([*compose, "exec", "-T", "dut", *command])

    def state(command: int) -> tuple[dict, Oracle]:
        receipt = json.loads((output / "peer.json").read_text())
        return receipt, receipt_oracle(receipt, run_id, command)

    def wait(command: int, assertion) -> tuple[dict, Oracle]:
        deadline = time.monotonic() + 35
        while True:
            try:
                receipt, oracle = state(command)
                assertion(receipt, oracle)
                return receipt, oracle
            except (FileNotFoundError, AssertionError) as error:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"wire condition failed: {error}") from error
                time.sleep(0.2)

    def send(command: int, sequence: int) -> tuple[dict, Oracle]:
        write_receipt(str(output / "command.json"),
                      {"run_id": run_id, "id": command, "sequence": sequence})
        return wait(command, lambda _receipt, _oracle: None)

    def metrics(name: str) -> None:
        # HTTP status/read errors propagate from the existing Python-equipped peer.
        scrape = run([*compose, "exec", "-T", "peer", "python3", "-c",
                      "import urllib.request; "
                      f"print(urllib.request.urlopen('http://{DUT}:9179/metrics', timeout=5).read().decode(), end='')"])
        (output / f"{name}.prom").write_text(scrape)
        totals = duplicate_totals(scrape)
        if any(row["total"] != 0 for row in totals.values()):
            raise AssertionError(f"duplicate accounting changed: {totals}")
        process = next(line for line in scrape.splitlines() if line.startswith("process_start_time_seconds "))
        if "process_start" in ledger and ledger["process_start"] != process:
            raise AssertionError("DUT restarted during proof")
        ledger["process_start"] = process
        ledger.setdefault("metrics", {})[name] = totals

    ledger["harness_dirty"] = bool(run(["git", "status", "--porcelain"]))
    started = False
    try:
        for name, reference in (("dut", args.image), ("raw", args.raw_image)):
            image = json.loads(run(["docker", "image", "inspect", reference]))[0]
            ledger[name + "_image"] = {key: image.get(key) for key in ("Id", "RepoDigests", "Created")}
            environment["PEER_SYNC_" + ("DUT" if name == "dut" else "RAW") + "_IMAGE"] = image["Id"]
            if name == "dut" and (image["Config"].get("Labels") or {}).get(
                    "org.opencontainers.image.revision") != args.source_revision:
                raise ValueError("DUT image OCI revision does not match --source-revision")
        network_ids = run(["docker", "network", "ls", "-q"]).split()
        if network_ids:
            for network in json.loads(run(["docker", "network", "inspect", *network_ids])):
                for config in network.get("IPAM", {}).get("Config") or []:
                    subnet = config.get("Subnet")
                    if subnet and ipaddress.ip_network(subnet).overlaps(ipaddress.ip_network("10.99.0.0/24")):
                        raise ValueError("proof subnet overlaps an existing Docker network")
        run([*compose, "config", "--quiet"])
        started = True
        run([*compose, "up", "-d", "--pull", "never"])
        dut("sh", "/start.sh", DUT, "10.99.0.2", "100")
        dut("bridge", "link", "set", "dev", "vxlan100", "neigh_suppress", "on")
        # Keep the deliberately installed reachable neighbors stable throughout the proof.
        dut("sh", "-ec", "echo 600000 > /proc/sys/net/ipv4/neigh/br100/base_reachable_time_ms; "
            "echo 600000 > /proc/sys/net/ipv6/neigh/br100/base_reachable_time_ms")
        wait(0, lambda _receipt, _oracle: None)
        metrics("baseline")
        first, _ = send(1, 3)
        time.sleep(12)  # At least two default originator polls before local observation.
        for name in "abcef":
            dut("bridge", "fdb", "replace", MACS[name], "dev", "ce100a", "master", "static")
        for name, addresses in IPS.items():
            for address in addresses:
                dut("ip", "neigh", "replace", address, "lladdr", MACS[name], "dev", "br100", "nud", "reachable")

        def adopted(receipt, oracle, sequence, checkpoint):
            oracle.expect_transition(LOCAL, sequence, next_hop=DUT, after=checkpoint)
            oracle.expect(CONTROLS, 0, next_hop=DUT)
            oracle.expect_owned_keys(LOCAL + CONTROLS, rd=DUT_RD)
            oracle.expect_never_owned(rd=DUT_RD, mac=MACS["d"])

        wait(1, lambda receipt, oracle: adopted(receipt, oracle, 3, first["checkpoint"]))
        time.sleep(12)
        receipt, oracle = state(1)
        adopted(receipt, oracle, 3, first["checkpoint"])
        metrics("sequence-3")
        raised, _ = send(2, 9)
        wait(2, lambda receipt, oracle: adopted(receipt, oracle, 9, raised["checkpoint"]))
        time.sleep(12)
        receipt, oracle = state(2)
        adopted(receipt, oracle, 9, raised["checkpoint"])
        metrics("sequence-9")
        # Exact replay and lower sequence must not cause even a transient export.
        for command, sequence in ((3, 9), (4, 3)):
            sent, _ = send(command, sequence)
            time.sleep(12)
            receipt, oracle = state(command)
            oracle.expect(LOCAL, 9, next_hop=DUT)
            oracle.expect(CONTROLS, 0, next_hop=DUT)
            oracle.expect_owned_keys(LOCAL + CONTROLS, rd=DUT_RD)
            oracle.expect_quiet(after=sent["checkpoint"], rd=DUT_RD)
            oracle.expect_never_owned(rd=DUT_RD, mac=MACS["d"])
            metrics(f"replay-{sequence}")
        # Remove C's actual local ownership, then replay the remote owner.
        for address in IPS["c"]:
            dut("ip", "neigh", "del", address, "dev", "br100")
        dut("bridge", "fdb", "del", MACS["c"], "dev", "ce100a", "master")
        wait(4, lambda _receipt, oracle: oracle.expect_absent(rd=DUT_RD, mac=MACS["c"]))
        sent, _ = send(5, 9)
        time.sleep(12)
        final, oracle = state(5)
        oracle.expect_absent(rd=DUT_RD, mac=MACS["c"])
        oracle.expect_owned_keys([route for route in LOCAL if route.mac != MACS["c"]] + CONTROLS,
                                 rd=DUT_RD)
        oracle.expect_never_owned(rd=DUT_RD, mac=MACS["d"])
        oracle.expect_quiet(after=sent["checkpoint"], rd=DUT_RD)
        metrics("after-age")
        ledger.update(passed=True, final_event_count=len(final["events"]))
    except BaseException as error:
        ledger["error"] = str(error)
        raise
    finally:
        cleanup_errors = []
        if started:
            for command in ([*compose, "logs", "--no-color"],
                            [*compose, "exec", "-T", "dut", "cat", "/var/log/rustbgpd.log"],
                            [*compose, "down", "--volumes", "--remove-orphans"],
                            [*compose, "down", "--volumes", "--remove-orphans"]):
                try:
                    run(command)
                except Exception as error:
                    cleanup_errors.append(str(error))
            for kind in ("container", "network"):
                try:
                    owned = run(["docker", kind, "ls", "-q", "--filter",
                                 f"label=com.docker.compose.project={project}",
                                 *(["-a"] if kind == "container" else [])])
                    if owned.strip():
                        cleanup_errors.append(f"owned {kind} remains: {owned.strip()}")
                except Exception as error:
                    cleanup_errors.append(str(error))
        ledger["cleanup_errors"] = cleanup_errors
        ledger["passed"] &= not cleanup_errors
        write_receipt(str(output / "result.json"), ledger)
        if cleanup_errors:
            raise RuntimeError(f"cleanup or log capture failed: {cleanup_errors}")
    print(f"PASS: controlled peer sequence adoption; receipt {output}")


if __name__ == "__main__":
    main()
