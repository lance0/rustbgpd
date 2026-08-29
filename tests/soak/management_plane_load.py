#!/usr/bin/env python3
"""Bounded management-plane load for the route-server flagship soak.

Four independent workers exercise the shipped HTTP and ``rbgp`` surfaces.
Only timing, disposition, byte count, and a payload digest are retained; the
potentially large response bodies never enter the JSONL evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import BinaryIO, Callable, Optional


OPERATIONS = ("metrics", "neighbor", "policy_stats", "rib_prefix")
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
MAX_RECORD_BYTES = 4096
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True)
class ProbeResult:
    exit_code: Optional[int]
    result: str
    byte_count: int
    sha256: str


def _payload_fingerprint(stream: BinaryIO) -> tuple[Optional[bytes], int, str]:
    """Hash a stream while retaining at most MAX_PAYLOAD_BYTES."""
    digest = hashlib.sha256()
    retained = bytearray()
    total = 0
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        digest.update(chunk)
        if len(retained) <= MAX_PAYLOAD_BYTES:
            remaining = MAX_PAYLOAD_BYTES + 1 - len(retained)
            retained.extend(chunk[:remaining])
    payload = bytes(retained) if total <= MAX_PAYLOAD_BYTES else None
    return payload, total, digest.hexdigest()


def validate_metrics(status: int, payload: Optional[bytes], byte_count: int) -> str:
    if status != 200:
        return "http_status"
    if byte_count == 0:
        return "empty"
    if payload is None:
        return "payload_too_large"
    return "ok"


def validate_cli_json(
    operation: str,
    payload: Optional[bytes],
    peer_count: int,
    route_prefix: str,
) -> str:
    if payload is None:
        return "payload_too_large"
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "json"
    if operation == "neighbor":
        if not isinstance(value, list):
            return "schema"
        return "ok" if len(value) == peer_count else "cardinality"
    if operation == "policy_stats":
        if not isinstance(value, dict) or not isinstance(value.get("chains"), list):
            return "schema"
        return "ok"
    if operation == "rib_prefix":
        if not isinstance(value, list):
            return "schema"
        if len(value) != 1 or not isinstance(value[0], dict):
            return "route"
        return "ok" if value[0].get("prefix") == route_prefix else "route"
    raise ValueError(f"unsupported CLI operation: {operation}")


def probe_metrics(
    url: str,
    timeout_seconds: float,
    opener: Callable[..., object] = urllib.request.urlopen,
) -> ProbeResult:
    status: Optional[int] = None
    try:
        with opener(url, timeout=timeout_seconds) as response:
            status = int(response.status)
            payload, byte_count, digest = _payload_fingerprint(response)
    except urllib.error.HTTPError as error:
        status = int(error.code)
        payload, byte_count, digest = _payload_fingerprint(error)
    except (TimeoutError, socket.timeout):
        return ProbeResult(None, "timeout", 0, EMPTY_SHA256)
    except urllib.error.URLError as error:
        if isinstance(error.reason, (TimeoutError, socket.timeout)):
            return ProbeResult(None, "timeout", 0, EMPTY_SHA256)
        return ProbeResult(None, "http_error", 0, EMPTY_SHA256)
    except OSError:
        return ProbeResult(None, "http_error", 0, EMPTY_SHA256)
    result = validate_metrics(status, payload, byte_count)
    return ProbeResult(status, result, byte_count, digest)


def run_cli_command(
    argv: list[str],
    operation: str,
    timeout_seconds: float,
    peer_count: int,
    route_prefix: str,
) -> ProbeResult:
    with tempfile.TemporaryFile() as stdout:
        try:
            completed = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=subprocess.DEVNULL,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            stdout.seek(0)
            _, byte_count, digest = _payload_fingerprint(stdout)
            return ProbeResult(None, "timeout", byte_count, digest)
        stdout.seek(0)
        payload, byte_count, digest = _payload_fingerprint(stdout)
    if completed.returncode != 0:
        return ProbeResult(completed.returncode, "cli_exit", byte_count, digest)
    result = validate_cli_json(operation, payload, peer_count, route_prefix)
    return ProbeResult(completed.returncode, result, byte_count, digest)


def cli_commands(rbgp: str, uds: str, route_prefix: str) -> dict[str, list[str]]:
    base = [rbgp, "-s", uds, "--json"]
    return {
        "neighbor": [*base, "neighbor"],
        "policy_stats": [*base, "policy", "stats", "--direction", "both"],
        "rib_prefix": [*base, "rib", "--prefix", route_prefix],
    }


class JsonlSink:
    """One bounded append per record; the terminal summary is fsynced."""

    def __init__(self, path: str) -> None:
        self._fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        self._lock = threading.Lock()

    def write(self, record: dict, *, terminal: bool = False) -> None:
        encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(encoded) > MAX_RECORD_BYTES:
            raise RuntimeError(f"management-plane JSONL record exceeds {MAX_RECORD_BYTES} bytes")
        with self._lock:
            written = os.write(self._fd, encoded)
            if written != len(encoded):
                raise RuntimeError("short management-plane JSONL append")
            if terminal:
                os.fsync(self._fd)

    def close(self) -> None:
        os.close(self._fd)


class ManagementPlaneLoad:
    def __init__(
        self,
        *,
        output: str,
        metrics_url: str,
        rbgp: str,
        uds: str,
        peer_count: int,
        route_prefix: str,
        metrics_interval_seconds: float,
        cli_interval_seconds: float,
        timeout_seconds: float,
    ) -> None:
        self.sink = JsonlSink(output)
        self.metrics_url = metrics_url
        self.peer_count = peer_count
        self.route_prefix = route_prefix
        self.timeout_seconds = timeout_seconds
        self.intervals = {
            "metrics": metrics_interval_seconds,
            "neighbor": cli_interval_seconds,
            "policy_stats": cli_interval_seconds,
            "rib_prefix": cli_interval_seconds,
        }
        self.commands = cli_commands(rbgp, uds, route_prefix)
        self.stop = threading.Event()
        self.counter_lock = threading.Lock()
        self.counts = {
            operation: {"scheduled": 0, "completed": 0, "missed": 0}
            for operation in OPERATIONS
        }
        self.started_monotonic = time.monotonic()
        self.stop_requested_monotonic: Optional[float] = None
        self.worker_error: Optional[str] = None

    def _mark(self, operation: str, field: str, amount: int = 1) -> None:
        with self.counter_lock:
            self.counts[operation][field] += amount

    def _probe(self, operation: str) -> ProbeResult:
        if operation == "metrics":
            return probe_metrics(self.metrics_url, self.timeout_seconds)
        return run_cli_command(
            self.commands[operation],
            operation,
            self.timeout_seconds,
            self.peer_count,
            self.route_prefix,
        )

    def request_stop(self) -> None:
        with self.counter_lock:
            if self.stop_requested_monotonic is None:
                self.stop_requested_monotonic = time.monotonic()
        self.stop.set()

    def _worker(self, operation: str) -> None:
        interval = self.intervals[operation]
        due = self.started_monotonic
        try:
            while not self.stop.is_set():
                delay = due - time.monotonic()
                if delay > 0 and self.stop.wait(delay):
                    break
                if self.stop.is_set():
                    break
                self._mark(operation, "scheduled")
                started = time.monotonic()
                result = self._probe(operation)
                completed = time.monotonic()
                self._mark(operation, "completed")
                self.sink.write({
                    "record": "operation",
                    "scheduled_monotonic": round(due, 6),
                    "started_monotonic": round(started, 6),
                    "completed_monotonic": round(completed, 6),
                    "operation": operation,
                    "duration_ms": round((completed - started) * 1000, 3),
                    "exit": result.exit_code,
                    "result": result.result,
                    "bytes": result.byte_count,
                    "sha256": result.sha256,
                })
                due += interval
                if self.stop.is_set():
                    break
                now = time.monotonic()
                if due <= now:
                    missed = math.floor((now - due) / interval) + 1
                    self._mark(operation, "scheduled", missed)
                    self._mark(operation, "missed", missed)
                    due += missed * interval
        except Exception as error:  # evidence and parent lifecycle handle failure
            self.worker_error = f"{operation}:{type(error).__name__}"
            self.stop.set()

    def run(self) -> int:
        self.sink.write({
            "record": "start",
            "started_monotonic": round(self.started_monotonic, 6),
            "operations": list(OPERATIONS),
            "interval_seconds": self.intervals,
            "timeout_seconds": self.timeout_seconds,
            "peer_count": self.peer_count,
            "route_prefix": self.route_prefix,
        })
        workers = [
            threading.Thread(
                target=self._worker,
                args=(operation,),
                name=operation,
                daemon=True,
            )
            for operation in OPERATIONS
        ]
        for worker in workers:
            worker.start()
        while not self.stop.wait(1.0):
            if self.worker_error is not None:
                break
        for worker in workers:
            worker.join(self.timeout_seconds + 1.0)
        if self.worker_error is not None or any(worker.is_alive() for worker in workers):
            self.sink.close()
            return 1
        completed_monotonic = time.monotonic()
        if self.stop_requested_monotonic is None:
            self.sink.close()
            return 1
        scheduled = {op: self.counts[op]["scheduled"] for op in OPERATIONS}
        completed = {op: self.counts[op]["completed"] for op in OPERATIONS}
        missed = {op: self.counts[op]["missed"] for op in OPERATIONS}
        self.sink.write({
            "record": "summary",
            "started_monotonic": round(self.started_monotonic, 6),
            "stop_requested_monotonic": round(self.stop_requested_monotonic, 6),
            "completed_monotonic": round(completed_monotonic, 6),
            "operation": "summary",
            "duration_ms": round(
                (completed_monotonic - self.started_monotonic) * 1000, 3
            ),
            "exit": 0,
            "result": "clean_sigterm",
            "bytes": 0,
            "sha256": EMPTY_SHA256,
            "signal": "SIGTERM",
            "scheduled": scheduled,
            "completed": completed,
            "missed": missed,
            "interval_seconds": self.intervals,
            "timeout_seconds": self.timeout_seconds,
            "peer_count": self.peer_count,
            "route_prefix": self.route_prefix,
        }, terminal=True)
        self.sink.close()
        return 0


def positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return parsed


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--metrics-url", required=True)
    parser.add_argument("--rbgp", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--peers", required=True, type=positive_int)
    parser.add_argument("--route-prefix", default="20.0.0.0/24")
    parser.add_argument("--metrics-interval", type=positive_float, default=1.0)
    parser.add_argument("--cli-interval", type=positive_float, default=5.0)
    parser.add_argument("--timeout", type=positive_float, default=5.0)
    args = parser.parse_args()

    load = ManagementPlaneLoad(
        output=args.output,
        metrics_url=args.metrics_url,
        rbgp=args.rbgp,
        uds=args.socket,
        peer_count=args.peers,
        route_prefix=args.route_prefix,
        metrics_interval_seconds=args.metrics_interval,
        cli_interval_seconds=args.cli_interval,
        timeout_seconds=args.timeout,
    )

    def stop_on_sigterm(_signum: int, _frame: object) -> None:
        load.request_stop()

    signal.signal(signal.SIGTERM, stop_on_sigterm)
    return load.run()


if __name__ == "__main__":
    raise SystemExit(main())
