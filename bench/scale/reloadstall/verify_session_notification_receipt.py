#!/usr/bin/env python3
"""Fail-closed verifier for the LAN-1162 flapstorm notification-depth receipt."""
import datetime, hashlib, json, math, re, subprocess, sys
from pathlib import Path
ROWS = [("initial_drained", 0, 700, 700, 399828)] + [row for r in range(1, 4) for row in (("round_start", r, 700, 0, 0), ("withdraw_drained", r, 650, 650, 28600), ("reannounce_drained", r, 700, 650, 28600))]
WORKLOAD = {"peers": 700, "prefixes": 400400, "flapped": 50, "rounds": 3}
FILES = {"harness.log", "initial.csv", "checkpoints.csv", "flapstorm.csv", "daemon-summary.json", "README.md", "verification.json"}
SOURCES = {"harness_main", "verifier", "harness_lock", "workspace_lock", "matrix_runner", "scenario_generator"}
BASE = "32664ee2e4a87052685b036befefdaa20ae8ef19"
BASE_TREE = "428101e3d6324667a75842bb1c9d851dc1768efd"
SOURCE_PATHS = {"harness_main":"bench/scale/reloadstall/src/main.rs", "verifier":"bench/scale/reloadstall/verify_session_notification_receipt.py", "harness_lock":"bench/scale/Cargo.lock", "workspace_lock":"Cargo.lock", "matrix_runner":"bench/scale/matrix/run-matrix.sh", "scenario_generator":"bench/scale/reloadstall/gen-scenario.py"}
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def directory_digest(root):
    files = sorted(path for path in root.rglob("*") if path.is_file())
    framed = b"".join(str(path.relative_to(root)).encode() + b"\0" + sha(path).encode() + b"\n" for path in files)
    return hashlib.sha256(framed).hexdigest()
def parse_rows(text):
    rows = []
    for line in text.splitlines():
        if not line.startswith("session_notification_receipt,"): continue
        parts = line.split(",")[1:]
        if len(parts) != 9 or any("=" not in part for part in parts): raise ValueError("malformed session notification row")
        fields = dict(part.split("=", 1) for part in parts)
        keys = {"stage", "round", "sessions", "completions", "target", "current", "high_watermark", "parse_errors", "drain_wait_us"}
        if set(fields) != keys: raise ValueError("malformed session notification row")
        try: numeric = tuple(int(fields[k]) for k in ("round", "sessions", "completions", "target", "current", "high_watermark", "parse_errors", "drain_wait_us"))
        except ValueError as error: raise ValueError("non-integer session notification row") from error
        if any(value < 0 for value in numeric): raise ValueError("negative session notification value")
        rows.append((fields["stage"], *numeric))
    if [(r[0], *r[1:5], r[5], r[7]) for r in rows] != [(*row, 0, 0) for row in ROWS]: raise ValueError("session notification row order or values changed")
    highs = [row[6] for row in rows]
    if any(value == 0 for value in highs) or highs != sorted(highs): raise ValueError("high-water marks must be positive and nondecreasing")
    if any(row[8] > 5_000_000 for row in rows): raise ValueError("drain wait exceeds checkpoint deadline")
    return rows
def exact_hash_map(items, keys, label):
    if set(items) != keys: raise ValueError(f"{label} roster changed")
    for name, item in items.items():
        if set(item) != {"path", "sha256"} or sha(Path(item["path"])) != item["sha256"]: raise ValueError(f"{label} hash mismatch: {name}")
def verify(root):
    receipt = json.loads((root / "receipt.json").read_text())
    required = {"repo", "commit", "tree", "base", "base_tree", "binaries", "sources", "artifacts", "workload", "command", "environment", "system", "raw_campaign_root"}
    if set(receipt) != required or receipt["workload"] != WORKLOAD or receipt["base"] != BASE or receipt["base_tree"] != BASE_TREE: raise ValueError("receipt schema, workload, or base changed")
    for key in ("commit", "tree", "base", "base_tree"):
        value = receipt[key]
        if len(value) != 40 or any(c not in "0123456789abcdef" for c in value): raise ValueError("provenance must use lowercase full object IDs")
    repo, commit = Path(receipt["repo"]), receipt["commit"]
    def git(*args): return subprocess.run(["git", "-C", repo, *args], check=True, text=True, capture_output=True).stdout.strip()
    if git("rev-parse", f"{commit}^{{commit}}") != commit or git("rev-parse", f"{commit}^{{tree}}") != receipt["tree"] or git("rev-parse", f"{receipt['base']}^{{tree}}") != receipt["base_tree"]: raise ValueError("commit/tree provenance mismatch")
    subprocess.run(["git", "-C", repo, "merge-base", "--is-ancestor", receipt["base"], commit], check=True)
    exact_hash_map(receipt["binaries"], {"daemon", "harness"}, "binary")
    if set(receipt["sources"]) != SOURCES: raise ValueError("source roster changed")
    for name, relative in SOURCE_PATHS.items():
        item, expected = receipt["sources"][name], (repo / relative).resolve()
        if set(item) != {"path", "sha256"} or Path(item["path"]).resolve() != expected or sha(expected) != item["sha256"] or hashlib.sha256(subprocess.run(["git", "-C", repo, "show", f"{commit}:{relative}"], check=True, capture_output=True).stdout).hexdigest() != item["sha256"]: raise ValueError(f"source path/blob mismatch: {name}")
    command = ["bash", "bench/scale/matrix/run-matrix.sh", "rustbgpd"]
    if receipt["command"] != command: raise ValueError("command changed")
    expected_env = {"N_PEERS":"700", "TOTAL_PREFIXES":"400400", "RELOADS":"0", "CONTROL_SECS":"30", "FLAPSTORM":"50", "ARTIFACTS_DIR":receipt["raw_campaign_root"]["path"], "RELOADSTALL_SESSION_NOTIFICATION_METRICS_ADDR":receipt["environment"].get("RELOADSTALL_SESSION_NOTIFICATION_METRICS_ADDR")}
    if receipt["environment"] != expected_env: raise ValueError("environment roster changed")
    if receipt["environment"]["RELOADSTALL_SESSION_NOTIFICATION_METRICS_ADDR"] != "127.0.0.1:9179": raise ValueError("metrics address changed")
    if set(receipt["system"]) != {"rustc", "cargo", "kernel", "cpu", "captured_at"} or any(not str(v).strip() for v in receipt["system"].values()): raise ValueError("system provenance changed")
    datetime.datetime.fromisoformat(receipt["system"]["captured_at"].replace("Z", "+00:00"))
    artifacts = receipt["artifacts"]
    if set(artifacts) != FILES or any(sha(root / name) != digest for name, digest in artifacts.items()): raise ValueError("compact artifact roster/hash mismatch")
    sums = {name.removeprefix("*"): digest for digest, name in (line.split(None, 1) for line in (root / "SHA256SUMS").read_text().splitlines())}
    if sums != artifacts: raise ValueError("SHA256SUMS roster changed")
    parse_rows((root / "harness.log").read_text())
    initial = (root / "initial.csv").read_text().splitlines()
    if initial != ["first_exact_bitmap,mode=flapstorm,peers=700,total=400400,per_peer=572,expected=399828,completed=700,min_unique=399828,max_unique=399828"]: raise ValueError("initial convergence CSV changed")
    flaps = (root / "flapstorm.csv").read_text().splitlines()
    if len(flaps) != 3: raise ValueError("flapstorm CSV row count changed")
    for i, line in enumerate(flaps, 1):
        tokens = line.split(",")
        if len(tokens) != 15 or tokens[:6] != ["flapstorm_csv", str(i), "700", "50", "400400", "28600"] or tokens[-2:] != ["700", "0"]: raise ValueError("flapstorm CSV changed or reports correctness errors")
        if any(not math.isfinite(float(token)) for token in tokens[6:13]): raise ValueError("non-finite flapstorm statistic")
    raw = receipt["raw_campaign_root"]; raw_path = Path(raw["path"]).resolve()
    if set(raw) != {"path", "sha256"} or raw_path == root.resolve() or root.resolve() in raw_path.parents or raw_path == repo.resolve() or repo.resolve() in raw_path.parents or directory_digest(raw_path) != raw["sha256"]: raise ValueError("raw campaign root/digest mismatch")
    run = raw_path / "rustbgpd"; logs = [run / "reloadstall.log", run / "daemon.log", run / "status"]
    paths = {path.relative_to(raw_path).as_posix() for path in raw_path.rglob("*") if path.is_file()}; required = {"rustbgpd/reloadstall.log", "rustbgpd/daemon.log", "rustbgpd/status"}
    if not required <= paths or any(path not in required and path != "rustbgpd/rss.csv" and not path.startswith("rustbgpd/scenario/") for path in paths): raise ValueError("raw layout changed")
    if logs[2].read_text() != "pass\n": raise ValueError("raw status is not lowercase pass")
    raw_harness = logs[0].read_text(); extract = lambda prefix: "\n".join(line for line in raw_harness.splitlines() if line.startswith(prefix)) + "\n"
    if (root / "initial.csv").read_text() != extract("first_exact_bitmap,") or (root / "checkpoints.csv").read_text() != extract("session_notification_receipt,") or (root / "flapstorm.csv").read_text() != extract("flapstorm_csv,"): raise ValueError("compact CSV differs from raw harness log")
    text = "\n".join(path.read_text(errors="replace") for path in logs).lower()
    sends = len(re.findall(r"send[^\n]*(?:error|fail)|(?:error|fail)[^\n]*send", text)); correctness = sum(text.count(token) for token in ("panicked", "panic", "correctness error", "fail:"))
    summary = {"notification_send_errors": sends, "correctness_errors": correctness, "raw_logs_sha256": hashlib.sha256(text.encode()).hexdigest()}
    if sends or correctness or json.loads((root / "daemon-summary.json").read_text()) != summary: raise ValueError("daemon summary/log scan reports errors")
    if json.loads((root / "verification.json").read_text()) != {"commit": commit, "verdict": "verified"}: raise ValueError("verification finalization changed")
if __name__ == "__main__":
    try: verify(Path(sys.argv[1]))
    except (OSError, KeyError, ValueError, subprocess.SubprocessError, IndexError) as error: print(f"FAIL: {error}", file=sys.stderr); sys.exit(1)
    print("session notification receipt verified")
