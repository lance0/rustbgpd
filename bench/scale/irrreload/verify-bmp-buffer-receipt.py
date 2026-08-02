#!/usr/bin/env python3
"""Verify the two-run IRR-scale BMP Loc-RIB buffer receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

EXPECTED_EORS = [[1, 1], [2, 1], [1, 128], [2, 128]]
EXPECTED_SHAPE = {
    "n_members": 320,
    "total_prefixes": 183040,
    "seed": 61,
    "min_list": 1000,
    "max_list": 40000,
    "changed_fraction": 0.1,
    "total_filter_entries": 3218965,
    "admit_churn": True,
    "bmp_collector": "127.0.0.1:11019",
    "bmp_version": 3,
    "bmp_view": "loc_rib",
}
EXPECTED_RUNTIME_FILES = ["config.toml", "member.rpol", "gen-a.rpol", "gen-b.rpol"]
EXPECTED_RUN_FILES = {
    "daemon.log",
    "manifest.json",
    "metrics.prom",
    "receipt.json",
    "reloadstall.log",
    "scenario.sha256",
    "sink.log",
    "summary.json",
}
MAX_FRAME_BYTES = 1 << 20
MAX_CAPTURE_BYTES = 1 << 30
METRIC_RE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([-+0-9.eE]+)$")
LABEL_RE = re.compile(r'(\w+)="([^"]*)"')


class VerifyError(RuntimeError):
    """Retained evidence did not satisfy the contract."""


def load_json(path: pathlib.Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise VerifyError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise VerifyError(f"{path} is not a JSON object")
    return value


def parse_metrics(path: pathlib.Path) -> list[tuple[str, dict[str, str], float]]:
    samples = []
    try:
        lines = path.read_text().splitlines()
    except OSError as error:
        raise VerifyError(f"cannot read {path}: {error}") from error
    for line in lines:
        if not line or line.startswith("#"):
            continue
        match = METRIC_RE.fullmatch(line)
        if match is None:
            continue
        labels = dict(LABEL_RE.findall(match.group(2) or ""))
        samples.append((match.group(1), labels, float(match.group(3))))
    return samples


def metric_value(
    samples: list[tuple[str, dict[str, str], float]],
    name: str,
    collector: str,
) -> float:
    matches = [
        value
        for metric, labels, value in samples
        if metric == name and labels.get("collector") == collector
    ]
    if len(matches) != 1:
        raise VerifyError(f"expected one {name} sample for {collector}, got {len(matches)}")
    return matches[0]


def drop_samples(
    samples: list[tuple[str, dict[str, str], float]], collector: str
) -> list[tuple[dict[str, str], float]]:
    return [
        (labels, value)
        for metric, labels, value in samples
        if metric == "bmp_collector_drops_total" and labels.get("collector") == collector
    ]


def require_integer(value: float, what: str) -> int:
    integer = int(value)
    if value != integer:
        raise VerifyError(f"{what} is not an integer: {value}")
    return integer


def verify_manifest(manifest: dict) -> str:
    for key, expected in EXPECTED_SHAPE.items():
        if manifest.get(key) != expected:
            raise VerifyError(f"manifest {key}={manifest.get(key)!r}, expected {expected!r}")
    digest = manifest.get("dataset_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise VerifyError("manifest dataset digest is missing or malformed")
    if manifest.get("cell") != "rustbgpd" or manifest.get("path_hiding") is not True:
        raise VerifyError("manifest is not the canonical rustbgpd comparison cell")
    if manifest.get("runtime_files") != EXPECTED_RUNTIME_FILES:
        raise VerifyError("manifest runtime-file roster is not exact")
    return digest


def verify_scenario_roster(run: pathlib.Path, manifest: dict) -> str:
    path = run / "scenario.sha256"
    entries = {}
    try:
        lines = path.read_text().splitlines()
    except OSError as error:
        raise VerifyError(f"cannot read {path}: {error}") from error
    for line in lines:
        digest, separator, relative = line.partition("  ")
        if (
            not separator
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or relative in entries
            or pathlib.PurePosixPath(relative).is_absolute()
            or ".." in pathlib.PurePosixPath(relative).parts
        ):
            raise VerifyError("scenario checksum roster is malformed or unsafe")
        entries[relative] = digest
    expected = sorted([*manifest["runtime_files"], "manifest.json"])
    if sorted(entries) != expected:
        raise VerifyError("scenario checksum roster does not match runtime inputs")
    manifest_digest = hashlib.sha256((run / "manifest.json").read_bytes()).hexdigest()
    if entries["manifest.json"] != manifest_digest:
        raise VerifyError("scenario checksum roster does not bind manifest.json")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_common(summary: dict) -> None:
    if summary.get("schema") != 1:
        raise VerifyError("unsupported sink-summary schema")
    captured = summary.get("captured_bytes")
    if not isinstance(captured, int) or not 0 < captured <= MAX_CAPTURE_BYTES:
        raise VerifyError("capture byte count is outside 1..1GiB")
    if summary.get("initiation") != 1 or summary.get("loc_rib_peer_up") != 1:
        raise VerifyError("generation lacks its exact Initiation/Loc-RIB Peer Up roster")
    if summary.get("base_duplicates") != 0 or summary.get("base_withdrawals") != 0:
        raise VerifyError("base inventory contains a duplicate or withdrawal")
    eors = summary.get("eors")
    if not isinstance(eors, list) or eors != EXPECTED_EORS[: len(eors)]:
        raise VerifyError("End-of-RIB sequence is not an exact ordered prefix")


def verify_run(run: pathlib.Path) -> dict:
    try:
        run_files = {path.name for path in run.iterdir() if path.is_file()}
    except OSError as error:
        raise VerifyError(f"cannot enumerate {run}: {error}") from error
    if run_files != EXPECTED_RUN_FILES:
        raise VerifyError("run evidence file roster is not exact")
    manifest = load_json(run / "manifest.json")
    dataset_digest = verify_manifest(manifest)
    scenario_digest = verify_scenario_roster(run, manifest)
    summary = load_json(run / "summary.json")
    receipt = load_json(run / "receipt.json")
    verify_common(summary)
    samples = parse_metrics(run / "metrics.prom")
    collector = EXPECTED_SHAPE["bmp_collector"]
    depth = require_integer(
        metric_value(samples, "bmp_loc_rib_dump_live_buffer_depth", collector),
        "buffer depth",
    )
    high_watermark = require_integer(
        metric_value(samples, "bmp_loc_rib_dump_live_buffer_high_watermark", collector),
        "buffer high watermark",
    )
    replay = require_integer(
        metric_value(samples, "bmp_replay_attempts_total", collector), "replay count"
    )
    if depth != 0 or replay != 1:
        raise VerifyError(f"expected depth=0/replay=1, got depth={depth}/replay={replay}")
    drops = drop_samples(samples, collector)
    outcome = summary.get("outcome")
    if receipt.get("outcome") != outcome:
        raise VerifyError("runner and sink disagree on outcome")
    if receipt.get("collector") != collector:
        raise VerifyError("runner collector identity mismatch")
    if receipt.get("timeout_seconds") != 600:
        raise VerifyError("runner did not retain the 600-second bound")
    if not isinstance(receipt.get("daemon_pid"), int) or receipt["daemon_pid"] <= 0:
        raise VerifyError("missing daemon PID identity")
    if not isinstance(receipt.get("daemon_start_ticks"), int) or receipt["daemon_start_ticks"] <= 0:
        raise VerifyError("missing daemon start identity")
    if not isinstance(receipt.get("commit"), str) or not re.fullmatch(
        r"[0-9a-f]{40}", receipt["commit"]
    ):
        raise VerifyError("missing exact source commit")

    if outcome == "complete":
        if summary.get("base_prefixes") != EXPECTED_SHAPE["total_prefixes"]:
            raise VerifyError("complete dump does not contain the exact base inventory")
        if summary.get("eors") != EXPECTED_EORS:
            raise VerifyError("complete dump does not contain four exact ordered EoRs")
        if not summary.get("post_eor_churn") or not summary.get("complete_handshake"):
            raise VerifyError("complete dump lacks post-EoR churn handshake")
        if not summary.get("generation_open_at_summary"):
            raise VerifyError("complete generation was not open at sink summary")
        if receipt.get("generation_open_at_scrape") is not True:
            raise VerifyError("complete generation was not open at metric scrape")
        if not 1 <= high_watermark <= 8192:
            raise VerifyError(f"complete high watermark outside 1..8192: {high_watermark}")
        if any(value != 0 for _, value in drops):
            raise VerifyError("complete generation recorded a BMP drop")
    elif outcome == "overflow":
        base_prefixes = summary.get("base_prefixes")
        if not isinstance(base_prefixes, int) or not 0 < base_prefixes <= 183040:
            raise VerifyError("overflow generation lacks a bounded partial/base inventory")
        if summary.get("post_eor_churn") or summary.get("complete_handshake"):
            raise VerifyError("overflow generation reached the complete handshake")
        if summary.get("generation_open_at_summary"):
            raise VerifyError("overflow summary was written before EOF")
        if receipt.get("generation_open_at_scrape") is not False:
            raise VerifyError("overflow generation remained open at metric scrape")
        if high_watermark != 8193:
            raise VerifyError(f"overflow high watermark is {high_watermark}, expected 8193")
        live_buffer_drop = 0
        other_drop = 0
        for labels, value in drops:
            if labels.get("phase") == "loc_rib_dump" and labels.get("reason") == "live_buffer_full":
                live_buffer_drop += require_integer(value, "live-buffer-full discard")
            else:
                other_drop += require_integer(value, "other BMP drop")
        if live_buffer_drop != 8193 or other_drop != 0:
            raise VerifyError(
                f"overflow drops live_buffer_full={live_buffer_drop}, other={other_drop}"
            )
    else:
        raise VerifyError(f"unknown outcome {outcome!r}")
    return {
        "outcome": outcome,
        "dataset_sha256": dataset_digest,
        "commit": receipt["commit"],
        "process_identity": [receipt["daemon_pid"], receipt["daemon_start_ticks"]],
        "scenario_roster_sha256": scenario_digest,
        "buffer_high_watermark": high_watermark,
        "captured_bytes": summary["captured_bytes"],
    }


def verify_provenance(root: pathlib.Path) -> dict:
    provenance = load_json(root / "provenance.json")
    if provenance.get("schema") != 1:
        raise VerifyError("unsupported root provenance schema")
    if provenance.get("runs") != ["run-a", "run-b"]:
        raise VerifyError("root provenance run roster is not exact")
    if provenance.get("order") != "fresh-sequential":
        raise VerifyError("root provenance does not require fresh sequential runs")
    commit = provenance.get("commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise VerifyError("root provenance commit is missing or malformed")
    return provenance


def verify_seal(root: pathlib.Path, verification: dict, *, required: bool) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise VerifyError(f"retained receipt contains a symlink: {path.relative_to(root)}")
    roster = root / "SHA256SUMS"
    if not required:
        return
    if not roster.is_file():
        raise VerifyError("sealed receipt is missing SHA256SUMS")
    completed = root / "COMPLETED"
    if not completed.is_file() or completed.read_text() != "pass\n":
        raise VerifyError("sealed receipt is missing its exact COMPLETED marker")
    if load_json(root / "verification.json") != verification:
        raise VerifyError("retained verification.json does not match recomputed results")
    expected = {}
    for line in roster.read_text().splitlines():
        digest, separator, relative = line.partition("  ")
        if (
            not separator
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or relative in expected
            or pathlib.PurePosixPath(relative).is_absolute()
            or ".." in pathlib.PurePosixPath(relative).parts
        ):
            raise VerifyError("malformed, duplicate, or unsafe SHA256SUMS entry")
        expected[relative] = digest
    exact_paths = {"COMPLETED", "provenance.json", "verification.json"}
    for run_name in ("run-a", "run-b"):
        exact_paths.update(f"{run_name}/{name}" for name in EXPECTED_RUN_FILES)
    actual_paths = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    if set(actual_paths) != exact_paths or set(expected) != exact_paths:
        raise VerifyError("sealed receipt file/checksum roster is not exact")
    for relative, digest in expected.items():
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if actual != digest:
            raise VerifyError(f"checksum mismatch: {relative}")


def verify_root(root: pathlib.Path, *, require_seal: bool = False) -> dict:
    if not root.is_dir():
        raise VerifyError(f"receipt root is not a directory: {root}")
    provenance = verify_provenance(root)
    runs = [verify_run(root / "run-a"), verify_run(root / "run-b")]
    if runs[0]["outcome"] != runs[1]["outcome"]:
        raise VerifyError("the two fresh sequential runs disagree on outcome class")
    if runs[0]["dataset_sha256"] != runs[1]["dataset_sha256"]:
        raise VerifyError("the two runs used different canonical datasets")
    if runs[0]["commit"] != runs[1]["commit"]:
        raise VerifyError("the two runs used different source commits")
    if runs[0]["process_identity"] == runs[1]["process_identity"]:
        raise VerifyError("the two runs reused a daemon process identity")
    if any(run["commit"] != provenance["commit"] for run in runs):
        raise VerifyError("root provenance commit does not match both run receipts")
    verification = {
        "schema": 1,
        "status": "pass",
        "outcome": runs[0]["outcome"],
        "runs": runs,
    }
    verify_seal(root, verification, required=require_seal)
    return verification


def metric_fixture(outcome: str, high: int) -> str:
    collector = EXPECTED_SHAPE["bmp_collector"]
    lines = [
        f'bmp_loc_rib_dump_live_buffer_depth{{collector="{collector}"}} 0',
        f'bmp_loc_rib_dump_live_buffer_high_watermark{{collector="{collector}"}} {high}',
        f'bmp_replay_attempts_total{{collector="{collector}"}} 1',
    ]
    if outcome == "overflow":
        lines.append(
            f'bmp_collector_drops_total{{collector="{collector}",phase="loc_rib_dump",reason="live_buffer_full"}} 8193'
        )
    return "\n".join(lines) + "\n"


def make_fixture(run: pathlib.Path, outcome: str, identity: tuple[int, int]) -> None:
    run.mkdir(parents=True)
    manifest = dict(EXPECTED_SHAPE)
    manifest.update(
        {
            "cell": "rustbgpd",
            "path_hiding": True,
            "dataset_sha256": "a" * 64,
            "runtime_files": EXPECTED_RUNTIME_FILES,
        }
    )
    summary = {
        "schema": 1,
        "outcome": outcome,
        "captured_bytes": MAX_FRAME_BYTES,
        "initiation": 1,
        "loc_rib_peer_up": 1,
        "base_prefixes": 183040 if outcome == "complete" else 100,
        "base_duplicates": 0,
        "base_withdrawals": 0,
        "churn_announces": 1 if outcome == "complete" else 0,
        "churn_withdrawals": 0,
        "eors": EXPECTED_EORS if outcome == "complete" else EXPECTED_EORS[:2],
        "post_eor_churn": outcome == "complete",
        "complete_handshake": outcome == "complete",
        "generation_open_at_summary": outcome == "complete",
    }
    receipt = {
        "outcome": outcome,
        "collector": EXPECTED_SHAPE["bmp_collector"],
        "timeout_seconds": 600,
        "daemon_pid": identity[0],
        "daemon_start_ticks": identity[1],
        "commit": "b" * 40,
        "generation_open_at_scrape": outcome == "complete",
    }
    (run / "manifest.json").write_text(json.dumps(manifest))
    manifest_digest = hashlib.sha256((run / "manifest.json").read_bytes()).hexdigest()
    scenario = {name: "c" * 64 for name in EXPECTED_RUNTIME_FILES}
    scenario["manifest.json"] = manifest_digest
    (run / "scenario.sha256").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(scenario.items()))
    )
    (run / "summary.json").write_text(json.dumps(summary))
    (run / "receipt.json").write_text(json.dumps(receipt))
    (run / "metrics.prom").write_text(
        metric_fixture(outcome, 7 if outcome == "complete" else 8193)
    )
    for name in ("daemon.log", "reloadstall.log", "sink.log"):
        (run / name).write_text("")


def write_provenance(root: pathlib.Path) -> None:
    document = {"schema": 1, "commit": "b" * 40, "runs": ["run-a", "run-b"], "order": "fresh-sequential"}
    (root / "provenance.json").write_text(json.dumps(document))


def seal_fixture(root: pathlib.Path) -> None:
    verification = verify_root(root, require_seal=False)
    (root / "verification.json").write_text(json.dumps(verification, indent=2) + "\n")
    (root / "COMPLETED").write_text("pass\n")
    paths = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256((root / relative).read_bytes()).hexdigest()}  {relative}\n"
            for relative in paths
        )
    )
    assert verify_root(root, require_seal=True) == verification


def expect_rejected(name: str, root: pathlib.Path, mutate, *, sealed: bool = False) -> None:
    copy = root.parent / f"mutated-{name}"
    shutil.copytree(root, copy)
    mutate(copy)
    try:
        verify_root(copy, require_seal=sealed)
    except VerifyError:
        print(f"proof:{name}")
        return
    raise AssertionError(f"mutation was accepted: {name}")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        base = pathlib.Path(temporary) / "complete"
        make_fixture(base / "run-a", "complete", (101, 1001))
        make_fixture(base / "run-b", "complete", (102, 1002))
        write_provenance(base)
        assert verify_root(base)["outcome"] == "complete"
        print("proof:complete-metrics")

        expect_rejected(
            "high-watermark-bound",
            base,
            lambda root: (root / "run-a" / "metrics.prom").write_text(
                metric_fixture("complete", 8193)
            ),
        )
        expect_rejected(
            "socket-open-at-scrape",
            base,
            lambda root: _mutate_json(
                root / "run-a" / "receipt.json", "generation_open_at_scrape", False
            ),
        )
        expect_rejected(
            "exact-base-inventory",
            base,
            lambda root: _mutate_json(root / "run-a" / "summary.json", "base_prefixes", 183039),
        )
        expect_rejected(
            "post-eor-churn",
            base,
            lambda root: _mutate_json(root / "run-a" / "summary.json", "post_eor_churn", False),
        )

        overflow = pathlib.Path(temporary) / "overflow"
        make_fixture(overflow / "run-a", "overflow", (201, 2001))
        make_fixture(overflow / "run-b", "overflow", (202, 2002))
        write_provenance(overflow)
        assert verify_root(overflow)["outcome"] == "overflow"
        print("proof:overflow-metrics")
        expect_rejected(
            "overflow-discard-count",
            overflow,
            lambda root: (root / "run-a" / "metrics.prom").write_text(
                metric_fixture("overflow", 8193).replace(
                    'reason="live_buffer_full"} 8193',
                    'reason="live_buffer_full"} 8192',
                )
            ),
        )
        expect_rejected(
            "same-outcome-class",
            overflow,
            lambda root: _set_fixture_outcome(root / "run-b", "complete"),
        )
        expect_rejected(
            "fresh-process-identity",
            overflow,
            lambda root: _copy_identity(root / "run-a" / "receipt.json", root / "run-b" / "receipt.json"),
        )
        expect_rejected(
            "canonical-shape",
            overflow,
            lambda root: _mutate_json(root / "run-a" / "manifest.json", "n_members", 319),
        )
        expect_rejected(
            "canonical-policy-shape",
            overflow,
            lambda root: _rewrite_manifest_and_roster(root / "run-a", "min_list", 999),
        )
        expect_rejected(
            "scenario-roster",
            overflow,
            lambda root: (root / "run-a" / "scenario.sha256").write_text("c" * 64 + "  config.toml\n"),
        )

        sealed = pathlib.Path(temporary) / "sealed"
        make_fixture(sealed / "run-a", "complete", (301, 3001))
        make_fixture(sealed / "run-b", "complete", (302, 3002))
        write_provenance(sealed)
        seal_fixture(sealed)
        print("proof:sealed-artifact")
        expect_rejected(
            "missing-checksum-seal",
            sealed,
            lambda root: (root / "SHA256SUMS").unlink(),
            sealed=True,
        )
        expect_rejected(
            "missing-completed-marker",
            sealed,
            lambda root: (root / "COMPLETED").unlink(),
            sealed=True,
        )
        expect_rejected(
            "provenance-order",
            sealed,
            lambda root: _mutate_json(root / "provenance.json", "order", "parallel"),
            sealed=True,
        )
        expect_rejected(
            "provenance-commit",
            sealed,
            lambda root: _mutate_json(root / "provenance.json", "commit", "d" * 40),
            sealed=True,
        )
        expect_rejected(
            "checksum-drift",
            sealed,
            lambda root: (root / "run-a" / "daemon.log").write_text("changed\n"),
            sealed=True,
        )
        expect_rejected("symlink-artifact", sealed, _replace_log_with_symlink, sealed=True)
        cli_cases = [
            ("cli-requires-seal", base, [], False),
            ("cli-allows-runner-preseal", base, ["--allow-unsealed"], True),
            ("cli-sealed-pass", sealed, [], True),
        ]
        for name, root, options, should_pass in cli_cases:
            result = subprocess.run(
                [sys.executable, __file__, "verify", *options, str(root)],
                check=False,
                capture_output=True,
                text=True,
            )
            assert (result.returncode == 0) is should_pass, result.stderr
            print(f"proof:{name}")
    return 0


def _mutate_json(path: pathlib.Path, key: str, value) -> None:
    document = json.loads(path.read_text())
    document[key] = value
    path.write_text(json.dumps(document))


def _copy_identity(source: pathlib.Path, target: pathlib.Path) -> None:
    source_doc = json.loads(source.read_text())
    target_doc = json.loads(target.read_text())
    target_doc["daemon_pid"] = source_doc["daemon_pid"]
    target_doc["daemon_start_ticks"] = source_doc["daemon_start_ticks"]
    target.write_text(json.dumps(target_doc))


def _rewrite_manifest_and_roster(run: pathlib.Path, key: str, value) -> None:
    _mutate_json(run / "manifest.json", key, value)
    digest = hashlib.sha256((run / "manifest.json").read_bytes()).hexdigest()
    lines = [
        f"{digest}  manifest.json" if line.endswith("  manifest.json") else line
        for line in (run / "scenario.sha256").read_text().splitlines()
    ]
    (run / "scenario.sha256").write_text("\n".join(lines) + "\n")


def _replace_log_with_symlink(root: pathlib.Path) -> None:
    log = root / "run-a" / "daemon.log"
    log.unlink()
    log.symlink_to("../provenance.json")


def _set_fixture_outcome(run: pathlib.Path, outcome: str) -> None:
    receipt = load_json(run / "receipt.json")
    identity = (receipt["daemon_pid"], receipt["daemon_start_ticks"])
    shutil.rmtree(run)
    make_fixture(run, outcome, identity)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("root", type=pathlib.Path)
    verify_parser.add_argument(
        "--allow-unsealed",
        action="store_true",
        help="allow the runner's one pre-seal verification pass",
    )
    subparsers.add_parser("self-test")
    args = parser.parse_args()
    try:
        if args.command == "self-test":
            return self_test()
        verification = verify_root(args.root, require_seal=not args.allow_unsealed)
        print(json.dumps(verification, indent=2))
        return 0
    except (OSError, VerifyError, AssertionError) as error:
        print(f"receipt verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
