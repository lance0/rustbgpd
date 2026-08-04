#!/usr/bin/env python3
"""Validate IRR reload topology evidence and counterbalanced receipts."""

from __future__ import annotations

import argparse
import codecs
import csv
import hashlib
import json
import math
import mmap
import os
import re
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


COMPARISON_CELLS = ("rustbgpd-sighup", "bird", "openbgpd")
GROUPED_CELL = "rustbgpd-sighup-grouped-control"
TRANSACTION_CELL = "rustbgpd-txn"
CANONICAL_SHAPE = (320, 183040, 1000, 40000, 61)
CANONICAL_FULL_INPUTS = {
    "smoke": "",
    "n_members": "320",
    "total_prefixes": "183040",
    "min_list": "1000",
    "max_list": "40000",
    "seed": "61",
    "changed_fraction": "0.1",
    "port": "1790",
    "reloads": "4",
    "control_secs": "30",
    "txn_max_candidate_bytes": "402653184",
    "cell_timeout": "7200",
    "start_timeout": "600",
    "bird_threads": "8",
    "skip_preflight": "",
    "bird_image": "bird:3.3.1",
    "openbgpd_image": "openbgpd/openbgpd:9.1",
}
ROWS_HEADER = (
    "cell,reload,peers_total,peers_changed,peers_stable,prefixes,"
    "completion_p50_s,completion_p95_s,completion_max_s,"
    "changed_maxgap_p50_ms,changed_maxgap_p95_ms,changed_maxgap_max_ms,"
    "all_observer_maxgap_p50_ms,all_observer_maxgap_p95_ms,"
    "all_observer_maxgap_max_ms,changed_first_generation_update_p50_ms,"
    "changed_first_generation_update_p95_ms,changed_first_generation_update_max_ms,"
    "rss_before_mib,rss_after_mib,stable_marker_peers,sessions_up,parse_errors"
)
METRIC_NAME = re.compile(r"[A-Za-z_:][A-Za-z0-9_:]*")
LABEL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
FLOAT_VALUE = re.compile(
    r"(?:[-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?|NaN|[+-]Inf)"
)
INT64_TIMESTAMP = re.compile(r"[+-]?[0-9]+")
WATCHED = ("bgp_rib_", "bgp_peer_", "bgp_update_group", "bgp_session_")


class InvalidReceipt(ValueError):
    pass


def fail(message: str) -> None:
    raise InvalidReceipt(message)


def quoted(text: str, position: int) -> tuple[str, int]:
    if position >= len(text) or text[position] != '"':
        fail("expected quoted string")
    chars: list[str] = []
    position += 1
    while position < len(text):
        char = text[position]
        position += 1
        if char == '"':
            return "".join(chars), position
        if char == "\\":
            if position >= len(text) or text[position] not in '\\"n':
                fail("malformed label escape")
            chars.append({"\\": "\\", '"': '"', "n": "\n"}[text[position]])
            position += 1
        elif char in "\r\n":
            fail("unescaped line break")
        else:
            chars.append(char)
    fail("unterminated quoted string")


def parse_sample(text: str):
    match = METRIC_NAME.match(text)
    if not match:
        return None
    name, position, labels = match.group(), match.end(), {}
    if position < len(text) and text[position] == "{":
        position += 1
        while True:
            while position < len(text) and text[position] in " \t":
                position += 1
            if position < len(text) and text[position] == "}":
                position += 1
                break
            if position < len(text) and text[position] == '"':
                key, position = quoted(text, position)
            else:
                match = LABEL_NAME.match(text, position)
                if not match:
                    fail("malformed label name")
                key, position = match.group(), match.end()
            while position < len(text) and text[position] in " \t":
                position += 1
            if position >= len(text) or text[position] != "=":
                fail("missing label equals")
            position += 1
            while position < len(text) and text[position] in " \t":
                position += 1
            value, position = quoted(text, position)
            if key in labels:
                fail(f"duplicate label {key!r}")
            labels[key] = value
            while position < len(text) and text[position] in " \t":
                position += 1
            if position < len(text) and text[position] == "}":
                position += 1
                break
            if position >= len(text) or text[position] != ",":
                fail("malformed label separator")
            position += 1
    if position >= len(text) or text[position] not in " \t":
        fail("missing sample value separator")
    tokens = text[position:].split()
    if len(tokens) not in (1, 2) or not FLOAT_VALUE.fullmatch(tokens[0]):
        fail("malformed sample value")
    if len(tokens) == 2:
        if not INT64_TIMESTAMP.fullmatch(tokens[1]):
            fail("malformed sample timestamp")
        timestamp = int(tokens[1])
        if not -(1 << 63) <= timestamp < (1 << 63):
            fail("sample timestamp outside int64")
    return name, labels, float(tokens[0])


def parse_metrics(path: Path) -> dict[str, list[tuple[dict[str, str], float]]]:
    result: dict[str, list[tuple[dict[str, str], float]]] = {}
    identities = set()
    for line in path.read_text().splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        try:
            parsed = parse_sample(text)
        except InvalidReceipt:
            if text.startswith(WATCHED):
                raise
            continue
        if parsed is None:
            continue
        name, labels, value = parsed
        identity = (name, tuple(sorted(labels.items())))
        if identity in identities:
            fail(f"duplicate metric sample {identity}")
        identities.add(identity)
        result.setdefault(name, []).append((labels, value))
    return result


def rows(data, name: str, count: int | None = None):
    found = data.get(name, [])
    if count is not None and len(found) != count:
        fail(f"{name}: expected {count} samples, got {len(found)}")
    if any(not math.isfinite(value) for _, value in found):
        fail(f"{name}: non-finite sample")
    return found


def one(data, name: str, expected: int) -> None:
    found = rows(data, name, 1)
    labels, value = found[0]
    if labels or value != expected:
        fail(f"{name}: expected unlabelled {expected}, got {found[0]}")


def peer_rows(data, name: str, peers: int, extra=()):
    found = rows(data, name, peers)
    expected_labels = {"peer", *extra}
    identities = [labels.get("peer") for labels, _ in found]
    if (
        None in identities
        or len(set(identities)) != peers
        or any(set(labels) != expected_labels for labels, _ in found)
    ):
        fail(f"{name}: missing/duplicate peer or unexpected labels")
    return found


def family_rows(data, name: str, peers: set[str], families: tuple[str, ...]):
    found = rows(data, name, len(peers) * len(families))
    expected = {(peer, family) for peer in peers for family in families}
    actual = {(labels.get("peer"), labels.get("afi_safi")) for labels, _ in found}
    if actual != expected or any(set(labels) != {"peer", "afi_safi"} for labels, _ in found):
        fail(f"{name}: family/peer roster mismatch")
    return {(labels["peer"], labels["afi_safi"]): value for labels, value in found}


def validate_topology(
    mode: str,
    peers: int,
    total: int,
    config: Path,
    timestamps: Path,
    metric_paths: list[Path],
    output: Path,
) -> None:
    if mode not in ("private", "grouped") or len(metric_paths) != 3:
        fail("topology requires private/grouped mode and exactly three scrapes")
    config_text = config.read_text()
    if "[neighbors.add_path]" in config_text:
        fail("topology proof requires Add-Path disabled")
    expected_best = peers if mode == "private" else 0
    if config_text.count("per_client_best = true") != expected_best:
        fail(f"{mode}: per_client_best mapping is not exact")
    timestamp_rows = list(csv.DictReader(timestamps.open(), delimiter="\t"))
    if [row.get("phase") for row in timestamp_rows] != ["scrape1", "scrape2", "scrape3"]:
        fail("topology timestamps must contain exactly three scrapes")
    epoch_ns = [int(row["epoch_ns"]) for row in timestamp_rows]
    if epoch_ns[1] - epoch_ns[0] < 1_000_000_000 or epoch_ns[2] - epoch_ns[1] < 1_000_000_000:
        fail("topology scrapes must be at least one second apart")
    scrapes = [parse_metrics(path) for path in metric_paths]
    stable = []
    peer_roster = None
    group_id = None
    for data in scrapes:
        one(data, "bgp_rib_outbound_registered_peers", peers)
        one(data, "bgp_rib_ingest_channel_depth", 0)
        one(data, "bgp_rib_policy_transition_in_progress", 0)
        sessions = peer_rows(data, "bgp_peer_session_established", peers, ("interface",))
        if any(value != 1 for _, value in sessions):
            fail("not every expected session is established")
        identities = {labels["peer"] for labels, _ in sessions}
        established = peer_rows(data, "bgp_session_established_total", peers)
        if {labels["peer"] for labels, _ in established} != identities:
            fail("session establishment counter roster mismatch")
        if any(value != 1 for _, value in established):
            fail("session establishment counter value mismatch")
        flaps = rows(data, "bgp_session_flaps_total")
        if any(
            set(labels) != {"peer"}
            or labels["peer"] not in identities
            for labels, _ in flaps
        ):
            fail("session flap counter roster/labels mismatch")
        if any(value != 0 for _, value in flaps):
            fail("session flap counter value mismatch")
        queues = peer_rows(data, "bgp_peer_outbound_queue_depth", peers)
        if {labels["peer"] for labels, _ in queues} != identities or any(
            value != 0 for _, value in queues
        ):
            fail("every expected outbound queue must be empty")
        groups = peer_rows(data, "bgp_peer_update_group", peers)
        if {labels["peer"] for labels, _ in groups} != identities:
            fail("group peer roster mismatch")
        if peer_roster is None:
            peer_roster = identities
        elif peer_roster != identities:
            fail("peer roster changed between topology scrapes")
        loc = rows(data, "bgp_rib_loc_prefixes", 1)
        if loc != [({"afi_safi": "all"}, float(total))]:
            fail("Loc-RIB aggregate mismatch")
        per_peer = total // peers
        adj_in = family_rows(data, "bgp_rib_prefixes", identities, ("all", "flowspec"))
        if any(
            adj_in[(peer, family)] != (per_peer if family == "all" else 0)
            for peer in identities
            for family in ("all", "flowspec")
        ):
            fail("Adj-RIB-In aggregate/non-all roster mismatch")
        out_families = ("all", "bgpls", "evpn", "flowspec", "labeled", "rtc", "vpn")
        adj_out = family_rows(data, "bgp_rib_adj_out_prefixes", identities, out_families)
        expected_out = total - per_peer
        if any(
            adj_out[(peer, family)] != (expected_out if family == "all" else 0)
            for peer in identities
            for family in out_families
        ):
            fail("Adj-RIB-Out aggregate/non-all roster mismatch")
        if mode == "private":
            one(data, "bgp_update_groups", 0)
            one(data, "bgp_update_group_fallback_peers", peers)
            if rows(data, "bgp_update_group_members") or any(value != -1 for _, value in groups):
                fail("private topology must have no group and every peer at group -1")
            group_snapshot = (0, peers, tuple(sorted((labels["peer"], value) for labels, value in groups)))
        else:
            one(data, "bgp_update_groups", 1)
            one(data, "bgp_update_group_fallback_peers", 0)
            members = rows(data, "bgp_update_group_members", 1)
            labels, member_count = members[0]
            ids = {value for _, value in groups}
            candidate = next(iter(ids)) if len(ids) == 1 else math.nan
            if (
                set(labels) != {"group"}
                or member_count != peers
                or not math.isfinite(candidate)
                or candidate < 0
                or candidate != int(candidate)
                or labels["group"] != str(int(candidate))
            ):
                fail("grouped topology must have one complete nonnegative group")
            if group_id is None:
                group_id = int(candidate)
            group_snapshot = (1, 0, int(candidate), tuple(sorted((labels["peer"], value) for labels, value in groups)))
        route_snapshot = tuple(
            sorted(
                (name, tuple(sorted(labels.items())), value)
                for name, found in data.items()
                if name in {"bgp_rib_loc_prefixes", "bgp_rib_prefixes", "bgp_rib_adj_out_prefixes"}
                for labels, value in found
            )
        )
        stable.append((group_snapshot, route_snapshot))
    if not stable[0] == stable[1] == stable[2]:
        fail("topology was not stable across three scrapes")
    output.write_text(
        json.dumps(
            {
                "status": "pass",
                "mode": mode,
                "peers": peers,
                "scrape_epoch_ns": epoch_ns,
                "group_id": group_id,
            },
            sort_keys=True,
        )
        + "\n"
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def provenance_fingerprint(provenance: dict) -> str:
    unsigned = dict(provenance)
    unsigned.pop("fingerprint", None)
    canonical = json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256((canonical + "\n").encode()).hexdigest()


def reject_symlinks(root: Path) -> None:
    if root.is_symlink() or any(path.is_symlink() for path in root.rglob("*")):
        fail(f"{root}: receipt contains a symlink")


def validate_seal(root: Path) -> None:
    completed = root / "COMPLETED"
    roster = root / "SHA256SUMS"
    if not completed.is_file() or not roster.is_file():
        fail(f"{root}: incomplete root (COMPLETED/SHA256SUMS missing)")
    expected = {}
    for line in roster.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or match.group(2).startswith("/") or ".." in Path(match.group(2)).parts:
            fail(f"{root}: malformed checksum roster")
        relative = match.group(2).removeprefix("./")
        if not relative or relative in expected:
            fail(f"{root}: duplicate checksum path")
        expected[relative] = match.group(1)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    if actual != set(expected):
        fail(f"{root}: checksum roster does not exactly cover retained files")
    for relative, digest in expected.items():
        if sha256(root / relative) != digest:
            fail(f"{root}: checksum mismatch for {relative}")
    for path in [root, *root.rglob("*")]:
        if path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
            fail(f"{root}: writable retained path {path.relative_to(root) if path != root else '.'}")


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{path}: invalid JSON: {error}")


def decode_lossless_path(value, context: str) -> bytes:
    if (
        not isinstance(value, dict)
        or list(value) != ["encoding", "value"]
        or value.get("encoding") != "unix-bytes-hex"
        or not isinstance(value.get("value"), str)
        or len(value["value"]) % 2 or not re.fullmatch(r"[0-9a-f]*", value["value"])
    ):
        fail(f"{context}: invalid lossless path")
    return bytes.fromhex(value["value"])


def inline_manifest_source_sha256(manifest: dict, raw_sha: str) -> str:
    if manifest != {"toml_sha256": raw_sha, "rpol_units": [], "datasets": []}:
        fail("transaction v3 manifest is not the exact inline-policy shape")
    digest = hashlib.sha256(b"rustbgpd.config-source.v2\0")
    for value in (bytes.fromhex(raw_sha), (0).to_bytes(8, "big"), (0).to_bytes(8, "big")):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def canonical_json(path: Path, cap: int, context: str) -> tuple[dict, bytes]:
    raw = path.read_bytes()
    if not raw or len(raw) > cap:
        fail(f"{context}: file is empty or exceeds its cap")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        fail(f"{context}: invalid JSON: {error}")
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
    if encoded != raw or not raw.startswith(b'{"version":3,'):
        fail(f"{context}: JSON is not canonical v3")
    return value, raw


def secure_file_identity(path: Path, cap: int, context: str) -> dict:
    if path.is_symlink():
        fail(f"{context}: symlink is forbidden")
    metadata = path.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
        or metadata.st_size <= 0
        or metadata.st_size > cap
    ):
        fail(f"{context}: type, owner, mode, or size is invalid")
    return {"name": path.name, "device": metadata.st_dev, "inode": metadata.st_ino,
            "bytes": metadata.st_size, "sha256": sha256(path), "mode": "0600",
            "owner_current_uid": True}


def require_utf8(path: Path, context: str) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                decoder.decode(chunk)
        decoder.decode(b"", final=True)
    except UnicodeDecodeError:
        fail(f"{context}: content is not UTF-8")


def inspect_v3(locator_path: Path, metadata_path: Path, raw_path: Path, config_path: Path, confirm_id: str) -> dict:
    locator_identity = secure_file_identity(locator_path, 512 * 1024, "v3 locator")
    metadata_identity = secure_file_identity(metadata_path, 34 * 1024 * 1024, "v3 metadata")
    raw_identity = secure_file_identity(raw_path, 384 * 1024 * 1024, "v3 raw")
    locator, _ = canonical_json(locator_path, 512 * 1024, "v3 locator")
    metadata, _ = canonical_json(metadata_path, 34 * 1024 * 1024, "v3 metadata")
    locator_fields = ("version", "confirm_id", "metadata_path", "config_target",
                      "prior_sha256", "prior_source_sha256")
    metadata_fields = ("version", "confirm_id", "deadline_unix_seconds", "rollback_failed",
                       "raw_name", "raw_length", "raw_sha256", "raw_source_sha256",
                       "raw_device", "raw_inode", "manifest")
    if tuple(locator or {}) != locator_fields or type(locator.get("version")) is not int or locator["version"] != 3 or locator.get("confirm_id") != confirm_id:
        fail("v3 locator schema or confirmation id is invalid")
    if tuple(metadata or {}) != metadata_fields or type(metadata.get("version")) is not int or metadata["version"] != 3 or metadata.get("confirm_id") != confirm_id:
        fail("v3 metadata schema or confirmation id is invalid")
    if tuple(metadata.get("manifest") or {}) != ("toml_sha256", "rpol_units", "datasets"):
        fail("v3 metadata manifest field order is invalid")
    expected_metadata = os.fsencode(str(metadata_path.resolve(strict=True)))
    expected_config = os.fsencode(str(config_path.resolve(strict=True)))
    if decode_lossless_path(locator["metadata_path"], "v3 metadata path") != expected_metadata:
        fail("v3 locator does not name the expected metadata path")
    if decode_lossless_path(locator["config_target"], "v3 config target") != expected_config:
        fail("v3 locator does not name the expected config target")
    if decode_lossless_path(metadata["raw_name"], "v3 raw name") != b"commit-confirm-v3-prior.toml":
        fail("v3 metadata does not name the fixed raw object")
    require_utf8(raw_path, "v3 raw")
    raw_sha = raw_identity["sha256"]
    source_sha = inline_manifest_source_sha256(metadata["manifest"], raw_sha)
    if (
        metadata.get("rollback_failed") is not False
        or type(metadata.get("deadline_unix_seconds")) is not int
        or metadata["deadline_unix_seconds"] <= 0
        or any(type(metadata.get(field)) is not int for field in ("raw_length", "raw_device", "raw_inode"))
        or metadata.get("raw_length") != raw_identity["bytes"]
        or metadata.get("raw_device") != raw_identity["device"]
        or metadata.get("raw_inode") != raw_identity["inode"]
        or metadata.get("raw_sha256") != raw_sha
        or metadata.get("raw_source_sha256") != source_sha
        or metadata["manifest"].get("toml_sha256") != raw_sha
        or locator.get("prior_sha256") != raw_sha
        or locator.get("prior_source_sha256") != source_sha
    ):
        fail("v3 locator, metadata, manifest, and raw object are not linked")
    return {
        "schema": 1,
        "version": 3,
        "confirm_id": confirm_id,
        "deadline_unix_seconds": metadata["deadline_unix_seconds"],
        "linkage_verified": True,
        "locator": locator_identity,
        "metadata": metadata_identity,
        "raw": raw_identity,
    }


def generation_marker(path: Path) -> str:
    pattern = re.compile(rb'set_community_add\s*=\s*\[\s*"65400:(1000|2000)"\s*,?\s*\]')
    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        markers = pattern.findall(data)
    if len(markers) != 1:
        fail(f"{path}: transaction generation marker is not exact A or B")
    return "65400:" + markers[0].decode()


def validate_quiet(path: Path) -> None:
    data = list(csv.DictReader(path.open(), delimiter="\t"))
    if [row.get("sample") for row in data] != ["1", "2"]:
        fail(f"{path}: quiet gate needs exactly two samples")
    epochs = [int(row["epoch_s"]) for row in data]
    loads = [float(row["load1"]) for row in data]
    if (
        epochs[1] - epochs[0] < 30
        or any(not math.isfinite(load) or load >= 2.0 for load in loads)
        or any(row.get("port1790_free") != "true" or row.get("port9179_free") != "true" for row in data)
        or any(int(row.get("disk_available_kib", "0")) < 40 * 1024 * 1024 for row in data)
        or len({(row.get("pswpin"), row.get("pswpout")) for row in data}) != 1
        or any(not row.get("pswpin", "").isdigit() or not row.get("pswpout", "").isdigit() for row in data)
    ):
        fail(f"{path}: quiet samples are too close or not below load 2")


def validate_process(path: Path) -> tuple[int, int]:
    data = list(csv.DictReader(path.open(), delimiter="\t"))
    if len(data) != 1:
        fail(f"{path}: expected one process identity")
    row = data[0]
    pid, before, after = int(row["pid"]), int(row["starttime_before"]), int(row["starttime_after"])
    if pid <= 0 or before <= 0 or before != after:
        fail(f"{path}: missing, reused, or changed process identity")
    return pid, before


def read_rows(path: Path, expected_cells: tuple[str, ...]) -> list[list[str]]:
    with path.open(newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        data = list(reader)
    if header != ROWS_HEADER.split(","):
        fail(f"{path}: unexpected row header")
    if len(data) != 4 * len(expected_cells):
        fail(f"{path}: expected four rows per cell")
    for cell in expected_cells:
        found = [row for row in data if row and row[0] == cell]
        if len(found) != 4 or [row[1] for row in found] != ["1", "2", "3", "4"]:
            fail(f"{path}: {cell} does not have reload rows 1..4")
    if {row[0] for row in data if row} != set(expected_cells):
        fail(f"{path}: unexpected/missing cells")
    if any(len(row) != 23 for row in data):
        fail(f"{path}: malformed measurement row width")
    return data


def validate_preflight(path: Path) -> None:
    text = path.read_text()
    lines = text.splitlines()
    if "[preflight] READY — all pre-flight checks passed" not in lines or any(
        "FAIL:" in line for line in lines
    ):
        fail(f"{path}: preflight did not finish READY without failures")
    for phrase in ("bench-nightly cron is paused", "no pushes to main"):
        if not any(phrase in line and "confirmed" in line for line in lines):
            fail(f"{path}: missing manual confirmation for {phrase}")


def parse_digest_roster(path: Path, expected_paths: set[str]) -> dict[str, str]:
    entries = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (?:\./)?(.+)", line)
        if not match or match.group(2).startswith("/") or ".." in Path(match.group(2)).parts:
            fail(f"{path}: malformed digest roster")
        if match.group(2) in entries:
            fail(f"{path}: duplicate digest path")
        entries[match.group(2)] = match.group(1)
    if set(entries) != expected_paths:
        fail(f"{path}: digest roster does not exactly cover expected paths")
    return entries


def validate_digest_roster(path: Path, base: Path, expected_paths: set[str]) -> str:
    entries = parse_digest_roster(path, expected_paths)
    for relative, digest in entries.items():
        if sha256(base / relative) != digest:
            fail(f"{path}: checksum mismatch for {relative}")
    return sha256(path)


def validate_scenario_roster(cdir: Path, manifest: dict) -> str:
    runtime_files = manifest.get("runtime_files")
    if not isinstance(runtime_files, list) or not runtime_files:
        fail(f"{cdir}: manifest runtime_files is not a nonempty roster")
    if any(
        not isinstance(relative, str)
        or not relative
        or Path(relative).name != relative
        or ".." in relative
        or relative == "manifest.json"
        for relative in runtime_files
    ) or len(set(runtime_files)) != len(runtime_files):
        fail(f"{cdir}: manifest runtime_files contains an unsafe or duplicate path")
    expected = {*runtime_files, "manifest.json"}
    entries = parse_digest_roster(cdir / "scenario.sha256", expected)
    for relative, digest in entries.items():
        retained = cdir / relative
        if retained.exists() and (not retained.is_file() or sha256(retained) != digest):
            fail(f"{cdir}: retained scenario input mismatch for {relative}")
    if sha256(cdir / "manifest.json") != entries["manifest.json"]:
        fail(f"{cdir}: scenario roster does not bind retained manifest.json")
    return sha256(cdir / "scenario.sha256")


def validate_measurement_rows(rows_data: list[list[str]], cell: str, peers: int, total: int) -> None:
    for row in rows_data:
        if row[0] != cell:
            fail(f"{cell}: row escaped its cell roster")
        try:
            integers = [int(row[index]) for index in (1, 2, 3, 4, 5, 20, 21, 22)]
            floats = [float(row[index]) for index in range(6, 20)]
        except ValueError:
            fail(f"{cell}: nonnumeric measurement field")
        if any(value < 0 or not math.isfinite(value) for value in floats):
            fail(f"{cell}: negative/non-finite measurement")
        for offset in (0, 3, 6, 9):
            p50, p95, maximum = floats[offset : offset + 3]
            if not p50 <= p95 <= maximum:
                fail(f"{cell}: percentile triplet is not monotonic")
        if floats[0] <= 0 or floats[9] <= 0:
            fail(f"{cell}: completion/first-generation latency must be positive")
        if any(
            first_generation > completion * 1000
            for completion, first_generation in zip(
                floats[0:3], floats[9:12], strict=True
            )
        ):
            fail(f"{cell}: first-generation latency exceeds completion latency")
        if any(
            all_observer < changed_observer
            for changed_observer, all_observer in zip(
                floats[3:6], floats[6:9], strict=True
            )
        ):
            fail(f"{cell}: all-observer max-gap is below changed-observer max-gap")
        reload_no, peers_total, peers_changed, peers_stable, prefixes, stable_marker, sessions, parse_errors = integers
        if (
            reload_no not in range(1, 5)
            or peers_total != peers
            or peers_changed != peers
            or peers_stable != 0
            or prefixes != total
            or stable_marker != 0
            or sessions != peers
            or parse_errors != 0
        ):
            fail(f"{cell}: canonical row invariants failed")


def validate_rss(path: Path) -> None:
    data = list(csv.reader(path.open()))
    if not data or data[0] != ["epoch_s", "total_rss_kib", "pids"] or len(data) < 2:
        fail(f"{path}: RSS evidence is missing or malformed")
    for row in data[1:]:
        if len(row) != 3 or any(not value.isdigit() or int(value) <= 0 for value in row):
            fail(f"{path}: RSS sample is not a positive integer triple")


def validate_cell_chain(
    root: Path,
    cell: str,
    root_provenance: dict,
    scenario_digest: str,
    dataset: str,
    root_rows: list[list[str]],
    peers: int,
    total: int,
) -> None:
    cdir = root / cell
    fingerprint = root_provenance["fingerprint"]
    cell_rows = list(csv.reader((cdir / "rows.csv").open()))
    expected_rows = [row for row in root_rows if row[0] == cell]
    if cell_rows != expected_rows:
        fail(f"{cdir}: cell rows do not equal their root rows")
    validate_measurement_rows(cell_rows, cell, peers, total)
    logged = []
    for line in (cdir / "reloadstall.log").read_text().splitlines():
        if line.startswith("reloadstall_csv,"):
            logged.append([cell, *line.split(",")[1:]])
    if logged != cell_rows:
        fail(f"{cdir}: retained rows do not re-extract from reloadstall.log")
    validate_rss(cdir / "rss.csv")
    cell_provenance = read_json(cdir / "provenance.json")
    scenario = cell_provenance.pop("scenario", {})
    if (
        cell_provenance != root_provenance
        or scenario.get("manifest_sha256") != scenario_digest
        or scenario.get("dataset_sha256") != dataset
    ):
        fail(f"{cdir}: cell provenance/scenario chain is broken")
    retained = {
        path.relative_to(cdir).as_posix()
        for path in cdir.rglob("*")
        if path.is_file() and path.name not in {"evidence.sha256", "status"}
    }
    evidence_digest = validate_digest_roster(cdir / "evidence.sha256", cdir, retained)
    status = (cdir / "status").read_text().split()
    if status != ["pass", fingerprint, scenario_digest, dataset, evidence_digest]:
        fail(f"{cdir}: pass status does not bind the full evidence chain")


def reject_transaction_tokens(value, path="receipt") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"plan_token", "runtime_snapshot_token"}:
                fail(f"{path}: token contents were retained")
            reject_transaction_tokens(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_transaction_tokens(child, f"{path}[{index}]")
    elif isinstance(value, str) and (
        re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", value)
        or value.startswith(("kv1:", "kv2:"))
    ):
        fail(f"{path}: token-shaped string was retained")


def validate_content(value, context: str) -> None:
    if set(value or {}) != {"sha256", "bytes", "marker"} or not re.fullmatch(
        r"[0-9a-f]{64}", value.get("sha256", "")
    ) or not isinstance(value.get("bytes"), int) or value["bytes"] <= 0 or value.get(
        "marker"
    ) not in {"65400:1000", "65400:2000"}:
        fail(f"{context}: invalid content identity")


def validate_process_json(value, expected: tuple[int, int], context: str) -> None:
    if (
        set(value or {}) != {"pid", "starttime", "vmrss_kib", "vmhwm_kib"}
        or (value.get("pid"), value.get("starttime")) != expected
        or not all(isinstance(value.get(key), int) and value[key] > 0 for key in value)
        or value["vmhwm_kib"] < value["vmrss_kib"]
    ):
        fail(f"{context}: daemon process/RSS identity is invalid")


def validate_history(value, context: str) -> None:
    if set(value or {}) != {"entries", "files"} or value.get("entries") != [] or value.get("files") != []:
        fail(f"{context}: oversize history was not exactly empty")


def validate_warning(value, context: str) -> tuple[int, int]:
    if (
        set(value or {}) != {"count_before", "count_after", "bytes"}
        or not all(isinstance(value.get(key), int) for key in value)
        or value["count_after"] != value["count_before"] + 1
        or value["bytes"] <= 10 * 1024 * 1024
    ):
        fail(f"{context}: SkippedOversize warning evidence is invalid")
    return value["count_before"], value["count_after"]


def validate_file_identity(value, expected_name: str, context: str) -> None:
    if (
        set(value or {})
        != {"name", "device", "inode", "bytes", "sha256", "mode", "owner_current_uid"}
        or value.get("name") != expected_name
        or not re.fullmatch(r"[0-9a-f]{64}", value.get("sha256", ""))
        or not all(isinstance(value.get(key), int) and value[key] > 0 for key in ("device", "inode", "bytes"))
        or value.get("mode") != "0600"
        or value.get("owner_current_uid") is not True
    ):
        fail(f"{context}: invalid v3 file identity")


def validate_authority(value, confirm_id: str, deadline: int, context: str) -> None:
    if (
        set(value or {})
        != {
            "schema",
            "version",
            "confirm_id",
            "deadline_unix_seconds",
            "linkage_verified",
            "locator",
            "metadata",
            "raw",
        }
        or value.get("schema") != 1
        or value.get("version") != 3
        or value.get("confirm_id") != confirm_id
        or value.get("deadline_unix_seconds") != deadline
        or value.get("linkage_verified") is not True
    ):
        fail(f"{context}: v3 authority linkage receipt is invalid")
    validate_file_identity(value["locator"], "config.toml.commit-confirm-locator.json", context)
    validate_file_identity(value["metadata"], "commit-confirm-v3-metadata.json", context)
    validate_file_identity(value["raw"], "commit-confirm-v3-prior.toml", context)
    if not 10 * 1024 * 1024 < value["raw"]["bytes"] <= 384 * 1024 * 1024:
        fail(f"{context}: v3 raw snapshot is outside (10 MiB, 384 MiB]")


def validate_state(
    value,
    expected_process: tuple[int, int],
    pending: bool,
    context: str,
    confirm_id: str = "",
    deadline: int = 0,
) -> None:
    common = {"legacy_absent", "history_entries", "history_outcome", "process", "config", "runtime"}
    expected_keys = common | ({"authority"} if pending else {"v3_absent"})
    if (
        set(value or {}) != expected_keys
        or value.get("legacy_absent") is not True
        or value.get("history_entries") != 0
        or value.get("history_outcome") != "skipped_oversize"
        or (not pending and value.get("v3_absent") is not True)
    ):
        fail(f"{context}: lifecycle state shape/outcome is invalid")
    validate_process_json(value["process"], expected_process, context)
    validate_content(value["config"], context)
    validate_content(value["runtime"], context)
    if pending:
        validate_authority(value["authority"], confirm_id, deadline, context)


def validate_plan_apply(prefix, confirm_id: str, timeout: int, context: str) -> int:
    plan, apply = prefix.get("plan", {}), prefix.get("apply", {})
    deadline = apply.get("deadline_unix_seconds")
    if (
        plan != {
        "transport": "streamed",
        "status": "committable",
        "plan_token_present": True,
        "runtime_snapshot_token_present": True,
        }
        or not isinstance(deadline, int)
        or deadline <= 0
        or apply
        != {
            "transport": "streamed",
            "explicit_plan_token": True,
            "status": "committable",
            "confirmation_status": "pending",
            "confirm_id": confirm_id,
            "timeout_seconds": timeout,
            "deadline_unix_seconds": deadline,
            "runtime_token_coherent": True,
        }
    ):
        fail(f"{context}: streamed explicit-token confirmed apply contract is invalid")
    return deadline


def validate_transaction_evidence(
    cdir: Path, identity: tuple[int, int], scenario_entries: dict[str, str]
) -> dict:
    expected_files = {
        "daemon.log", "evidence.sha256", "final-evidence/ack", "final-evidence/ready",
        "manifest.json", "process.tsv", "provenance.json", "quiet.tsv", "reloadstall.log",
        "rows.csv", "rss.csv", "scenario.sha256", "status", "transactions/cycles.jsonl",
        "transactions/lifecycle.json",
    }
    actual_files = {path.relative_to(cdir).as_posix() for path in cdir.rglob("*") if path.is_file()}
    if actual_files != expected_files:
        fail(f"{cdir}: transaction cell roster is not exact")
    try:
        cycles = [json.loads(line) for line in (cdir / "transactions/cycles.jsonl").read_text().splitlines()]
    except json.JSONDecodeError as error:
        fail(f"{cdir}: invalid transaction cycle JSONL: {error}")
    if len(cycles) != 4:
        fail(f"{cdir}: expected exactly four transaction cycles")
    warning_edges = []
    candidate_ids = []
    actual_ids = []
    for number, cycle in enumerate(cycles, 1):
        reject_transaction_tokens(cycle)
        if set(cycle) != {"schema", "cycle", "candidate", "plan", "apply", "history", "pending", "confirmed"} or cycle.get("schema") != 1 or cycle.get("cycle") != number:
            fail(f"{cdir}: transaction cycle roster/order is invalid")
        validate_content(cycle["candidate"], f"cycle {number} candidate")
        if not 10 * 1024 * 1024 < cycle["candidate"]["bytes"] <= 384 * 1024 * 1024:
            fail(f"{cdir}: transaction candidate is outside streamed bounds")
        candidate_ids.append(
            (
                cycle["candidate"]["sha256"],
                cycle["candidate"]["bytes"],
                cycle["candidate"]["marker"],
            )
        )
        confirm_id = f"irrreload-measured-{number}"
        deadline = validate_plan_apply(cycle, confirm_id, 600, f"cycle {number}")
        history = cycle.get("history", {})
        if set(history) != {"before", "after", "outcome", "warning"} or history.get("outcome") != "skipped_oversize":
            fail(f"{cdir}: cycle {number} history receipt is invalid")
        validate_history(history["before"], f"cycle {number} history before")
        validate_history(history["after"], f"cycle {number} history after")
        if history["before"] != history["after"]:
            fail(f"{cdir}: cycle {number} changed bounded history")
        warning_edges.append(validate_warning(history["warning"], f"cycle {number}"))
        validate_state(
            cycle["pending"],
            identity,
            True,
            f"cycle {number} pending",
            confirm_id,
            deadline,
        )
        confirmed = cycle["confirmed"]
        if confirmed.get("status") != "confirmed" or confirmed.get("status_view_verified") is not True:
            fail(f"{cdir}: cycle {number} was not confirmed")
        validate_state(
            {
                key: value
                for key, value in confirmed.items()
                if key not in {"status", "status_view_verified"}
            },
            identity,
            False,
            f"cycle {number} confirmed",
        )
        for field in ("config", "runtime"):
            if cycle["pending"][field] != confirmed[field]:
                fail(f"{cdir}: confirm changed {field} identity")
        expected_marker = "65400:2000" if number % 2 else "65400:1000"
        if cycle["candidate"]["marker"] != expected_marker or any(
            confirmed[field]["marker"] != expected_marker
            for field in ("config", "runtime")
        ):
            fail(f"{cdir}: cycle {number} did not apply its sealed generation marker")
        actual_ids.append(
            (
                (
                    confirmed["config"]["sha256"],
                    confirmed["config"]["bytes"],
                    confirmed["config"]["marker"],
                ),
                (
                    confirmed["runtime"]["sha256"],
                    confirmed["runtime"]["bytes"],
                    confirmed["runtime"]["marker"],
                ),
            )
        )
    if not (candidate_ids[0] == candidate_ids[2] and candidate_ids[1] == candidate_ids[3] and candidate_ids[0] != candidate_ids[1]):
        fail(f"{cdir}: measured candidates do not alternate B/A/B/A")
    if (
        candidate_ids[0][0] != scenario_entries.get("gen-b.toml")
        or candidate_ids[1][0] != scenario_entries.get("gen-a.toml")
    ):
        fail(f"{cdir}: measured candidates are not bound to sealed gen-a/gen-b inputs")
    if not (
        actual_ids[0] == actual_ids[2]
        and actual_ids[1] == actual_ids[3]
        and actual_ids[0] != actual_ids[1]
    ):
        fail(f"{cdir}: persisted config/runtime did not alternate B/A/B/A")

    lifecycle = read_json(cdir / "transactions/lifecycle.json")
    reject_transaction_tokens(lifecycle)
    if set(lifecycle or {}) != {"schema", "generations", "baseline", "abort", "timeout", "restored_current_plan", "final_state"} or lifecycle.get("schema") != 1:
        fail(f"{cdir}: lifecycle roster is invalid")
    generations = lifecycle.get("generations", {})
    if set(generations) != {"current", "opposite"}:
        fail(f"{cdir}: lifecycle generation roster is invalid")
    validate_content(generations["current"], "current generation")
    validate_content(generations["opposite"], "opposite generation")
    if (
        (
            generations["current"]["sha256"],
            generations["current"]["bytes"],
            generations["current"]["marker"],
        )
        != candidate_ids[3]
        or (
            generations["opposite"]["sha256"],
            generations["opposite"]["bytes"],
            generations["opposite"]["marker"],
        )
        != candidate_ids[2]
    ):
        fail(f"{cdir}: lifecycle did not use final A/opposite B generations")
    baseline = lifecycle["baseline"]
    final_state = lifecycle["final_state"]
    for state, label in ((baseline, "baseline"), (final_state, "final")):
        if set(state or {}) != {"history_entries", "history_outcome", "process", "config", "runtime"} or state.get("history_entries") != 0 or state.get("history_outcome") != "skipped_oversize":
            fail(f"{cdir}: {label} restored state is invalid")
        validate_process_json(state["process"], identity, label)
        validate_content(state["config"], label); validate_content(state["runtime"], label)
    if any(baseline[field] != final_state[field] for field in ("config", "runtime")):
        fail(f"{cdir}: final disk/runtime state was not restored exactly")
    if any(
        (baseline[field]["sha256"], baseline[field]["bytes"], baseline[field]["marker"])
        != actual_ids[3][index]
        for index, field in enumerate(("config", "runtime"))
    ):
        fail(f"{cdir}: lifecycle baseline is not measured generation A")
    prior_after = warning_edges[-1][1]
    for name, terminal_status in (("abort", "aborted"), ("timeout", "auto_reverted")):
        phase = lifecycle.get(name, {})
        expected_id = f"irrreload-{name}"
        required = {"candidate_role", "plan", "apply", "history_before", "apply_history_warning", "pending", "terminal"}
        if set(phase or {}) != required or phase.get("candidate_role") != "opposite":
            fail(f"{cdir}: {name} lifecycle roster is invalid")
        deadline = validate_plan_apply(phase, expected_id, 600 if name == "abort" else 10, name)
        validate_history(phase["history_before"], f"{name} history before")
        apply_edge = validate_warning(phase["apply_history_warning"], f"{name} apply")
        validate_state(
            phase["pending"], identity, True, f"{name} pending", expected_id, deadline
        )
        terminal = phase["terminal"]
        extra = {
            "status",
            "status_view_verified",
            "restored_exactly",
            "history_warning",
            "history_after",
        }
        if (
            not extra.issubset(terminal)
            or terminal.get("status") != terminal_status
            or terminal.get("status_view_verified") is not True
            or terminal.get("restored_exactly") is not True
        ):
            fail(f"{cdir}: {name} terminal outcome is invalid")
        validate_state({key: value for key, value in terminal.items() if key not in extra}, identity, False, f"{name} terminal")
        validate_history(terminal["history_after"], f"{name} history after")
        if terminal["history_after"] != phase["history_before"]:
            fail(f"{cdir}: {name} changed bounded history")
        terminal_edge = validate_warning(terminal["history_warning"], f"{name} restore")
        if apply_edge[0] != prior_after or terminal_edge[0] != apply_edge[1]:
            fail(f"{cdir}: {name} history warning sequence is discontinuous")
        prior_after = terminal_edge[1]
        for field in ("config", "runtime"):
            if terminal[field] != baseline[field]:
                fail(f"{cdir}: {name} did not restore {field} exactly")
        for index, field in enumerate(("config", "runtime")):
            pending_identity = (
                phase["pending"][field]["sha256"],
                phase["pending"][field]["bytes"],
                phase["pending"][field]["marker"],
            )
            if pending_identity != actual_ids[2][index]:
                fail(f"{cdir}: {name} pending state is not measured generation B")
    if any(right[0] != left[1] for left, right in zip(warning_edges, warning_edges[1:])) or warning_edges[0][0] != 1 or prior_after != 9:
        fail(f"{cdir}: oversize warning count is not exact across nine persists")
    if lifecycle.get("restored_current_plan") != {"transport": "streamed", "status": "noop", "plan_token_present": False}:
        fail(f"{cdir}: restored-current streamed Plan was not tokenless NOOP")
    warning_lines = [
        line for line in (cdir / "daemon.log").read_text().splitlines()
        if "applied config exceeds the bounded history entry size; history was left unchanged" in line
    ]
    if len(warning_lines) != 9:
        fail(f"{cdir}: daemon log does not contain exactly nine oversize history warnings")
    try:
        warning_bytes = [json.loads(line)["fields"]["bytes"] for line in warning_lines]
    except (json.JSONDecodeError, KeyError, TypeError):
        fail(f"{cdir}: daemon oversize warning lines are malformed")
    if any(not isinstance(size, int) or size <= 10 * 1024 * 1024 for size in warning_bytes):
        fail(f"{cdir}: daemon oversize warning byte counts are invalid")
    compact_warning_bytes = [cycle["history"]["warning"]["bytes"] for cycle in cycles]
    for name in ("abort", "timeout"):
        compact_warning_bytes.extend(
            (
                lifecycle[name]["apply_history_warning"]["bytes"],
                lifecycle[name]["terminal"]["history_warning"]["bytes"],
            )
        )
    if compact_warning_bytes != warning_bytes[1:]:
        fail(f"{cdir}: compact history-warning evidence is not bound to daemon log order")
    return {
        "inputs": {"a": candidate_ids[1], "b": candidate_ids[0]},
        "actual": {
            "a": {"config": actual_ids[1][0], "runtime": actual_ids[1][1]},
            "b": {"config": actual_ids[0][0], "runtime": actual_ids[0][1]},
        },
    }


def validate_root(root: Path, kind: str):
    reject_symlinks(root)
    validate_seal(root)
    validate_preflight(root / "preflight.log")
    provenance = read_json(root / "provenance.json")
    inputs, git = provenance.get("inputs", {}), provenance.get("git", {})
    expected_cells = {
        "comparison": COMPARISON_CELLS,
        "grouped": (GROUPED_CELL,),
        "transaction": (TRANSACTION_CELL,),
    }[kind]
    expected_kind = {
        "comparison": "full-cross-daemon",
        "grouped": "full-grouped-control",
        "transaction": "full-transaction",
    }[kind]
    scripts = provenance.get("scripts")
    binaries = provenance.get("binaries")
    environment = provenance.get("environment")
    top_entries = {path.name for path in root.iterdir()}
    expected_entries = {
        "COMPLETED",
        "SHA256SUMS",
        "dataset.sha256",
        "preflight.log",
        "provenance.json",
        "rows.csv",
        *expected_cells,
    }
    if top_entries != expected_entries:
        fail(f"{root}: artifact-root roster is not exact")
    if inputs.get("cells") != ",".join(expected_cells):
        fail(f"{root}: wrong {kind} cell roster")
    if inputs.get("campaign_kind") != expected_kind:
        fail(f"{root}: wrong campaign kind for {kind} role")
    fingerprint = provenance.get("fingerprint")
    if (
        set(provenance)
        != {
            "schema",
            "started_at_epoch_ns",
            "git",
            "scripts",
            "binaries",
            "environment",
            "inputs",
            "fingerprint",
        }
        or provenance.get("schema") != 3
        or not isinstance(provenance.get("started_at_epoch_ns"), int)
        or provenance.get("started_at_epoch_ns", -1) <= 0
        or not isinstance(fingerprint, str)
        or not re.fullmatch(r"[0-9a-f]{64}", fingerprint)
        or provenance_fingerprint(provenance) != fingerprint
        or not isinstance(scripts, dict)
        or set(scripts) != {"runner", "verifier", "generator", "rss_sampler", "txn_apply", "txn_lifecycle"}
        or not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in scripts.values())
        or not isinstance(binaries, dict)
        or set(binaries) != {"reloadstall", "rustbgpd", "rbgp", "rs_config_render"}
        or not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in binaries.values())
        or not isinstance(environment, dict)
        or set(environment)
        != {"rustc", "cargo", "python", "jq", "docker", "kernel", "cpu_model"}
        or not all(isinstance(value, str) and value for value in environment.values())
    ):
        fail(f"{root}: schema/tool/source provenance is incomplete")
    expected_input_keys = {
        *CANONICAL_FULL_INPUTS,
        "campaign_kind",
        "cells",
        "bird_image_id",
        "openbgpd_image_id",
    }
    if set(inputs) != expected_input_keys or any(
        inputs.get(key) != value for key, value in CANONICAL_FULL_INPUTS.items()
    ):
        fail(f"{root}: full workload inputs are not exact and canonical")
    selected_image = re.compile(r"sha256:[0-9a-f]{64}")
    expected_image_id = selected_image.fullmatch if kind == "comparison" else None
    if (
        kind == "comparison"
        and not all(
            isinstance(inputs.get(key), str) and expected_image_id(inputs[key])
            for key in ("bird_image_id", "openbgpd_image_id")
        )
    ) or (
        kind != "comparison"
        and any(
            inputs.get(key) != "not-selected"
            for key in ("bird_image_id", "openbgpd_image_id")
        )
    ):
        fail(f"{root}: container image identities do not match the campaign role")
    actual_shape = tuple(int(inputs.get(name, -1)) for name in ("n_members", "total_prefixes", "min_list", "max_list", "seed"))
    if actual_shape != CANONICAL_SHAPE or int(inputs.get("reloads", -1)) != 4:
        fail(f"{root}: noncanonical full shape/seed/reload count")
    commit = git.get("commit")
    if (
        not isinstance(commit, str)
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or not isinstance(git.get("origin_main"), str)
        or not re.fullmatch(r"[0-9a-f]{40}", git.get("origin_main"))
        or git.get("dirty") is not False
        or git.get("origin_main") != commit
        or git.get("head_matches_origin_main") is not True
        or not re.fullmatch(r"[0-9a-f]{64}", git.get("dirty_state_sha256", ""))
        or set(git)
        != {
            "commit",
            "dirty",
            "dirty_state_sha256",
            "origin_main",
            "head_matches_origin_main",
        }
    ):
        fail(f"{root}: full source/preflight contract not proven")
    dataset = (root / "dataset.sha256").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", dataset):
        fail(f"{root}: invalid canonical dataset digest")
    rows_data = read_rows(root / "rows.csv", expected_cells)
    completed = read_json(root / "COMPLETED")
    if (
        completed.get("status") != "pass"
        or completed.get("fingerprint") != fingerprint
        or completed.get("cells") != ",".join(expected_cells)
        or not isinstance(completed.get("completed_at_epoch_ns"), int)
        or completed.get("completed_at_epoch_ns", -1) <= provenance["started_at_epoch_ns"]
    ):
        fail(f"{root}: COMPLETED does not bind status/cells/fingerprint/time")
    identities = []
    transaction_evidence = None
    for cell in expected_cells:
        cdir = root / cell
        validate_quiet(cdir / "quiet.tsv")
        identities.append(validate_process(cdir / "process.tsv"))
        for marker in ("ready", "ack"):
            marker_path = cdir / "final-evidence" / marker
            if marker_path.is_symlink() or not marker_path.is_file() or marker_path.read_text() != f"{marker}\n":
                fail(f"{root}: {cell} final-evidence {marker} is not an exact regular marker")
        manifest = read_json(cdir / "manifest.json")
        scenario_digest = validate_scenario_roster(cdir, manifest)
        scenario_entries = parse_digest_roster(
            cdir / "scenario.sha256", {*manifest["runtime_files"], "manifest.json"}
        )
        validate_cell_chain(
            root,
            cell,
            provenance,
            scenario_digest,
            dataset,
            rows_data,
            320,
            183040,
        )
        if manifest.get("dataset_sha256") != dataset or manifest.get("admit_churn") is not True:
            fail(f"{root}: {cell} manifest dataset/churn mismatch")
        manifest_shape = tuple(
            int(manifest.get(name, -1))
            for name in ("n_members", "total_prefixes", "min_list", "max_list", "seed")
        )
        if manifest_shape != CANONICAL_SHAPE:
            fail(f"{root}: {cell} manifest does not describe the canonical dataset")
        if cell == "rustbgpd-sighup":
            if manifest.get("path_hiding") is not True or manifest.get("path_hiding_applicable") is not True:
                fail(f"{root}: private rustbgpd path-hiding mode not explicit")
        elif cell == GROUPED_CELL:
            if manifest.get("path_hiding") is not False or manifest.get("path_hiding_applicable") is not True:
                fail(f"{root}: grouped rustbgpd path-hiding mode not explicit")
        elif cell == TRANSACTION_CELL:
            if manifest.get("path_hiding") is not True or manifest.get("path_hiding_applicable") is not True:
                fail(f"{root}: transaction path-hiding mode not explicit")
            transaction_evidence = validate_transaction_evidence(
                cdir, identities[-1], scenario_entries
            )
        elif not (
            manifest.get("path_hiding") is None
            and manifest.get("path_hiding_applicable") is False
            and manifest.get("path_hiding_requested") is True
        ):
            fail(f"{root}: competitor path-hiding applicability is misstated")
        if cell in ("rustbgpd-sighup", GROUPED_CELL):
            for marker in ("ready", "ack"):
                marker_path = cdir / "pre-churn" / marker
                if marker_path.is_symlink() or not marker_path.is_file() or marker_path.read_text() != f"{marker}\n":
                    fail(f"{root}: {cell} pre-churn {marker} is not an exact regular marker")
            topology = read_json(cdir / "topology.json")
            expected_mode = "private" if cell == "rustbgpd-sighup" else "grouped"
            with tempfile.NamedTemporaryFile() as revalidated:
                validate_topology(
                    expected_mode,
                    320,
                    183040,
                    cdir / "config.toml",
                    cdir / "topology.tsv",
                    [cdir / f"metrics-{sample}.prom" for sample in range(1, 4)],
                    Path(revalidated.name),
                )
                raw_topology = read_json(Path(revalidated.name))
            scrapes = topology.get("scrape_epoch_ns", [])
            if (
                any(topology.get(key) != raw_topology.get(key) for key in ("status", "mode", "peers", "scrape_epoch_ns", "group_id"))
                or topology.get("status") != "pass"
                or topology.get("mode") != expected_mode
                or topology.get("peers") != 320
                or len(scrapes) != 3
                or any(right - left < 1_000_000_000 for left, right in zip(scrapes, scrapes[1:]))
                or scrapes[-1] // 1000 >= int(topology.get("first_reload_wall_us", -1))
            ):
                fail(f"{root}: {cell} pre-reload topology proof is invalid")
    return {
        "root": root,
        "kind": kind,
        "commit": commit,
        "dataset": dataset,
        "shape": actual_shape,
        "started": int(provenance.get("started_at_epoch_ns", -1)),
        "completed": int(completed.get("completed_at_epoch_ns", -1)),
        "git": git,
        "scripts": scripts,
        "binaries": binaries,
        "environment": environment,
        "inputs": inputs,
        "identities": identities,
        "rows": rows_data,
        "transaction_evidence": transaction_evidence,
    }


def audit_combined(path: Path, expected_cells: tuple[str, ...]) -> None:
    with path.open(newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        data = list(reader)
    if header != ["repeat", *ROWS_HEADER.split(",")]:
        fail(f"{path}: combined output header mismatch")
    if len(data) != 8 * len(expected_cells):
        fail(f"{path}: combined output row count mismatch")
    for repeat in ("A", "B"):
        repeat_rows = [row for row in data if row and row[0] == repeat]
        if len(repeat_rows) != 4 * len(expected_cells) or {
            row[1] for row in repeat_rows
        } != set(expected_cells):
            fail(f"{path}: {repeat} cell roster/count mismatch")
        for cell in expected_cells:
            if [row[2] for row in repeat_rows if row[1] == cell] != ["1", "2", "3", "4"]:
                fail(f"{path}: {repeat}/{cell} reload roster mismatch")
    if {row[0] for row in data if row} != {"A", "B"}:
        fail(f"{path}: repeat labels must be exactly A/B")


def write_combined(path: Path, campaigns, expected_cells: tuple[str, ...]) -> None:
    if len(campaigns) != 2 or any(
        {row[0] for row in campaign["rows"]} != set(expected_cells)
        or len(campaign["rows"]) != 4 * len(expected_cells)
        for campaign in campaigns
    ):
        fail(f"{path}: writer input escaped expected cell roster")
    with path.open("w", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["repeat", *ROWS_HEADER.split(",")])
        for repeat, campaign in zip(("A", "B"), campaigns, strict=True):
            for row in campaign["rows"]:
                writer.writerow([repeat, *row])
    audit_combined(path, expected_cells)


def validate_campaigns(roots: list[Path], output_dir: Path) -> None:
    if len(roots) != 4:
        fail("expected four roots in comparison-A/grouped-A/grouped-B/comparison-B order")
    campaigns = [
        validate_root(roots[0], "comparison"),
        validate_root(roots[1], "grouped"),
        validate_root(roots[2], "grouped"),
        validate_root(roots[3], "comparison"),
    ]
    if len({(entry["commit"], entry["shape"], entry["dataset"]) for entry in campaigns}) != 1:
        fail("four roots do not share commit, canonical shape/seed, and dataset digest")
    starts = [entry["started"] for entry in campaigns]
    if any(value <= 0 for value in starts) or starts != sorted(starts) or len(set(starts)) != 4:
        fail("roots are not in strict A/B/B/A execution order")
    if any(
        campaigns[index]["completed"] >= campaigns[index + 1]["started"]
        for index in range(3)
    ):
        fail("campaign roots overlap or do not finish before the next root starts")
    source_identity = ("git", "scripts", "binaries", "environment")
    if any(
        tuple(campaign[key] for key in source_identity)
        != tuple(campaigns[0][key] for key in source_identity)
        for campaign in campaigns[1:]
    ):
        fail("four roots do not share exact source, tool, and platform identities")
    repeat_identity = ("git", "scripts", "binaries", "environment", "inputs")
    for left, right in ((campaigns[0], campaigns[3]), (campaigns[1], campaigns[2])):
        if tuple(left[key] for key in repeat_identity) != tuple(
            right[key] for key in repeat_identity
        ):
            fail("A/B repeats do not share exact protocol, tool, and image identities")
    identities = [identity for entry in campaigns for identity in entry["identities"]]
    if len(identities) != len(set(identities)):
        fail("daemon PID/start identity was reused across campaign cells")
    output_dir.mkdir(parents=True, exist_ok=False)
    write_combined(
        output_dir / "comparison.csv", (campaigns[0], campaigns[3]), COMPARISON_CELLS
    )
    write_combined(
        output_dir / "grouped-control.csv", (campaigns[1], campaigns[2]), (GROUPED_CELL,)
    )
    (output_dir / "verification.json").write_text(
        json.dumps(
            {
                "status": "pass",
                "order": ["comparison-A", "grouped-A", "grouped-B", "comparison-B"],
                "commit": campaigns[0]["commit"],
                "dataset_sha256": campaigns[0]["dataset"],
                "comparison_rows": len(campaigns[0]["rows"]) + len(campaigns[3]["rows"]),
                "grouped_control_rows": len(campaigns[1]["rows"]) + len(campaigns[2]["rows"]),
            },
            sort_keys=True,
        )
        + "\n"
    )


def validate_transactions(roots: list[Path], output_dir: Path) -> None:
    if len(roots) != 2:
        fail("expected exactly two transaction roots in A/B order")
    campaigns = [validate_root(root, "transaction") for root in roots]
    if len({(entry["commit"], entry["shape"], entry["dataset"]) for entry in campaigns}) != 1:
        fail("transaction roots do not share commit, canonical shape/seed, and dataset")
    if campaigns[0]["completed"] >= campaigns[1]["started"]:
        fail("transaction roots overlap or are not in A/B order")
    shared = ("git", "scripts", "binaries", "environment", "inputs")
    if any(campaigns[0][key] != campaigns[1][key] for key in shared):
        fail("transaction roots do not share exact source, tool, platform, and inputs")
    if campaigns[0]["transaction_evidence"] != campaigns[1]["transaction_evidence"]:
        fail("transaction roots do not share exact A/B input and applied-state identities")
    identities = [identity for campaign in campaigns for identity in campaign["identities"]]
    if len(identities) != len(set(identities)):
        fail("daemon PID/start identity was reused across transaction roots")
    output_dir.mkdir(parents=True, exist_ok=False)
    write_combined(output_dir / "transactions.csv", campaigns, (TRANSACTION_CELL,))
    (output_dir / "verification.json").write_text(
        json.dumps(
            {
                "status": "pass",
                "order": ["transaction-A", "transaction-B"],
                "commit": campaigns[0]["commit"],
                "dataset_sha256": campaigns[0]["dataset"],
                "transaction_rows": sum(len(campaign["rows"]) for campaign in campaigns),
            },
            sort_keys=True,
        )
        + "\n"
    )


def make_transaction_evidence(cdir: Path, pid: int) -> None:
    size = 11 * 1024 * 1024
    history = {"entries": [], "files": []}
    process = {"pid": pid, "starttime": pid + 100, "vmrss_kib": 1024, "vmhwm_kib": 2048}

    def content(digest):
        return {"sha256": digest * 64, "bytes": size,
                "marker": "65400:1000" if digest == "a" else "65400:2000"}

    def file_identity(name, digest, inode, bytes_count):
        return {"name": name, "device": 1, "inode": inode, "bytes": bytes_count,
                "sha256": digest * 64, "mode": "0600", "owner_current_uid": True}

    def authority(confirm_id, deadline, inode):
        return {"schema": 1, "version": 3, "confirm_id": confirm_id,
            "deadline_unix_seconds": deadline, "linkage_verified": True,
            "locator": file_identity("config.toml.commit-confirm-locator.json", "c", inode, 100),
            "raw": file_identity("commit-confirm-v3-prior.toml", "d", inode + 1, size),
            "metadata": file_identity("commit-confirm-v3-metadata.json", "e", inode + 2, 200)}

    def base_state(digest):
        return {"history_entries": 0, "history_outcome": "skipped_oversize",
                "process": process, "config": content(digest), "runtime": content(digest)}

    def pending(digest, confirm_id, deadline, inode):
        return {"authority": authority(confirm_id, deadline, inode),
                "legacy_absent": True, **base_state(digest)}

    def terminal(digest):
        return {"v3_absent": True, "legacy_absent": True, **base_state(digest)}

    def warning(before):
        return {"count_before": before, "count_after": before + 1, "bytes": size}

    cycles = []
    for number in range(1, 5):
        digest = "b" if number % 2 else "a"
        confirm_id = f"irrreload-measured-{number}"
        deadline = 1_000 + number
        cycles.append(
            {
                "schema": 1,
                "cycle": number,
                "candidate": content(digest),
                "plan": {"transport": "streamed", "status": "committable", "plan_token_present": True, "runtime_snapshot_token_present": True},
                "apply": {"transport": "streamed", "explicit_plan_token": True, "status": "committable", "confirmation_status": "pending", "confirm_id": confirm_id, "timeout_seconds": 600, "deadline_unix_seconds": deadline, "runtime_token_coherent": True},
                "history": {"before": history, "after": history, "outcome": "skipped_oversize", "warning": warning(number)},
                "pending": pending(digest, confirm_id, deadline, 100 + number * 10),
                "confirmed": {"status": "confirmed", "status_view_verified": True, **terminal(digest)},
            }
        )
    txn_dir = cdir / "transactions"
    txn_dir.mkdir()
    (txn_dir / "cycles.jsonl").write_text("".join(json.dumps(cycle) + "\n" for cycle in cycles))

    def phase(name, timeout, apply_before, restore_before, inode):
        confirm_id = f"irrreload-{name}"
        deadline = 2_000 + inode
        return {"candidate_role": "opposite",
            "plan": {"transport": "streamed", "status": "committable", "plan_token_present": True, "runtime_snapshot_token_present": True},
            "apply": {"transport": "streamed", "explicit_plan_token": True, "status": "committable", "confirmation_status": "pending", "confirm_id": confirm_id, "timeout_seconds": timeout, "deadline_unix_seconds": deadline, "runtime_token_coherent": True},
            "history_before": history, "apply_history_warning": warning(apply_before),
            "pending": pending("b", confirm_id, deadline, inode),
            "terminal": {"status": "aborted" if name == "abort" else "auto_reverted",
                "status_view_verified": True, "restored_exactly": True,
                "history_warning": warning(restore_before),
                "history_after": history, **terminal("a")}}

    lifecycle = {
        "schema": 1,
        "generations": {"current": content("a"), "opposite": content("b")},
        "baseline": base_state("a"),
        "abort": phase("abort", 600, 5, 6, 200),
        "timeout": phase("timeout", 10, 7, 8, 300),
        "restored_current_plan": {"transport": "streamed", "status": "noop", "plan_token_present": False},
        "final_state": base_state("a"),
    }
    (txn_dir / "lifecycle.json").write_text(json.dumps(lifecycle) + "\n")
    warning_line = json.dumps({"fields": {"message": "applied config exceeds the bounded history entry size; history was left unchanged", "bytes": size}})
    (cdir / "daemon.log").write_text((warning_line + "\n") * 9)


def make_fixture(root: Path, kind: str, started: int, identity_seed: int) -> None:
    cells = {
        "comparison": COMPARISON_CELLS,
        "grouped": (GROUPED_CELL,),
        "transaction": (TRANSACTION_CELL,),
    }[kind]
    root.mkdir()
    dataset = "a" * 64
    (root / "dataset.sha256").write_text(dataset + "\n")
    image_id = "sha256:" + "a" * 64
    provenance = {
        "schema": 3,
        "started_at_epoch_ns": started,
        "git": {"commit": "c" * 40, "dirty": False, "dirty_state_sha256": "d" * 64, "origin_main": "c" * 40, "head_matches_origin_main": True},
        "scripts": {"runner": "1" * 64, "verifier": "2" * 64, "generator": "3" * 64, "rss_sampler": "4" * 64, "txn_apply": "5" * 64, "txn_lifecycle": "a" * 64},
        "binaries": {"reloadstall": "6" * 64, "rustbgpd": "7" * 64, "rbgp": "8" * 64, "rs_config_render": "9" * 64},
        "environment": {key: "fixture" for key in ("rustc", "cargo", "python", "jq", "docker", "kernel", "cpu_model")},
        "inputs": {
            **CANONICAL_FULL_INPUTS,
            "campaign_kind": {"comparison": "full-cross-daemon", "grouped": "full-grouped-control", "transaction": "full-transaction"}[kind],
            "cells": ",".join(cells),
            "bird_image_id": image_id if kind == "comparison" else "not-selected",
            "openbgpd_image_id": image_id if kind == "comparison" else "not-selected",
        },
    }
    provenance["fingerprint"] = provenance_fingerprint(provenance)
    fingerprint = provenance["fingerprint"]
    (root / "provenance.json").write_text(json.dumps(provenance))
    (root / "preflight.log").write_text(
        "  ok: bench-nightly cron is paused for the soak window (confirmed via fixture)\n"
        "  ok: no pushes to main during the soak window (confirmed via fixture)\n"
        "[preflight] READY — all pre-flight checks passed\n"
    )
    root_rows = []
    with (root / "rows.csv").open("w") as stream:
        stream.write(ROWS_HEADER + "\n")
        for cell in cells:
            for reload_no in range(1, 5):
                row = [cell, str(reload_no), "320", "320", "0", "183040", *(["1"] * 14), "0", "320", "0"]
                root_rows.append(row)
                stream.write(",".join(row) + "\n")
    for offset, cell in enumerate(cells):
        cdir = root / cell
        cdir.mkdir()
        (cdir / "quiet.tsv").write_text(
            "sample\tepoch_s\tload1\tpswpin\tpswpout\tport1790_free\tport9179_free\tdisk_available_kib\n"
            "1\t1\t0.5\t0\t0\ttrue\ttrue\t41943040\n2\t31\t0.5\t0\t0\ttrue\ttrue\t41943040\n"
        )
        pid = identity_seed + offset
        (cdir / "process.tsv").write_text(f"pid\tstarttime_before\tstarttime_after\n{pid}\t{pid + 100}\t{pid + 100}\n")
        if cell == "rustbgpd-sighup":
            mode = {"path_hiding": True, "path_hiding_applicable": True, "path_hiding_requested": True}
        elif cell == GROUPED_CELL:
            mode = {"path_hiding": False, "path_hiding_applicable": True, "path_hiding_requested": False}
        elif cell == TRANSACTION_CELL:
            mode = {"path_hiding": True, "path_hiding_applicable": True, "path_hiding_requested": True}
        else:
            mode = {"path_hiding": None, "path_hiding_applicable": False, "path_hiding_requested": True}
        runtime_files = {
            "rustbgpd-sighup": ["config.toml", "member.rpol", "gen-a.rpol", "gen-b.rpol"],
            GROUPED_CELL: ["config.toml", "member.rpol", "gen-a.rpol", "gen-b.rpol"],
            TRANSACTION_CELL: ["config.toml", "candidate.toml", "gen-a.toml", "gen-b.toml"],
            "bird": ["bird.conf", "gen.conf", "gen-a.conf", "gen-b.conf"],
            "openbgpd": ["bgpd.conf", "gen.conf", "gen-a.conf", "gen-b.conf"],
        }[cell]
        manifest = {"dataset_sha256": dataset, "admit_churn": True, "n_members": 320, "total_prefixes": 183040, "min_list": 1000, "max_list": 40000, "seed": 61, "runtime_files": runtime_files, **mode}
        (cdir / "manifest.json").write_text(json.dumps(manifest))
        cell_rows = [row for row in root_rows if row[0] == cell]
        (cdir / "rows.csv").write_text("".join(",".join(row) + "\n" for row in cell_rows))
        (cdir / "reloadstall.log").write_text(
            "".join("reloadstall_csv," + ",".join(row[1:]) + "\n" for row in cell_rows)
        )
        (cdir / "daemon.log").write_text("fixture daemon log\n")
        (cdir / "rss.csv").write_text("epoch_s,total_rss_kib,pids\n1,1024,1\n")
        final_boundary = cdir / "final-evidence"
        final_boundary.mkdir()
        (final_boundary / "ready").write_text("ready\n")
        (final_boundary / "ack").write_text("ack\n")
        if cell in ("rustbgpd-sighup", GROUPED_CELL):
            topology_mode = "private" if cell == "rustbgpd-sighup" else "grouped"
            group_id = None if topology_mode == "private" else 7
            (cdir / "topology.json").write_text(json.dumps({"status": "pass", "mode": topology_mode, "peers": 320, "scrape_epoch_ns": [1_000_000_000, 2_000_000_000, 3_000_000_000], "group_id": group_id, "first_reload_wall_us": 4_000_000}))
            (cdir / "config.toml").write_text("per_client_best = true\n" * (320 if cell == "rustbgpd-sighup" else 0))
            (cdir / "topology.tsv").write_text("phase\tepoch_ns\nscrape1\t1000000000\nscrape2\t2000000000\nscrape3\t3000000000\n")
            metrics = ["bgp_rib_outbound_registered_peers 320", "bgp_rib_ingest_channel_depth 0", "bgp_rib_policy_transition_in_progress 0", 'bgp_rib_loc_prefixes{afi_safi="all"} 183040']
            for peer in range(320):
                metrics += [f'bgp_peer_session_established{{interface="eth0",peer="p{peer}"}} 1', f'bgp_peer_outbound_queue_depth{{peer="p{peer}"}} 0']
                metrics += [f'bgp_session_established_total{{peer="p{peer}"}} 1']
                metrics += [f'bgp_rib_prefixes{{afi_safi="{family}",peer="p{peer}"}} {572 if family == "all" else 0}' for family in ("all", "flowspec")]
                metrics += [f'bgp_rib_adj_out_prefixes{{afi_safi="{family}",peer="p{peer}"}} {182468 if family == "all" else 0}' for family in ("all", "bgpls", "evpn", "flowspec", "labeled", "rtc", "vpn")]
            if topology_mode == "private":
                metrics += ["bgp_update_groups 0", "bgp_update_group_fallback_peers 320"]
                metrics += [f'bgp_peer_update_group{{peer="p{peer}"}} -1' for peer in range(320)]
            else:
                metrics += ["bgp_update_groups 1", "bgp_update_group_fallback_peers 0", 'bgp_update_group_members{group="7"} 320']
                metrics += [f'bgp_peer_update_group{{peer="p{peer}"}} 7' for peer in range(320)]
            for sample in range(1, 4):
                (cdir / f"metrics-{sample}.prom").write_text("\n".join(metrics) + "\n")
            boundary = cdir / "pre-churn"
            boundary.mkdir()
            (boundary / "ready").write_text("ready\n")
            (boundary / "ack").write_text("ack\n")
        elif cell == TRANSACTION_CELL:
            make_transaction_evidence(cdir, pid)
        scenario_lines = []
        for relative in [*runtime_files, "manifest.json"]:
            retained_input = cdir / relative
            if cell == TRANSACTION_CELL and relative == "gen-a.toml":
                digest = "a" * 64
            elif cell == TRANSACTION_CELL and relative == "gen-b.toml":
                digest = "b" * 64
            else:
                digest = sha256(retained_input) if retained_input.is_file() else "0" * 64
            scenario_lines.append(f"{digest}  ./{relative}")
        (cdir / "scenario.sha256").write_text("\n".join(sorted(scenario_lines)) + "\n")
        cell_provenance = json.loads(json.dumps(provenance))
        cell_provenance["scenario"] = {
            "manifest_sha256": sha256(cdir / "scenario.sha256"),
            "dataset_sha256": dataset,
        }
        (cdir / "provenance.json").write_text(json.dumps(cell_provenance))
        retained = {
            path.relative_to(cdir).as_posix()
            for path in cdir.rglob("*")
            if path.is_file()
        }
        lines = [f"{sha256(cdir / relative)}  {relative}" for relative in sorted(retained)]
        (cdir / "evidence.sha256").write_text("\n".join(lines) + "\n")
        evidence_digest = sha256(cdir / "evidence.sha256")
        scenario_digest = sha256(cdir / "scenario.sha256")
        (cdir / "status").write_text(
            f"pass {fingerprint} {scenario_digest} {dataset} {evidence_digest}\n"
        )
    (root / "COMPLETED").write_text(json.dumps({"status": "pass", "fingerprint": fingerprint, "completed_at_epoch_ns": started + 5, "cells": ",".join(cells)}))
    reseal(root)
    freeze(root)


def thaw(root: Path) -> None:
    for path in [root, *root.rglob("*")]:
        path.chmod(path.stat().st_mode | stat.S_IWUSR)


def freeze(root: Path) -> None:
    for path in sorted([root, *root.rglob("*")], key=lambda item: len(item.parts), reverse=True):
        path.chmod(path.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def reseal(root: Path) -> None:
    roster = root / "SHA256SUMS"
    if roster.exists():
        roster.unlink()
    lines = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        lines.append(f"{sha256(path)}  {path.relative_to(root).as_posix()}")
    roster.write_text("\n".join(lines) + "\n")


def reseal_cell_evidence(root: Path) -> None:
    for roster in root.rglob("evidence.sha256"):
        cdir = roster.parent
        status = cdir / "status"
        retained = {
            path.relative_to(cdir).as_posix()
            for path in cdir.rglob("*")
            if path.is_file() and path.name not in {"evidence.sha256", "status"}
        }
        roster.write_text(
            "\n".join(
                f"{sha256(cdir / relative)}  {relative}" for relative in sorted(retained)
            )
            + "\n"
        )
        prior = status.read_text().split()
        status.write_text(
            f"pass {prior[1]} {sha256(cdir / 'scenario.sha256')} {prior[3]} {sha256(roster)}\n"
        )


def rebind_provenance(root: Path) -> None:
    provenance_path = root / "provenance.json"
    provenance = read_json(provenance_path)
    provenance["fingerprint"] = provenance_fingerprint(provenance)
    provenance_path.write_text(json.dumps(provenance))
    for cell in (*COMPARISON_CELLS, GROUPED_CELL, TRANSACTION_CELL):
        cell_path = root / cell / "provenance.json"
        if not cell_path.is_file():
            continue
        cell_provenance = read_json(cell_path)
        scenario = cell_provenance["scenario"]
        cell_path.write_text(json.dumps({**provenance, "scenario": scenario}))
        status_path = cell_path.parent / "status"
        status = status_path.read_text().split()
        status[1] = provenance["fingerprint"]
        status_path.write_text(" ".join(status) + "\n")
    completed_path = root / "COMPLETED"
    completed = read_json(completed_path)
    completed["fingerprint"] = provenance["fingerprint"]
    completed_path.write_text(json.dumps(completed))


def self_test() -> None:
    proofs = {}
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)

        v3_dir = base / "v3"
        v3_dir.mkdir(mode=0o700)
        v3_config, v3_raw = v3_dir / "config.toml", v3_dir / "commit-confirm-v3-prior.toml"
        v3_metadata = v3_dir / "commit-confirm-v3-metadata.json"; v3_locator = v3_dir / "config.toml.commit-confirm-locator.json"
        v3_config.write_text("candidate\n")
        v3_raw.write_text("prior\n")
        v3_raw.chmod(0o600)
        raw_stat = v3_raw.stat()
        raw_sha = sha256(v3_raw)
        manifest = {"toml_sha256": raw_sha, "rpol_units": [], "datasets": []}
        source_sha = inline_manifest_source_sha256(manifest, raw_sha)

        def wire_path(path: Path) -> dict:
            return {"encoding": "unix-bytes-hex", "value": os.fsencode(str(path.resolve(strict=True))).hex()}

        def write_canonical(path: Path, value: dict) -> None:
            path.write_bytes(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n")
            path.chmod(0o600)

        metadata_value = {
            "version": 3, "confirm_id": "fixture-confirm", "deadline_unix_seconds": 1234,
            "rollback_failed": False,
            "raw_name": {"encoding": "unix-bytes-hex", "value": b"commit-confirm-v3-prior.toml".hex()},
            "raw_length": raw_stat.st_size, "raw_sha256": raw_sha, "raw_source_sha256": source_sha,
            "raw_device": raw_stat.st_dev, "raw_inode": raw_stat.st_ino, "manifest": manifest,
        }
        write_canonical(v3_metadata, metadata_value)
        locator_value = {"version": 3, "confirm_id": "fixture-confirm",
                         "metadata_path": wire_path(v3_metadata), "config_target": wire_path(v3_config),
                         "prior_sha256": raw_sha, "prior_source_sha256": source_sha}
        write_canonical(v3_locator, locator_value)
        inspect_v3(v3_locator, v3_metadata, v3_raw, v3_config, "fixture-confirm")

        def inspect_rejected(name: str, mutate) -> None:
            copied = base / f"bad-{name}"
            shutil.copytree(v3_dir, copied)
            copied_raw, copied_metadata = copied / v3_raw.name, copied / v3_metadata.name
            copied_locator, copied_config = copied / v3_locator.name, copied / v3_config.name
            copied_stat = copied_raw.stat()
            copied_metadata_value = read_json(copied_metadata)
            copied_metadata_value.update(raw_device=copied_stat.st_dev, raw_inode=copied_stat.st_ino)
            write_canonical(copied_metadata, copied_metadata_value)
            copied_locator_value = read_json(copied_locator)
            copied_locator_value.update(metadata_path=wire_path(copied_metadata), config_target=wire_path(copied_config))
            write_canonical(copied_locator, copied_locator_value)
            mutate(copied)
            try:
                inspect_v3(copied_locator, copied_metadata, copied_raw, copied_config, "fixture-confirm")
            except InvalidReceipt:
                proofs[name] = True
                return
            fail(f"red v3 inspector fixture unexpectedly accepted: {name}")

        def corrupt_metadata(copied: Path) -> None:
            value = read_json(copied / v3_metadata.name)
            value["raw_sha256"] = "f" * 64
            write_canonical(copied / v3_metadata.name, value)

        def corrupt_target(copied: Path) -> None:
            value = read_json(copied / v3_locator.name)
            value["config_target"] = {"encoding": "unix-bytes-hex", "value": b"/wrong/config.toml".hex()}
            write_canonical(copied / v3_locator.name, value)

        def corrupt_order(copied: Path) -> None:
            value = read_json(copied / v3_locator.name)
            write_canonical(copied / v3_locator.name, {
                "version": value["version"], "metadata_path": value["metadata_path"],
                "confirm_id": value["confirm_id"], "config_target": value["config_target"],
                "prior_sha256": value["prior_sha256"], "prior_source_sha256": value["prior_source_sha256"],
            })

        def corrupt_nested_order(copied: Path) -> None:
            value = read_json(copied / v3_locator.name); wire = value["metadata_path"]
            value["metadata_path"] = {"value": wire["value"], "encoding": wire["encoding"]}
            write_canonical(copied / v3_locator.name, value)

        def corrupt_raw_utf8(copied: Path) -> None:
            raw_path = copied / v3_raw.name; raw_path.write_bytes(b"prior\xff\n"); raw_path.chmod(0o600)
            raw_stat = raw_path.stat(); raw_sha = sha256(raw_path)
            metadata_path = copied / v3_metadata.name; value = read_json(metadata_path)
            value.update(raw_length=raw_stat.st_size, raw_sha256=raw_sha, raw_device=raw_stat.st_dev, raw_inode=raw_stat.st_ino)
            value["manifest"]["toml_sha256"] = raw_sha
            value["raw_source_sha256"] = inline_manifest_source_sha256(value["manifest"], raw_sha)
            write_canonical(metadata_path, value)
            locator_path = copied / v3_locator.name; locator = read_json(locator_path)
            locator.update(prior_sha256=raw_sha, prior_source_sha256=value["raw_source_sha256"])
            write_canonical(locator_path, locator)

        inspect_rejected("v3-inspector-linkage", corrupt_metadata)
        inspect_rejected("v3-inspector-mode", lambda copied: (copied / v3_raw.name).chmod(0o644))
        inspect_rejected("v3-inspector-target", corrupt_target)
        inspect_rejected("v3-inspector-field-order", corrupt_order)
        inspect_rejected("v3-inspector-nested-order", corrupt_nested_order)
        inspect_rejected("v3-inspector-raw-utf8", corrupt_raw_utf8)
        inspect_rejected(
            "v3-inspector-canonical",
            lambda copied: (copied / v3_locator.name).write_text(json.dumps(read_json(copied / v3_locator.name), indent=2) + "\n"),
        )

        topology_dir = base / "topology"
        topology_dir.mkdir()
        timestamps = topology_dir / "timestamps.tsv"
        timestamps.write_text(
            "phase\tepoch_ns\n"
            "scrape1\t1000000000\n"
            "scrape2\t2000000000\n"
            "scrape3\t3000000000\n"
        )

        def metric_text(mode: str, bad: str | None = None) -> str:
            lines = [
                "bgp_rib_outbound_registered_peers 2",
                "bgp_rib_ingest_channel_depth 0",
                "bgp_rib_policy_transition_in_progress 0",
                f'bgp_rib_loc_prefixes{{afi_safi="all"}} {7 if bad == "route-gauge" else 8}',
            ]
            for peer in ("p0", "p1"):
                established_peer = (
                    "unexpected" if bad == "establishment-roster" and peer == "p1"
                    else peer
                )
                lines += [
                    f'bgp_peer_session_established{{interface="eth0",peer="{peer}"}} {0 if bad == "current-down" else 1}',
                    f'bgp_session_established_total{{peer="{established_peer}"}} {2 if bad == "reestablished" else 1}',
                    f'bgp_peer_outbound_queue_depth{{peer="{peer}"}} 0',
                ]
                if peer == "p0":
                    flap_peer = "unexpected" if bad == "flap-roster" else peer
                    lines.append(
                        f'bgp_session_flaps_total{{peer="{flap_peer}"}} '
                        f'{1 if bad == "flapped" else 0}'
                    )
                lines += [
                    f'bgp_rib_prefixes{{afi_safi="{family}",peer="{peer}"}} '
                    f'{4 if family == "all" else int(bad == "route-family" and peer == "p1")}'
                    for family in ("all", "flowspec")
                ]
                lines += [
                    f'bgp_rib_adj_out_prefixes{{afi_safi="{family}",peer="{peer}"}} '
                    f'{4 if family == "all" else 0}'
                    for family in ("all", "bgpls", "evpn", "flowspec", "labeled", "rtc", "vpn")
                ]
            if bad == "counter-malformed":
                lines.append('bgp_session_flaps_total{peer="p0"} broken')
            if mode == "private":
                lines += ["bgp_update_groups 0", "bgp_update_group_fallback_peers 2"]
                lines += [f'bgp_peer_update_group{{peer="p{index}"}} -1' for index in range(2)]
            else:
                group = 8 if bad == "drift" else 7
                lines += [f"bgp_update_groups {2 if bad == 'group' else 1}", "bgp_update_group_fallback_peers 0", f'bgp_update_group_members{{group="{group}"}} 2']
                lines += [f'bgp_peer_update_group{{peer="p{index}"}} {group}' for index in range(2)]
            return "\n".join(lines) + "\n"

        for mode in ("private", "grouped"):
            config = topology_dir / f"{mode}.toml"
            config.write_text("per_client_best = true\n" * (2 if mode == "private" else 0))
            paths = []
            for sample in range(1, 4):
                path = topology_dir / f"{mode}-{sample}.prom"
                path.write_text(metric_text(mode))
                paths.append(path)
            validate_topology(mode, 2, 8, config, timestamps, paths, topology_dir / f"{mode}.json")
        def topology_rejected(name: str, bad: str, config: Path | None = None):
            paths = []
            for sample in range(1, 4):
                path = topology_dir / f"{name}-{sample}.prom"
                if bad in {"drift", "current-down", "counter-malformed", "establishment-roster", "flap-roster"}:
                    effective_bad = bad if sample == 3 else None
                elif bad in {"reestablished", "flapped"}:
                    effective_bad = bad if sample > 1 else None
                else:
                    effective_bad = bad
                path.write_text(metric_text("grouped", effective_bad))
                paths.append(path)
            try:
                validate_topology("grouped", 2, 8, config or topology_dir / "grouped.toml", timestamps, paths, topology_dir / f"{name}.json")
            except InvalidReceipt:
                proofs[name] = True

        topology_rejected("live-topology-gauge", "group")
        topology_rejected("route-gauge", "route-gauge")
        topology_rejected("route-family", "route-family")
        topology_rejected("one-scrape-drift", "drift")
        topology_rejected("current-down", "current-down")
        topology_rejected("reestablished", "reestablished")
        topology_rejected("flapped", "flapped")
        topology_rejected("counter-malformed", "counter-malformed")
        topology_rejected("establishment-roster", "establishment-roster")
        topology_rejected("flap-roster", "flap-roster")
        add_path = topology_dir / "add-path.toml"
        add_path.write_text("[neighbors.add_path]\nsend = true\n")
        topology_rejected("add-path", "none", add_path)
        wrong_count = topology_dir / "wrong-count.toml"
        wrong_count.write_text("per_client_best = true\n")
        topology_rejected("config-count", "none", wrong_count)
        names = ("comparison-a", "grouped-a", "grouped-b", "comparison-b")
        kinds = ("comparison", "grouped", "grouped", "comparison")
        roots = [base / name for name in names]
        for index, (root, kind) in enumerate(zip(roots, kinds, strict=True)):
            make_fixture(root, kind, 10 + index * 10, 1000 + index * 10)
        good_output = base / "good-output"
        validate_campaigns(roots, good_output)
        audit_combined(good_output / "comparison.csv", COMPARISON_CELLS)
        audit_combined(good_output / "grouped-control.csv", (GROUPED_CELL,))
        txn_roots = [base / "transaction-a", base / "transaction-b"]
        make_fixture(txn_roots[0], "transaction", 100, 2000)
        make_fixture(txn_roots[1], "transaction", 110, 3000)
        transaction_output = base / "transaction-output"
        validate_transactions(txn_roots, transaction_output)
        audit_combined(transaction_output / "transactions.csv", (TRANSACTION_CELL,))

        def mutate_cycle(root, index, function):
            path = root / TRANSACTION_CELL / "transactions/cycles.jsonl"
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            function(rows[index])
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))

        def mutate_lifecycle(root, function):
            path = root / TRANSACTION_CELL / "transactions/lifecycle.json"
            value = read_json(path); function(value); path.write_text(json.dumps(value) + "\n")

        def txn_alter_json(path, function):
            value = read_json(path); function(value); path.write_text(json.dumps(value) + "\n")

        def txn_rejected(name, mutate, root_index=0, cell_reseal=True):
            copied = base / f"bad-txn-{name}"
            shutil.copytree(txn_roots[root_index], copied); thaw(copied); mutate(copied)
            if cell_reseal:
                reseal_cell_evidence(copied)
            reseal(copied); freeze(copied)
            pair = txn_roots.copy(); pair[root_index] = copied
            try:
                validate_transactions(pair, base / f"txn-output-{name}")
            except InvalidReceipt:
                proofs[name] = True
                return
            fail(f"red transaction fixture unexpectedly accepted: {name}")

        def txn_pair_rejected(name, mutate):
            pair = []
            for index, root in enumerate(txn_roots):
                copied = base / f"bad-txn-{name}-{index}"
                shutil.copytree(root, copied); thaw(copied); mutate(copied)
                reseal_cell_evidence(copied); reseal(copied); freeze(copied); pair.append(copied)
            try:
                validate_transactions(pair, base / f"txn-output-{name}")
            except InvalidReceipt:
                proofs[name] = True; return
            fail(f"red transaction pair unexpectedly accepted: {name}")

        def mutate_candidate_b(root, digest, bind_scenario=False):
            mutate_cycle(root, 0, lambda row: row["candidate"].update({"sha256": digest}))
            mutate_cycle(root, 2, lambda row: row["candidate"].update({"sha256": digest}))
            mutate_lifecycle(root, lambda value: value["generations"]["opposite"].update({"sha256": digest}))
            if bind_scenario:
                cdir = root / TRANSACTION_CELL; scenario = cdir / "scenario.sha256"
                scenario.write_text(scenario.read_text().replace("b" * 64 + "  ./gen-b.toml", digest + "  ./gen-b.toml"))
                txn_alter_json(cdir / "provenance.json", lambda value: value["scenario"].update({"manifest_sha256": sha256(scenario)}))

        def swap_state_markers(state):
            for field in ("config", "runtime"):
                marker = state[field]["marker"]
                state[field]["marker"] = "65400:1000" if marker == "65400:2000" else "65400:2000"

        def swap_applied_markers(root):
            for index in range(4):
                mutate_cycle(root, index, lambda row: (swap_state_markers(row["pending"]), swap_state_markers(row["confirmed"])))
            def swap_lifecycle(value):
                for state in (value["baseline"], value["final_state"], value["abort"]["pending"], value["abort"]["terminal"], value["timeout"]["pending"], value["timeout"]["terminal"]):
                    swap_state_markers(state)
            mutate_lifecycle(root, swap_lifecycle)

        txn_rejected("transaction-cycle-roster", lambda root: mutate_cycle(root, 0, lambda row: row.update({"cycle": 2})))
        txn_rejected("transaction-plan-token", lambda root: mutate_cycle(root, 0, lambda row: row["apply"].update({"explicit_plan_token": False})))
        txn_rejected("transaction-confirm", lambda root: mutate_cycle(root, 0, lambda row: row["confirmed"].update({"status": "pending"})))
        txn_rejected("transaction-v3-pending", lambda root: mutate_cycle(root, 0, lambda row: row["pending"]["authority"]["raw"].update({"bytes": 1024})))
        txn_rejected("transaction-v3-linkage", lambda root: mutate_cycle(root, 0, lambda row: row["pending"]["authority"].update({"linkage_verified": False})))
        txn_rejected("transaction-v3-deadline", lambda root: mutate_cycle(root, 0, lambda row: row["pending"]["authority"].update({"deadline_unix_seconds": 9999})))
        txn_rejected("transaction-v3-cleanup", lambda root: mutate_cycle(root, 0, lambda row: row["confirmed"].update({"v3_absent": False})))
        txn_rejected("transaction-history", lambda root: mutate_cycle(root, 0, lambda row: row["history"]["after"]["entries"].append({"index": 0})))
        txn_rejected("transaction-abort", lambda root: mutate_lifecycle(root, lambda value: value["abort"]["terminal"].update({"status": "confirmed"})))
        txn_rejected("transaction-timeout", lambda root: mutate_lifecycle(root, lambda value: value["timeout"]["terminal"].update({"status": "auto_revert_failed"})))
        txn_rejected("transaction-noop", lambda root: mutate_lifecycle(root, lambda value: value["restored_current_plan"].update({"status": "committable"})))
        txn_rejected("transaction-opposite", lambda root: mutate_lifecycle(root, lambda value: value["generations"].update({"opposite": value["generations"]["current"]})))
        txn_rejected("transaction-token-leak", lambda root: mutate_cycle(root, 0, lambda row: row.update({"plan_token": "00000000-0000-4000-8000-000000000000"})))
        txn_rejected("transaction-warning-log", lambda root: (root / TRANSACTION_CELL / "daemon.log").write_text("missing warning\n"))
        txn_rejected("transaction-warning-binding", lambda root: mutate_cycle(root, 0, lambda row: row["history"]["warning"].update({"bytes": 12 * 1024 * 1024})))
        txn_pair_rejected("transaction-applied-generation", swap_applied_markers)
        txn_pair_rejected("transaction-scenario-generation", lambda root: mutate_candidate_b(root, "f" * 64))
        txn_rejected("transaction-cross-root-generation", lambda root: mutate_candidate_b(root, "f" * 64, True), root_index=1)
        txn_rejected("transaction-port-gate", lambda root: (root / TRANSACTION_CELL / "quiet.tsv").write_text((root / TRANSACTION_CELL / "quiet.tsv").read_text().replace("true\ttrue", "false\ttrue", 1)))
        txn_rejected("transaction-disk-gate", lambda root: (root / TRANSACTION_CELL / "quiet.tsv").write_text((root / TRANSACTION_CELL / "quiet.tsv").read_text().replace("41943040", "41943039", 1)))
        txn_rejected("transaction-swap-gate", lambda root: (root / TRANSACTION_CELL / "quiet.tsv").write_text((root / TRANSACTION_CELL / "quiet.tsv").read_text().replace("2\t31\t0.5\t0\t0", "2\t31\t0.5\t1\t0")))
        txn_rejected("transaction-fallback-shape", lambda root: (txn_alter_json(root / "provenance.json", lambda value: value["inputs"].update({"n_members": "10"})), rebind_provenance(root)))
        txn_rejected("transaction-mixed-binary", lambda root: (txn_alter_json(root / "provenance.json", lambda value: value["binaries"].update({"rbgp": "f" * 64})), rebind_provenance(root)), root_index=1)

        def reuse_transaction_process(root):
            source = txn_roots[0] / TRANSACTION_CELL / "process.tsv"
            shutil.copyfile(source, root / TRANSACTION_CELL / "process.tsv")
            old, new = 3000, 2000
            for relative in ("transactions/cycles.jsonl", "transactions/lifecycle.json"):
                path = root / TRANSACTION_CELL / relative
                path.write_text(path.read_text().replace(f'"pid": {old}', f'"pid": {new}').replace(f'"starttime": {old + 100}', f'"starttime": {new + 100}'))
        txn_rejected("transaction-process-reuse", reuse_transaction_process, root_index=1)
        txn_rejected("transaction-file-tamper", lambda root: (root / TRANSACTION_CELL / "transactions/cycles.jsonl").write_text("tampered\n"), cell_reseal=False)
        txn_rejected("transaction-extra-file", lambda root: (root / TRANSACTION_CELL / "unexpected.txt").write_text("unexpected\n"))

        def rejected(
            name, mutate, reseal_after=True, freeze_after=True, cell_reseal=True
        ):
            copied = base / f"bad-{name}"
            shutil.copytree(base / "comparison-a", copied)
            thaw(copied)
            mutate(copied)
            if reseal_after:
                if cell_reseal:
                    reseal_cell_evidence(copied)
                reseal(copied)
            if freeze_after:
                freeze(copied)
            bad_roots = [copied, roots[1], roots[2], roots[3]]
            try:
                validate_campaigns(bad_roots, base / f"output-{name}")
            except InvalidReceipt:
                proofs[name] = True
                return
            fail(f"red fixture unexpectedly accepted: {name}")

        def alter_json(path, function):
            data = read_json(path); function(data); path.write_text(json.dumps(data))
        rejected("default-roster", lambda root: alter_json(root / "provenance.json", lambda data: data["inputs"].update({"cells": "bird"})))
        rejected("mixed-roster", lambda root: alter_json(root / "provenance.json", lambda data: data["inputs"].update({"cells": f"{','.join(COMPARISON_CELLS)},{GROUPED_CELL}"})))
        rejected("mode-flags", lambda root: alter_json(root / "rustbgpd-sighup/manifest.json", lambda data: data.update({"path_hiding": False})))
        rejected("topology-mutation", lambda root: alter_json(root / "rustbgpd-sighup/topology.json", lambda data: data.update({"first_reload_wall_us": 2_000_000})))
        rejected("barrier-marker", lambda root: (root / "rustbgpd-sighup/pre-churn/ack").write_text("stale\n"))
        rejected("final-barrier-marker", lambda root: (root / "bird/final-evidence/ack").write_text("stale\n"))
        rejected("dirty-commit", lambda root: alter_json(root / "provenance.json", lambda data: data["git"].update({"dirty": True})))
        rejected("origin-only", lambda root: alter_json(root / "provenance.json", lambda data: data["git"].update({"origin_main": "e" * 40})))
        rejected("head-matches-false", lambda root: alter_json(root / "provenance.json", lambda data: data["git"].update({"head_matches_origin_main": False})))
        rejected("mismatched-commit", lambda root: alter_json(root / "provenance.json", lambda data: data["git"].update({"commit": "d" * 40, "origin_main": "d" * 40})))
        rejected("commit-malformed", lambda root: alter_json(root / "provenance.json", lambda data: data["git"].update({"commit": "C" * 40, "origin_main": "C" * 40})))
        rejected("scripts-null", lambda root: alter_json(root / "provenance.json", lambda data: data.update({"scripts": None})))
        rejected("scripts-empty-map", lambda root: alter_json(root / "provenance.json", lambda data: data.update({"scripts": {}})))
        rejected("binary-malformed", lambda root: alter_json(root / "provenance.json", lambda data: data["binaries"].update({"rbgp": "not-a-digest"})))
        rejected("fingerprint-recompute", lambda root: alter_json(root / "provenance.json", lambda data: data["environment"].update({"docker": "changed"})))
        def change_input_and_rebind(root, key, value):
            alter_json(root / "provenance.json", lambda data: data["inputs"].update({key: value}))
            rebind_provenance(root)
        rejected("canonical-changed-fraction", lambda root: change_input_and_rebind(root, "changed_fraction", "0.2"))
        rejected("canonical-control-secs", lambda root: change_input_and_rebind(root, "control_secs", "31"))
        rejected("canonical-bird-threads", lambda root: change_input_and_rebind(root, "bird_threads", "7"))
        rejected("repeat-image-identity", lambda root: change_input_and_rebind(root, "bird_image_id", "sha256:" + "b" * 64))
        rejected("cell-root-provenance", lambda root: alter_json(root / "bird/provenance.json", lambda data: data["environment"].update({"docker": "cell-only"})))
        def overlap_next_root(root):
            alter_json(root / "COMPLETED", lambda data: data.update({"completed_at_epoch_ns": 20}))
        rejected("nonoverlap-order", overlap_next_root)
        rejected("quiet-spacing", lambda root: (root / "bird/quiet.tsv").write_text("sample\tepoch_s\tload1\n1\t1\t0.5\n2\t2\t0.5\n"))
        rejected("preflight-raw", lambda root: (root / "preflight.log").write_text("FAIL: fixture\n"))
        rejected("cell-status", lambda root: (root / "bird/status").write_text("fail stale\n"), cell_reseal=False)
        rejected("cell-provenance", lambda root: alter_json(root / "bird/provenance.json", lambda data: data["scenario"].update({"dataset_sha256": "b" * 64})))
        def break_evidence_roster(root):
            roster = root / "bird/evidence.sha256"
            roster.write_text("\n".join(roster.read_text().splitlines()[1:]) + "\n")
            status = root / "bird/status"
            fields = status.read_text().split()
            fields[4] = sha256(roster)
            status.write_text(" ".join(fields) + "\n")
        rejected("evidence-roster", break_evidence_roster, cell_reseal=False)
        def rebind_scenario_manifest(cdir):
            manifest_path = cdir / "manifest.json"
            scenario_path = cdir / "scenario.sha256"
            lines = [
                f"{sha256(manifest_path)}  ./manifest.json"
                if line.endswith("  ./manifest.json")
                else line
                for line in scenario_path.read_text().splitlines()
            ]
            scenario_path.write_text("\n".join(lines) + "\n")
            alter_json(
                cdir / "provenance.json",
                lambda data: data["scenario"].update(
                    {"manifest_sha256": sha256(scenario_path)}
                ),
            )
        def break_scenario_roster(root):
            cdir = root / "bird"
            manifest_path = cdir / "manifest.json"
            alter_json(manifest_path, lambda data: data["runtime_files"].append("extra.conf"))
            rebind_scenario_manifest(cdir)
        rejected("scenario-roster", break_scenario_roster)
        def break_scenario_duplicate(root):
            cdir = root / "bird"
            alter_json(cdir / "manifest.json", lambda data: data["runtime_files"].append("bird.conf"))
            rebind_scenario_manifest(cdir)
        rejected("scenario-duplicate", break_scenario_duplicate)
        def break_scenario_unsafe(root):
            cdir = root / "bird"
            alter_json(cdir / "manifest.json", lambda data: data["runtime_files"].__setitem__(0, "../bird.conf"))
            scenario_path = cdir / "scenario.sha256"
            lines = [
                line.replace("  ./bird.conf", "  ./../bird.conf")
                if line.endswith("  ./bird.conf")
                else line
                for line in scenario_path.read_text().splitlines()
            ]
            scenario_path.write_text("\n".join(lines) + "\n")
            rebind_scenario_manifest(cdir)
        rejected("scenario-unsafe-path", break_scenario_unsafe)
        rejected("scenario-retained-config", lambda root: (root / "rustbgpd-sighup/config.toml").write_text((root / "rustbgpd-sighup/config.toml").read_text() + "# drift\n"))
        rejected("cell-root-rows", lambda root: (root / "bird/rows.csv").write_text((root / "bird/rows.csv").read_text().replace(",1,1,1,", ",2,1,1,", 1)))
        rejected("reload-log-rows", lambda root: (root / "bird/reloadstall.log").write_text("reloadstall_csv,missing\n"))
        def break_percentile(root, start, values):
            root_rows_path = root / "rows.csv"
            with root_rows_path.open(newline="") as stream:
                all_rows = list(csv.reader(stream))
            header, data = all_rows[0], all_rows[1:]
            target = next(row for row in data if row[0] == "bird")
            target[start : start + 3] = values
            with root_rows_path.open("w", newline="") as stream:
                writer = csv.writer(stream, lineterminator="\n")
                writer.writerow(header)
                writer.writerows(data)
            bird_rows = [row for row in data if row[0] == "bird"]
            with (root / "bird/rows.csv").open("w", newline="") as stream:
                csv.writer(stream, lineterminator="\n").writerows(bird_rows)
            (root / "bird/reloadstall.log").write_text(
                "".join(
                    "reloadstall_csv," + ",".join(row[1:]) + "\n"
                    for row in bird_rows
                )
            )
        rejected("percentile-order", lambda root: break_percentile(root, 6, ["3", "2", "1"]))
        rejected("percentile-positive", lambda root: break_percentile(root, 15, ["0", "1", "2"]))
        rejected("first-generation-bound", lambda root: break_percentile(root, 15, ["1001", "1001", "1001"]))
        rejected("observer-gap-bound", lambda root: break_percentile(root, 9, ["2", "2", "2"]))
        def break_row_invariant(root):
            for relative in ("rows.csv", "bird/rows.csv", "bird/reloadstall.log"):
                path = root / relative
                path.write_text(path.read_text().replace(",320,320,0,183040,", ",320,319,0,183040,", 1))
        rejected("row-invariants", break_row_invariant)
        def break_row_sessions(root):
            for relative in ("rows.csv", "bird/rows.csv", "bird/reloadstall.log"):
                path = root / relative
                lines = path.read_text().splitlines()
                path.write_text(
                    "\n".join(
                        line.rsplit(",320,0", 1)[0] + ",319,0"
                        if line.startswith(("bird,", "reloadstall_csv,"))
                        else line
                        for line in lines
                    )
                    + "\n"
                )
        rejected("row-session-loss", break_row_sessions)
        rejected("rss-raw", lambda root: (root / "bird/rss.csv").write_text("epoch_s,total_rss_kib,pids\n1,0,1\n"))
        def break_top_checksum_only(root):
            daemon_log = root / "bird/daemon.log"
            daemon_log.write_text(daemon_log.read_text() + "semantically harmless line\n")
            reseal_cell_evidence(root)
        rejected("seal-checksum", break_top_checksum_only, reseal_after=False)
        rejected("exact-root-roster", lambda root: (root / "unexpected.txt").write_text("unexpected\n"))
        def replace_with_symlink(root):
            daemon_log = root / "bird/daemon.log"
            daemon_log.unlink()
            daemon_log.symlink_to("../preflight.log")
        rejected("symlink-anywhere", replace_with_symlink)
        rejected("writable-root", lambda root: None, freeze_after=False)
        comparison_campaigns = [validate_root(roots[0], "comparison"), validate_root(roots[3], "comparison")]
        escaped = [
            {**campaign, "rows": [row.copy() for row in campaign["rows"]]}
            for campaign in comparison_campaigns
        ]
        escaped[0]["rows"][0][0] = GROUPED_CELL
        original_audit = globals()["audit_combined"]
        globals()["audit_combined"] = lambda _path, _cells: None
        try:
            write_combined(base / "escaped-comparison.csv", escaped, COMPARISON_CELLS)
        except InvalidReceipt:
            proofs["grouped-output-isolation"] = True
        finally:
            globals()["audit_combined"] = original_audit
        corrupted_output = base / "corrupt-comparison.csv"
        shutil.copyfile(good_output / "comparison.csv", corrupted_output)
        corrupted_output.write_text(corrupted_output.read_text().replace("A,", "C,", 1))
        try:
            audit_combined(corrupted_output, COMPARISON_CELLS)
        except InvalidReceipt:
            proofs["output-exact-roster"] = True
        class AuditCalled(Exception):
            pass
        def audit_sentinel(_path, _cells):
            raise AuditCalled
        globals()["audit_combined"] = audit_sentinel
        try:
            write_combined(base / "audit-call.csv", comparison_campaigns, COMPARISON_CELLS)
        except AuditCalled:
            proofs["output-audit-call"] = True
        finally:
            globals()["audit_combined"] = original_audit
        # Separate roots cover ordering and cross-root identity reuse.
        reordered = [roots[0], roots[2], roots[1], roots[3]]
        try:
            validate_campaigns(reordered, base / "output-ordering")
        except InvalidReceipt:
            proofs["ordering"] = True
        reused = base / "reused"
        shutil.copytree(roots[1], reused); thaw(reused)
        shutil.copyfile(roots[2] / "rustbgpd-sighup-grouped-control/process.tsv", reused / "rustbgpd-sighup-grouped-control/process.tsv")
        reseal_cell_evidence(reused); reseal(reused); freeze(reused)
        try:
            validate_campaigns([roots[0], reused, roots[2], roots[3]], base / "output-reused")
        except InvalidReceipt:
            proofs["reused-identity"] = True
        def grouped_pair_drift(name, section, key, value):
            changed = []
            for suffix, source in zip(("a", "b"), roots[1:3], strict=True):
                copied = base / f"bad-{name}-{suffix}"
                shutil.copytree(source, copied)
                thaw(copied)
                alter_json(
                    copied / "provenance.json",
                    lambda data: data[section].update({key: value}),
                )
                rebind_provenance(copied)
                reseal_cell_evidence(copied)
                reseal(copied)
                freeze(copied)
                changed.append(copied)
            try:
                validate_campaigns(
                    [roots[0], *changed, roots[3]], base / f"output-{name}"
                )
            except InvalidReceipt:
                proofs[name] = True
        grouped_pair_drift("cross-role-environment", "environment", "cpu_model", "other-platform")
        grouped_pair_drift("cross-role-source-identity", "binaries", "rbgp", "a" * 64)
        expected = {"default-roster", "mixed-roster", "mode-flags", "topology-mutation", "barrier-marker", "final-barrier-marker", "live-topology-gauge", "route-gauge", "route-family", "one-scrape-drift", "add-path", "config-count", "dirty-commit", "origin-only", "head-matches-false", "mismatched-commit", "commit-malformed", "scripts-null", "scripts-empty-map", "binary-malformed", "fingerprint-recompute", "canonical-changed-fraction", "canonical-control-secs", "canonical-bird-threads", "repeat-image-identity", "cell-root-provenance", "nonoverlap-order", "quiet-spacing", "preflight-raw", "cell-status", "cell-provenance", "evidence-roster", "scenario-roster", "scenario-duplicate", "scenario-unsafe-path", "scenario-retained-config", "cell-root-rows", "reload-log-rows", "percentile-order", "percentile-positive", "first-generation-bound", "observer-gap-bound", "row-invariants", "rss-raw", "seal-checksum", "exact-root-roster", "symlink-anywhere", "writable-root", "grouped-output-isolation", "output-exact-roster", "output-audit-call", "ordering", "reused-identity", "cross-role-environment", "cross-role-source-identity"}
        expected |= {"current-down", "reestablished", "flapped", "counter-malformed", "establishment-roster", "flap-roster", "row-session-loss"}
        expected |= set("""v3-inspector-linkage v3-inspector-mode v3-inspector-target v3-inspector-canonical v3-inspector-field-order v3-inspector-nested-order v3-inspector-raw-utf8 transaction-cycle-roster transaction-plan-token transaction-confirm transaction-v3-pending transaction-v3-linkage transaction-v3-deadline transaction-v3-cleanup transaction-history transaction-abort transaction-timeout transaction-noop transaction-opposite
transaction-token-leak transaction-warning-log transaction-warning-binding transaction-applied-generation transaction-scenario-generation transaction-cross-root-generation transaction-port-gate transaction-disk-gate transaction-swap-gate transaction-fallback-shape
transaction-mixed-binary transaction-process-reuse transaction-file-tamper transaction-extra-file""".split())
        missing = expected - proofs.keys()
        if missing:
            fail(f"self-test proofs did not reject: {sorted(missing)}")
        for name in sorted(expected):
            print(f"red-proof {name}=pass")
        print("SELF_TEST pass")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    topology = subparsers.add_parser("topology")
    topology.add_argument("--mode", choices=("private", "grouped"), required=True)
    topology.add_argument("--peers", type=int, required=True)
    topology.add_argument("--total", type=int, required=True)
    topology.add_argument("--config", type=Path, required=True)
    topology.add_argument("--timestamps", type=Path, required=True)
    topology.add_argument("--output", type=Path, required=True)
    topology.add_argument("metrics", nargs=3, type=Path)
    campaigns = subparsers.add_parser("campaigns")
    campaigns.add_argument("--output-dir", required=True, type=Path)
    campaigns.add_argument("roots", nargs=4, type=Path)
    transactions = subparsers.add_parser("transactions")
    transactions.add_argument("--output-dir", required=True, type=Path)
    transactions.add_argument("roots", nargs=2, type=Path)
    inspect = subparsers.add_parser("inspect-v3")
    inspect.add_argument("--locator", required=True, type=Path)
    inspect.add_argument("--metadata", required=True, type=Path)
    inspect.add_argument("--raw", required=True, type=Path)
    inspect.add_argument("--config", required=True, type=Path)
    inspect.add_argument("--confirm-id", required=True)
    marker = subparsers.add_parser("inspect-generation")
    marker.add_argument("config", type=Path)
    subparsers.add_parser("self-test")
    args = parser.parse_args()
    try:
        if args.command == "topology":
            validate_topology(args.mode, args.peers, args.total, args.config, args.timestamps, args.metrics, args.output)
        elif args.command == "campaigns":
            validate_campaigns(args.roots, args.output_dir)
        elif args.command == "transactions":
            validate_transactions(args.roots, args.output_dir)
        elif args.command == "inspect-v3":
            print(
                json.dumps(
                    inspect_v3(
                        args.locator,
                        args.metadata,
                        args.raw,
                        args.config,
                        args.confirm_id,
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        elif args.command == "inspect-generation":
            print(generation_marker(args.config))
        else:
            self_test()
    except (InvalidReceipt, OSError, KeyError, TypeError, ValueError) as error:
        print(f"receipt invalid: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
