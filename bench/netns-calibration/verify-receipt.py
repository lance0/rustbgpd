#!/usr/bin/env python3
"""Fail-closed verifier for pinned-kernel netns calibration VM receipts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")

EXPECTED: dict[str, Any] = {
    "host_tools": {
        "cloud_image_utils": {
            "deb_sha256": "c4203167b5f2ccc8d7e2ff66f6ed5bb55d1ce467511d27732b91e1389e15cd9e",
            "package": "cloud-image-utils",
            "path": "/usr/bin/cloud-localds",
            "version": "0.33-1",
        },
        "qemu_system_x86": {
            "deb_sha256": "14602e262627adac030329d2cecfee5f6c0938b34566ff2ea2d4c9a9eb02430d",
            "package": "qemu-system-x86",
            "path": "/usr/bin/qemu-system-x86_64",
            "version": "1:8.2.2+ds-0ubuntu1.18",
        },
    },
    "profiles": [
        {
            "guest": {
                "iproute2_package_version": "5.15.0-1ubuntu2.2",
                "kernel_package_version": "5.15.0-190.200",
                "kernel_release": "5.15.0-190-generic",
            },
            "name": "baseline-jammy-5.15",
            "role": "baseline",
            "source": {
                "sha256": "c0a5af17e6c0f76351fe07e2fffef3011dab1facb8a8ed5701dcf648dabd4f0a",
                "url": "https://cloud-images.ubuntu.com/releases/jammy/release-20260826/ubuntu-22.04-server-cloudimg-amd64.img",
            },
        },
        {
            "guest": {
                "iproute2_package_version": "6.1.0-1ubuntu6.4",
                "kernel_package_version": "6.8.0-138.138",
                "kernel_release": "6.8.0-138-generic",
            },
            "name": "current-noble-6.8",
            "role": "current",
            "source": {
                "sha256": "d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30",
                "url": "https://cloud-images.ubuntu.com/releases/noble/release-20260826/ubuntu-24.04-server-cloudimg-amd64.img",
            },
        },
    ],
    "raw_bridge_skew": {
        "active_limits": {"burst-32": 32, "burst-8": 8, "serial-1": 1},
        "censor_seconds": 5,
        "pairs_per_profile": 4000,
        "vm_timeout_seconds": 1500,
        "wall_seconds": 1200,
    },
    "schema": 1,
    "vm": {
        "machine": "pc-q35-8.2",
        "memory_mib": 2048,
        "timeout_seconds": 300,
        "vcpus": 2,
    },
}

RECEIPT_FILES = {
    "console.log": 2 * 1024 * 1024,
    "guest/guest.json": 64 * 1024,
    "guest/kernel.config": 2 * 1024 * 1024,
    "host.json": 64 * 1024,
    "plan.json": 64 * 1024,
    "quiet.tsv": 64 * 1024,
    "request.json": 64 * 1024,
}
SKEW_RECEIPT_FILES = {
    "guest/skew/report.json": 1024 * 1024,
    "guest/skew/run.json": 8 * 1024 * 1024,
    "guest/skew/samples.csv": 8 * 1024 * 1024,
}
QUIET_FIELDS = [
    "sample",
    "epoch_s",
    "load1",
    "pswpin",
    "pswpout",
    "governors",
    "performance_governors",
    "governor_count",
    "competitors",
    "quiet",
    "failed_dimensions",
    "original_attempt",
]
SOURCE_PATHS = {
    "guest": "bench/netns-calibration/guest-smoke.sh",
    "host_lock": "tests/soak/host-lock.sh",
    "host_quiet": "bench/scale/host-quiet.sh",
    "profiles": "bench/netns-calibration/profiles.json",
    "runner": "bench/netns-calibration/run-vm.sh",
    "verifier": "bench/netns-calibration/verify-receipt.py",
}
SKEW_SOURCE_PATH = "bench/netns-calibration/raw_bridge_skew.py"


class VerificationError(ValueError):
    """One closed receipt contract was violated."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def load_json(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"not a regular file: {path}")
    try:
        def reject_constant(value: str) -> None:
            raise VerificationError(f"non-finite JSON number: {value}")

        def reject_duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in items:
                require(key not in result, f"duplicate JSON key: {key}")
                result[key] = value
            return result

        value = json.loads(
            path.read_text(),
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicates,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot parse {path}: {exc}") from exc
    require(isinstance(value, dict), f"{path} must contain one JSON object")
    return value


def sha256(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f"not a regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_profiles(path: Path) -> dict[str, Any]:
    value = load_json(path)
    require(value == EXPECTED, "profile document is not the closed approved tuple")
    for profile in value["profiles"]:
        url = profile["source"]["url"]
        require("/release-20260826/" in url, f"profile uses a mutable URL: {url}")
        require("/current/" not in url and "/release/" not in url, f"profile uses a mutable URL: {url}")
        require(HEX_64.fullmatch(profile["source"]["sha256"]) is not None, "bad image SHA-256")
    return value


def selected_profile(profiles: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [item for item in profiles["profiles"] if item["name"] == name]
    require(len(matches) == 1, f"unknown or duplicate profile: {name}")
    return matches[0]


def expected_plan(
    profile: dict[str, Any], vm: dict[str, Any], host_tools: dict[str, Any]
) -> list[str]:
    return [
        host_tools["qemu_system_x86"]["path"],
        "-machine",
        f"{vm['machine']},accel=kvm",
        "-cpu",
        "host",
        "-smp",
        str(vm["vcpus"]),
        "-m",
        str(vm["memory_mib"]),
        "-name",
        f"rustbgpd-netns-calibration-{profile['name']}",
        "-display",
        "none",
        "-monitor",
        "none",
        "-no-reboot",
        "-nic",
        "none",
        "-snapshot",
        "-boot",
        "order=c,strict=on",
        "-drive",
        "file=<IMAGE>,format=qcow2,if=virtio",
        "-drive",
        "file=<SEED>,format=raw,media=cdrom,readonly=on",
        "-virtfs",
        "local,path=<PAYLOAD>,mount_tag=payload,security_model=none,readonly=on",
        "-virtfs",
        "local,path=<GUEST_OUT>,mount_tag=receipt,security_model=none",
        "-nographic",
    ]


def render_argv(
    profile: dict[str, Any],
    vm: dict[str, Any],
    host_tools: dict[str, Any],
    image: Path,
    seed: Path,
    payload: Path,
    guest_output: Path,
) -> list[str]:
    replacements = {
        "<IMAGE>": str(image),
        "<SEED>": str(seed),
        "<PAYLOAD>": str(payload),
        "<GUEST_OUT>": str(guest_output),
    }
    for label, value in replacements.items():
        require(value.startswith("/"), f"QEMU path is not absolute: {label}")
        require("\0" not in value and "\n" not in value, f"QEMU path is not one line: {label}")
    result = []
    for argument in expected_plan(profile, vm, host_tools):
        for label, value in replacements.items():
            argument = argument.replace(label, value)
        result.append(argument)
    require(not any("<" in argument or ">" in argument for argument in result), "QEMU placeholder remained")
    return result


def verify_plan(profiles_path: Path, plan_path: Path) -> None:
    profiles = verify_profiles(profiles_path)
    plan = load_json(plan_path)
    require(set(plan) == {"args", "profile", "schema"}, "plan has missing or extra fields")
    require(plan["schema"] == 1, "plan schema mismatch")
    profile = selected_profile(profiles, plan["profile"])
    require(
        plan["args"] == expected_plan(profile, profiles["vm"], profiles["host_tools"]),
        "QEMU plan is not exact",
    )
    joined = " ".join(plan["args"])
    require("-nic none" in joined, "QEMU plan does not disable networking")
    require("accel=kvm" in joined and "-cpu host" in joined, "QEMU plan is not KVM-only")
    require("-snapshot" in plan["args"], "QEMU plan can mutate its base image")
    require("readonly=on" in joined, "payload/seed read-only contract missing")
    for forbidden in ("-netdev", "-net user", "-nic user", "/home/", "<REPO>", "<HOME>"):
        require(forbidden not in joined, f"forbidden QEMU plan token: {forbidden}")


def verify_source_contract(repo: Path, runner: Path | None = None, guest: Path | None = None) -> None:
    runner = runner or repo / SOURCE_PATHS["runner"]
    guest = guest or repo / SOURCE_PATHS["guest"]
    runner_text = runner.read_text()
    guest_text = guest.read_text()
    skew_text = (repo / SKEW_SOURCE_PATH).read_text()
    anchors = [
        "if [ \"$EUID\" -eq 0 ]; then",
        "SCRIPT_DIR=$(cd --",
        "mapfile -t PROFILE_FIELDS",
        "mkdir -m 700 -- \"$OUTPUT\"",
        "trap cleanup EXIT",
        "acquire_rustbgpd_host_lock",
        "wait_for_rustbgpd_quiet_host",
        "python3 \"$VERIFIER\" argv",
        "TIMEOUT_SECONDS=300",
        "setsid timeout --signal=TERM",
        'verify_pinned_image_unchanged "pre-seal"',
        "python3 \"$VERIFIER\" receipt",
    ]
    positions = []
    for anchor in anchors:
        require(runner_text.count(anchor) == 1, f"runner source anchor is not unique: {anchor}")
        positions.append(runner_text.index(anchor))
    require(positions == sorted(positions), "runner cleanup/lock/quiet/QEMU/verify order changed")
    cleanup_start = runner_text.index("cleanup() {")
    cleanup_end = runner_text.index("\n}\ntrap cleanup EXIT", cleanup_start)
    cleanup = runner_text[cleanup_start:cleanup_end]
    cleanup_anchors = [
        'verify_pinned_image_unchanged "exit"',
        'if ! rm -rf -- "$TMP_DIR"; then',
        'if [ "$rc" -ne 0 ]; then',
        'rm -f -- "$OUTPUT/SHA256SUMS"',
        '[ -e "$OUTPUT/SHA256SUMS" ] || [ -L "$OUTPUT/SHA256SUMS" ]',
        'exit "$rc"',
    ]
    cleanup_positions = []
    for anchor in cleanup_anchors:
        require(cleanup.count(anchor) == 1, f"runner cleanup anchor changed: {anchor}")
        cleanup_positions.append(cleanup.index(anchor))
    require(
        cleanup_positions == sorted(cleanup_positions),
        "runner must recheck the image and clean staging before unsealing failures",
    )
    image_messages = [
        "pinned cloud image disappeared during the run",
        "pinned cloud image could not be hashed after the run",
        "pinned cloud image changed during the run",
    ]
    for message in image_messages:
        require(runner_text.count(message) == 1, f"runner image recheck changed: {message}")
    package_anchor = "/usr/bin/dpkg --verify qemu-system-x86 cloud-image-utils"
    require(runner_text.count(package_anchor) == 1, "host package verification changed")
    tool_anchors = [
        "QEMU_BIN=${PROFILE_FIELDS[2]}",
        "CLOUD_BIN=${PROFILE_FIELDS[3]}",
        "verify_dpkg_owned_tool qemu-system-x86 \"$QEMU_BIN\"",
        "verify_dpkg_owned_tool cloud-image-utils \"$CLOUD_BIN\"",
        "\"$CLOUD_BIN\" --network-config=",
        "\"${QEMU_COMMAND[@]}\" >\"$OUTPUT/console.log\"",
    ]
    for anchor in tool_anchors:
        require(runner_text.count(anchor) == 1, f"runner tool-path anchor changed: {anchor}")
    for forbidden in ("command -v qemu-system-x86_64", "command -v cloud-localds"):
        require(forbidden not in runner_text, f"runner resolves a pinned tool through PATH: {forbidden}")
    campaign_runner_anchors = [
        "CAMPAIGN=''",
        'if [ "$#" -eq 5 ] && [ "$1" = --raw-bridge-skew ]; then',
        'CAMPAIGN_TIMEOUT_SECONDS=$(python3 "$VERIFIER" skew-select "$PROFILES" "$CAMPAIGN")',
        'paths["raw_bridge_skew"] = "bench/netns-calibration/raw_bridge_skew.py"',
        'cp -- "$SKEW" "$PAYLOAD_DIR/"',
        'TIMEOUT_SECONDS=$CAMPAIGN_TIMEOUT_SECONDS',
    ]
    for anchor in campaign_runner_anchors:
        require(runner_text.count(anchor) == 1, f"runner campaign anchor changed: {anchor}")
    cleanup_anchor = 'ip netns del "$NETNS" >/dev/null 2>&1 || rc=1'
    require(guest_text.count(cleanup_anchor) == 1, "guest failure cleanup is not unique")
    guest_anchors = [
        "trap cleanup_guest EXIT",
        "ip netns add \"$NETNS\"",
        "ip netns delete \"$NETNS\"",
        "trap - EXIT",
    ]
    guest_positions = []
    for anchor in guest_anchors:
        require(guest_text.count(anchor) == 1, f"guest cleanup anchor is not unique: {anchor}")
        guest_positions.append(guest_text.index(anchor))
    require(guest_positions == sorted(guest_positions), "guest cleanup lifecycle changed")
    require(guest_text.index(cleanup_anchor) < guest_positions[0], "guest trap does not use the cleanup helper")
    campaign_guest_anchors = [
        'campaign=$(python3 -c',
        "python3 /mnt/payload/raw_bridge_skew.py",
        '--campaign "$campaign" --output "$output/skew"',
        "raw bridge skew campaign left netns residue",
    ]
    for anchor in campaign_guest_anchors:
        require(guest_text.count(anchor) == 1, f"guest campaign anchor changed: {anchor}")
    bootstrap_anchors = [
        "mount -t 9p -o trans=virtio,version=9p2000.L,ro payload",
        "mount -t 9p -o trans=virtio,version=9p2000.L receipt",
        "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "poweroff -f",
    ]
    bootstrap_positions = []
    for anchor in bootstrap_anchors:
        require(guest_text.count(anchor) == 1, f"guest staging anchor is not unique: {anchor}")
        bootstrap_positions.append(guest_text.index(anchor))
    require(bootstrap_positions == sorted(bootstrap_positions), "guest staging lifecycle changed")
    command = re.compile(r"^\s*(sudo|docker|curl|wget)\b", re.MULTILINE)
    require(command.search(runner_text) is None, "runner gained a forbidden host command")
    require(command.search(guest_text) is None, "guest gained a forbidden command")
    require(skew_text.count("self.socket.bind((0, RTMGRP_NEIGH))") == 1, "collector socket binding changed")
    for forbidden in ("bridge fdb add", "bridge fdb replace", "ip neigh add", "ip neigh replace"):
        require(forbidden not in skew_text, f"collector gained a synthetic measured stimulus: {forbidden}")


def verify_quiet(path: Path) -> None:
    with path.open(newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        require(reader.fieldnames == QUIET_FIELDS, "quiet receipt header mismatch")
        rows = list(reader)
    require(len(rows) == 2, "quiet receipt must retain exactly two samples")
    require([row.get("sample") for row in rows] == ["1", "2"], "quiet sample order mismatch")
    for row in rows:
        require(set(row) == set(QUIET_FIELDS), "quiet receipt row shape mismatch")
        require(row.get("quiet") == "true", "quiet receipt contains a failed sample")
        require(row.get("failed_dimensions") == "none", "quiet receipt contains a failed dimension")
        require(row.get("competitors") == "none", "quiet receipt contains a competing process")
        for field in ("epoch_s", "pswpin", "pswpout", "performance_governors", "governor_count", "original_attempt"):
            require(row[field].isdigit(), f"quiet receipt has a malformed integer: {field}")
        require(re.fullmatch(r"[0-9]+(?:[.][0-9]+)?", row["load1"]) is not None, "bad quiet load")
        require(float(row["load1"]) < 2.0, "quiet load threshold was not satisfied")
        require(int(row["governor_count"]) > 0, "quiet receipt has no CPU governors")
        require(
            int(row["performance_governors"]) == int(row["governor_count"]),
            "not every CPU used the performance governor",
        )
        governors = row["governors"].split(",")
        require(len(governors) == int(row["governor_count"]), "quiet governor inventory mismatch")
        require(set(governors) == {"performance"}, "quiet receipt used a non-performance governor")
    require(rows[0]["pswpin"] == rows[1]["pswpin"], "swap-in moved between quiet samples")
    require(rows[0]["pswpout"] == rows[1]["pswpout"], "swap-out moved between quiet samples")
    require(int(rows[1]["epoch_s"]) - int(rows[0]["epoch_s"]) >= 30, "quiet samples are too close")
    require(int(rows[0]["original_attempt"]) >= 1, "quiet attempt must be positive")
    require(
        int(rows[1]["original_attempt"]) > int(rows[0]["original_attempt"]),
        "quiet attempts are not ordered",
    )


def exact_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    require(set(value) == keys, f"{label} has missing or extra fields")


def same_typed_value(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            same_typed_value(actual[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            same_typed_value(left, right) for left, right in zip(actual, expected, strict=True)
        )
    return actual == expected


def verify_receipt(profiles_path: Path, root: Path, write_manifest: bool) -> None:
    profiles = verify_profiles(profiles_path)
    require(root.is_dir() and not root.is_symlink(), "receipt root must be a real directory")
    request = load_json(root / "request.json")
    campaign = request.get("raw_bridge_skew")
    if campaign is None:
        exact_keys(request, {"git", "image", "profile", "schema", "sources"}, "request")
        receipt_files = dict(RECEIPT_FILES)
        source_paths = dict(SOURCE_PATHS)
        allowed_directories = {"guest"}
    else:
        exact_keys(
            request,
            {"git", "image", "profile", "raw_bridge_skew", "schema", "sources"},
            "campaign request",
        )
        require(isinstance(campaign, dict), "raw bridge skew request must be an object")
        exact_keys(campaign, {"profile"}, "raw bridge skew request")
        require(
            campaign["profile"] in profiles["raw_bridge_skew"]["active_limits"],
            "unknown raw bridge skew profile",
        )
        receipt_files = {**RECEIPT_FILES, **SKEW_RECEIPT_FILES}
        source_paths = {**SOURCE_PATHS, "raw_bridge_skew": SKEW_SOURCE_PATH}
        allowed_directories = {"guest", "guest/skew"}
    found: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        require(not path.is_symlink(), f"receipt contains a symlink: {relative}")
        if path.is_dir():
            require(relative in allowed_directories, f"receipt contains an unexpected directory: {relative}")
            continue
        require(path.is_file(), f"receipt contains a non-regular path: {relative}")
        found.add(relative)
    allowed = set(receipt_files)
    if (root / "SHA256SUMS").exists():
        allowed.add("SHA256SUMS")
    require(found == allowed, f"receipt file set mismatch: got {sorted(found)}")
    for relative, limit in receipt_files.items():
        require((root / relative).stat().st_size <= limit, f"receipt artifact is oversized: {relative}")

    require(request["schema"] == 1, "request schema mismatch")
    profile = selected_profile(profiles, request["profile"])
    require(request["image"] == profile["source"], "request mixed or changed its image tuple")
    git = request["git"]
    exact_keys(git, {"commit", "dirty", "origin_main", "status_sha256"}, "request git")
    require(COMMIT.fullmatch(git["commit"]) is not None, "request commit is malformed")
    require(git["commit"] == git["origin_main"], "request commit is not exact origin/main")
    require(git["dirty"] is False and git["status_sha256"] == EMPTY_SHA256, "dirty source is not publishable")
    repo = Path(__file__).resolve().parents[2]
    require(set(request["sources"]) == set(source_paths), "request source inventory mismatch")
    for name, relative in source_paths.items():
        require(request["sources"][name] == sha256(repo / relative), f"source hash mismatch: {name}")

    plan = load_json(root / "plan.json")
    verify_plan(profiles_path, root / "plan.json")
    require(plan["profile"] == request["profile"], "plan/request profile mismatch")

    host = load_json(root / "host.json")
    exact_keys(
        host,
        {
            "cloud_image_utils",
            "cpu_model",
            "host_kernel",
            "kvm_access",
            "profile",
            "qemu_system_x86",
            "schema",
        },
        "host",
    )
    require(host["schema"] == 1 and host["profile"] == request["profile"], "host identity mismatch")
    require(host["kvm_access"] is True, "receipt was not produced with KVM access")
    require(isinstance(host["cpu_model"], str) and 0 < len(host["cpu_model"]) <= 160, "bad CPU model")
    require(isinstance(host["host_kernel"], str) and 0 < len(host["host_kernel"]) <= 256, "bad host kernel")
    for key in ("qemu_system_x86", "cloud_image_utils"):
        tool = host[key]
        keys = {
            "approved_deb_sha256",
            "binary_sha256",
            "dpkg_verified",
            "package",
            "package_version",
            "path",
        }
        if key == "qemu_system_x86":
            keys.add("version_output")
        exact_keys(tool, keys, key)
        require(
            {
                "deb_sha256": tool["approved_deb_sha256"],
                "package": tool["package"],
                "path": tool["path"],
                "version": tool["package_version"],
            }
            == profiles["host_tools"][key],
            f"{key} package tuple mismatch",
        )
        require(tool["dpkg_verified"] is True, f"{key} package files were not verified")
        require(HEX_64.fullmatch(tool["binary_sha256"]) is not None, f"bad {key} binary hash")
        if key == "qemu_system_x86":
            require(
                isinstance(tool["version_output"], str) and tool["version_output"],
                "missing QEMU version output",
            )

    verify_quiet(root / "quiet.tsv")
    guest = load_json(root / "guest/guest.json")
    exact_keys(
        guest,
        {
            "after_netns_sha256",
            "before_netns_sha256",
            "bridge_binary_sha256",
            "ip_binary_sha256",
            "ip_version_output",
            "iproute2_package_version",
            "kernel_config_sha256",
            "kernel_package_version",
            "kernel_release",
            "profile",
            "schema",
            "smoke",
            "status",
            "uid",
        },
        "guest",
    )
    expected_guest = profile["guest"]
    require(guest["schema"] == 1 and guest["status"] == "pass", "guest did not report success")
    require(guest["profile"] == request["profile"] and guest["uid"] == 0, "guest identity/privilege mismatch")
    for field in ("kernel_release", "kernel_package_version", "iproute2_package_version"):
        require(guest[field] == expected_guest[field], f"guest {field} mismatch")
    for field in ("before_netns_sha256", "after_netns_sha256", "ip_binary_sha256", "bridge_binary_sha256"):
        require(HEX_64.fullmatch(guest[field]) is not None, f"bad guest hash: {field}")
    require(guest["before_netns_sha256"] == guest["after_netns_sha256"], "guest left netns residue")
    require(guest["kernel_config_sha256"] == sha256(root / "guest/kernel.config"), "kernel config hash mismatch")
    require(
        guest["smoke"] == {
            "bridge_vlan_filtering": True,
            "deterministic_cleanup": True,
            "netns": True,
            "veth": True,
            "vlan_10": True,
            "vlan_20": True,
        },
        "guest smoke surface mismatch",
    )

    if campaign is not None:
        measured_profile = verify_skew_receipt(root / "guest/skew")
        require(
            measured_profile == campaign["profile"],
            "raw bridge skew request/result profile mismatch",
        )

    for relative in receipt_files:
        if relative.endswith((".csv", ".json", ".tsv", ".log")):
            text = (root / relative).read_text(errors="replace")
            for forbidden in ("/home/", "github_pat_", "ghp_", "GITHUB_TOKEN", "AWS_SECRET", "Authorization:"):
                require(forbidden not in text, f"unsanitized receipt content in {relative}")

    manifest_path = root / "SHA256SUMS"
    expected_manifest = "".join(
        f"{sha256(root / relative)}  {relative}\n" for relative in sorted(receipt_files)
    )
    if manifest_path.exists():
        require(manifest_path.is_file() and not manifest_path.is_symlink(), "bad SHA256SUMS path")
        require(manifest_path.read_text() == expected_manifest, "SHA256SUMS does not seal the exact receipt")
    elif write_manifest:
        manifest_path.write_text(expected_manifest)
    else:
        raise VerificationError("receipt has no SHA256SUMS (pass --write-manifest only at finalization)")


def verify_skew_receipt(root: Path) -> str:
    """Recompute a raw-bridge skew report from its closed plan and rows."""
    files = {"run.json", "samples.csv", "report.json"}
    require(root.is_dir() and not root.is_symlink(), "skew receipt root is not a real directory")
    require({path.name for path in root.iterdir()} == files, "skew receipt inventory mismatch")
    for name in files:
        path = root / name
        require(path.is_file() and not path.is_symlink(), f"bad skew artifact: {name}")
        require(path.stat().st_size <= 10 * 1024 * 1024, f"oversized skew artifact: {name}")
    require(sum((root / name).stat().st_size for name in files) <= 10 * 1024 * 1024, "skew artifacts exceed 10 MiB total")
    module_path = Path(__file__).with_name("raw_bridge_skew.py")
    spec = importlib.util.spec_from_file_location("raw_bridge_skew_verify", module_path)
    module = importlib.util.module_from_spec(spec)
    require(spec.loader is not None, "cannot load skew recomputer")
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    run = load_json(root / "run.json")
    require(
        set(run)
        == {
            "acceptance",
            "active_limit",
            "censor_seconds",
            "planned",
            "profile",
            "schema",
            "topology",
            "wall_seconds",
        },
        "run.json shape mismatch",
    )
    require(run["schema"] == 1 and run["profile"] in {"serial-1", "burst-8", "burst-32"}, "bad campaign identity")
    require(run["active_limit"] == {"serial-1": 1, "burst-8": 8, "burst-32": 32}[run["profile"]], "profile concurrency mismatch")
    require(run["active_limit"] <= 32 and run["censor_seconds"] == 5 and run["wall_seconds"] == 1200, "campaign bounds mismatch")
    require(run["acceptance"] is None, "campaign must remain descriptive without external acceptance inputs")
    topology = run["topology"]
    require(isinstance(topology, dict), "campaign topology must be an object")
    exact_keys(topology, {"bridge_ifindex", "port_ifindexes"}, "campaign topology")
    bridge_ifindex = topology["bridge_ifindex"]
    ports = topology["port_ifindexes"]
    require(type(bridge_ifindex) is int and bridge_ifindex > 0, "bad bridge ifindex")
    require(isinstance(ports, dict), "campaign port map must be an object")
    try:
        expected_run = module.deterministic_plan(run["profile"], bridge_ifindex, ports)
    except (RuntimeError, TypeError, ValueError, KeyError) as exc:
        raise VerificationError(f"invalid campaign topology: {exc}") from exc
    require(
        same_typed_value(run, expected_run),
        "run.json is not the exact closed deterministic plan",
    )
    planned = run["planned"]
    require(isinstance(planned, list) and len(planned) == 4000, "campaign denominator must be 4,000")
    expected_header = module.SAMPLE_FIELDS
    with (root / "samples.csv").open(newline="") as stream:
        reader = csv.DictReader(stream)
        require(reader.fieldnames == expected_header, "samples.csv header mismatch")
        samples = list(reader)
    require(len(samples) == 4000, "samples.csv denominator mismatch")
    require(
        [row["sample_id"] for row in samples] == [row["sample_id"] for row in planned],
        "samples do not exactly follow plan",
    )

    def decimal(value: str, label: str, *, signed: bool = False) -> int:
        pattern = r"-?(?:0|[1-9][0-9]*)" if signed else r"(?:0|[1-9][0-9]*)"
        require(re.fullmatch(pattern, value) is not None, f"bad sample integer: {label}")
        return int(value)

    rows = []
    for expected, sample in zip(planned, samples, strict=True):
        for field in ("sample_id", "profile", "phase"):
            require(sample[field] == str(expected[field]), f"sample metadata mismatch: {field}")
        require(
            decimal(sample["family"], "family") == expected["family"]
            and decimal(sample["vlan"], "vlan") == expected["vlan"],
            "sample family/VLAN mismatch",
        )
        complete = sample["complete"] == "true"
        require(sample["complete"] in {"true", "false"}, "bad complete value")
        neighbor = decimal(sample["neighbor_ns"], "neighbor_ns") if sample["neighbor_ns"] else None
        fdb = decimal(sample["fdb_ns"], "fdb_ns") if sample["fdb_ns"] else None
        skew = decimal(sample["skew_ns"], "skew_ns", signed=True) if sample["skew_ns"] else None
        require(complete == (neighbor is not None and fdb is not None), "complete row mismatch")
        require(skew == (neighbor - fdb if complete else None), "signed skew mismatch")
        missing_reason = (
            ""
            if complete
            else "missing-fdb-and-neighbor"
            if neighbor is None and fdb is None
            else "missing-neighbor"
            if neighbor is None
            else "missing-fdb"
        )
        require(sample["missing_reason"] == missing_reason, "missing reason mismatch")
        rows.append(
            {
                **expected,
                "complete": complete,
                "missing_reason": missing_reason,
                "neighbor_ns": neighbor,
                "fdb_ns": fdb,
                "skew_ns": skew,
                "duplicate_neighbor": decimal(sample["duplicate_neighbor"], "duplicate_neighbor"),
                "duplicate_fdb": decimal(sample["duplicate_fdb"], "duplicate_fdb"),
                "delete_events": decimal(sample["delete_events"], "delete_events"),
                "late_neighbor": decimal(sample["late_neighbor"], "late_neighbor"),
                "late_fdb": decimal(sample["late_fdb"], "late_fdb"),
                "late_delete": decimal(sample["late_delete"], "late_delete"),
            }
        )
    report = load_json(root / "report.json")
    require(
        report.get("wrong_tenant") == 0 and report.get("ambiguous_tenant") == 0,
        "wrong-tenant and ambiguity hard gates must be literal zero",
    )
    recomputed = module.build_report(rows, 4000, 0, 0, run["acceptance"])
    require(
        same_typed_value(report, recomputed),
        "report.json does not recompute from planned samples",
    )
    return run["profile"]


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    profiles_parser = sub.add_parser("profiles")
    profiles_parser.add_argument("profiles", type=Path)
    select_parser = sub.add_parser("select")
    select_parser.add_argument("profiles", type=Path)
    select_parser.add_argument("name")
    skew_select_parser = sub.add_parser("skew-select")
    skew_select_parser.add_argument("profiles", type=Path)
    skew_select_parser.add_argument("name")
    plan_parser = sub.add_parser("plan")
    plan_parser.add_argument("profiles", type=Path)
    plan_parser.add_argument("plan", type=Path)
    argv_parser = sub.add_parser("argv")
    argv_parser.add_argument("profiles", type=Path)
    argv_parser.add_argument("name")
    argv_parser.add_argument("image", type=Path)
    argv_parser.add_argument("seed", type=Path)
    argv_parser.add_argument("payload", type=Path)
    argv_parser.add_argument("guest_output", type=Path)
    source_parser = sub.add_parser("source")
    source_parser.add_argument("repo", type=Path)
    source_parser.add_argument("--runner", type=Path)
    source_parser.add_argument("--guest", type=Path)
    receipt_parser = sub.add_parser("receipt")
    receipt_parser.add_argument("profiles", type=Path)
    receipt_parser.add_argument("root", type=Path)
    receipt_parser.add_argument("--write-manifest", action="store_true")
    skew_parser = sub.add_parser("skew-receipt")
    skew_parser.add_argument("root", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "profiles":
            verify_profiles(args.profiles)
        elif args.command == "select":
            profiles = verify_profiles(args.profiles)
            profile = selected_profile(profiles, args.name)
            print(profile["source"]["sha256"])
            print(profile["source"]["url"])
            print(profiles["host_tools"]["qemu_system_x86"]["path"])
            print(profiles["host_tools"]["cloud_image_utils"]["path"])
        elif args.command == "skew-select":
            profiles = verify_profiles(args.profiles)
            require(
                args.name in profiles["raw_bridge_skew"]["active_limits"],
                f"unknown raw bridge skew profile: {args.name}",
            )
            print(profiles["raw_bridge_skew"]["vm_timeout_seconds"])
        elif args.command == "plan":
            verify_plan(args.profiles, args.plan)
        elif args.command == "argv":
            profiles = verify_profiles(args.profiles)
            profile = selected_profile(profiles, args.name)
            argv = render_argv(
                profile,
                profiles["vm"],
                profiles["host_tools"],
                args.image,
                args.seed,
                args.payload,
                args.guest_output,
            )
            sys.stdout.buffer.write(b"\0".join(item.encode() for item in argv) + b"\0")
        elif args.command == "source":
            verify_source_contract(args.repo.resolve(), args.runner, args.guest)
        elif args.command == "receipt":
            verify_receipt(args.profiles, args.root, args.write_manifest)
        else:
            verify_skew_receipt(args.root)
    except (OSError, VerificationError, ValueError, KeyError, TypeError) as exc:
        print(f"netns calibration receipt error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
