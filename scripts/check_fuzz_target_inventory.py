#!/usr/bin/env python3
"""Fail closed when the cargo-fuzz target inventory drifts."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TARGETS: dict[str, tuple[str, ...]] = {
    "crates/bfd": ("decode_bfd_control",),
    "crates/evpn": ("parse_rt",),
    "crates/mrt": ("snapshot_reader_drain", "warm_bundle_manifest"),
    "crates/policy": ("dataset_parse", "rpol_compile"),
    "crates/rpki": ("decode_rtr_pdu",),
    "crates/wire": (
        "decode_bgpls",
        "decode_evpn",
        "decode_flowspec",
        "decode_labeled",
        "decode_message",
        "decode_open",
        "decode_route_refresh",
        "decode_rtc",
        "decode_update",
        "decode_vpn",
        "encode_evpn",
        "parse_rd",
    ),
}
EXPECTED_COUNT = 19
CAMPAIGN_BOUNDS: dict[str, tuple[str, int]] = {
    "crates/bfd": ("decode_bfd_control", 256),
    "crates/rpki": ("decode_rtr_pdu", 65_535),
}
EXPECTED_SEEDS: dict[str, bytes] = {
    "crates/bfd/fuzz/seeds/decode_bfd_control/valid_down": bytes.fromhex(
        "204001180000000100000000000f4240000f424000000000"
    ),
    "crates/rpki/fuzz/seeds/decode_rtr_pdu/reset_query_v1": bytes.fromhex(
        "0102000000000008"
    ),
    "crates/wire/fuzz/seeds/decode_update/malformed_next_hop_length": bytes.fromhex(
        "00000006400303010203"
    ),
}


class InventoryError(RuntimeError):
    """The fuzz inventory could not be enumerated or did not match."""


def enumerate_manifest_targets(
    crate: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[str, ...]:
    manifest = ROOT / crate / "fuzz/Cargo.toml"
    try:
        result = runner(
            [
                "cargo",
                "metadata",
                "--format-version",
                "1",
                "--no-deps",
                "--manifest-path",
                str(manifest),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise InventoryError(f"cannot enumerate {manifest.relative_to(ROOT)}: {error}")

    if result.returncode != 0:
        detail = result.stderr.strip() or f"cargo metadata exited {result.returncode}"
        raise InventoryError(f"cannot enumerate {manifest.relative_to(ROOT)}: {detail}")

    try:
        metadata = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise InventoryError(
            f"cannot enumerate {manifest.relative_to(ROOT)}: invalid cargo metadata: "
            f"{error}"
        )

    targets: list[str] = []
    for package in metadata.get("packages", []):
        for target in package.get("targets", []):
            if "bin" not in target.get("kind", []):
                continue
            name = target["name"]
            expected_source = ROOT / crate / f"fuzz/fuzz_targets/{name}.rs"
            actual_source = Path(target.get("src_path", ""))
            if actual_source.resolve() != expected_source.resolve():
                raise InventoryError(
                    f"{manifest.relative_to(ROOT)} target {name} points to "
                    f"{actual_source}, expected {expected_source.relative_to(ROOT)}"
                )
            targets.append(name)
    targets.sort()
    if not targets:
        raise InventoryError(
            f"cannot enumerate {manifest.relative_to(ROOT)}: no binary targets"
        )
    if len(targets) != len(set(targets)):
        raise InventoryError(
            f"cannot enumerate {manifest.relative_to(ROOT)}: duplicate binary targets"
        )
    return tuple(targets)


def enumerate_source_targets(crate: str) -> tuple[str, ...]:
    source_dir = ROOT / crate / "fuzz/fuzz_targets"
    try:
        targets = tuple(sorted(path.stem for path in source_dir.glob("*.rs")))
    except OSError as error:
        raise InventoryError(
            f"cannot enumerate {source_dir.relative_to(ROOT)}: {error}"
        )
    if not targets:
        raise InventoryError(
            f"cannot enumerate {source_dir.relative_to(ROOT)}: no Rust targets"
        )
    return targets


def validate_inventory(
    manifest_targets: Mapping[str, Sequence[str]],
    source_targets: Mapping[str, Sequence[str]],
    discovered_crates: Sequence[str],
) -> None:
    expected_crates = tuple(sorted(EXPECTED_TARGETS))
    errors: list[str] = []

    if tuple(sorted(discovered_crates)) != expected_crates:
        errors.append(
            "fuzz crate set differs: "
            f"expected {list(expected_crates)}, got {sorted(discovered_crates)}"
        )

    for crate, expected in EXPECTED_TARGETS.items():
        manifest = tuple(sorted(manifest_targets.get(crate, ())))
        sources = tuple(sorted(source_targets.get(crate, ())))
        if manifest != expected:
            errors.append(
                f"{crate}/fuzz/Cargo.toml targets differ: "
                f"expected {list(expected)}, got {list(manifest)}"
            )
        if sources != expected:
            errors.append(
                f"{crate}/fuzz/fuzz_targets sources differ: "
                f"expected {list(expected)}, got {list(sources)}"
            )

    all_manifest_targets = [
        target
        for crate in expected_crates
        for target in manifest_targets.get(crate, ())
    ]
    if len(all_manifest_targets) != EXPECTED_COUNT:
        errors.append(
            f"expected exactly {EXPECTED_COUNT} manifest targets, "
            f"got {len(all_manifest_targets)}"
        )
    if len(all_manifest_targets) != len(set(all_manifest_targets)):
        errors.append("fuzz target names must be globally unique")

    if errors:
        raise InventoryError("; ".join(errors))


def validate_pipeline_enrollment(builder: str, workflow: str) -> None:
    """Keep newly inventoried crates on both hosted and nightly paths."""
    builder_roster = "for dir in " + " ".join(EXPECTED_TARGETS) + "; do"
    if builder_roster not in builder:
        raise InventoryError(
            "shared hosted builder fuzz-crate roster differs from the inventory"
        )

    if 'cp "fuzz/$name.options" "$OUT/$name.options"' not in builder:
        raise InventoryError("shared hosted builder does not copy target options")

    for crate, (target, max_len) in CAMPAIGN_BOUNDS.items():
        crate_block = re.search(
            rf"(?ms)^      - name: [^\n]+\n        run: \|\n(?P<body>.*?cd {re.escape(crate)}.*?)(?=^      - name:|\Z)",
            workflow,
        )
        if crate_block is None:
            raise InventoryError(f"nightly workflow has no {crate} campaign")
        body = crate_block.group("body")
        if f"grep -Fxq {target}" not in body:
            raise InventoryError(
                f"nightly workflow does not require {crate}/{target}"
            )
        if f"-max_len={max_len}" not in body:
            raise InventoryError(
                f"nightly workflow does not enforce {crate}/{target} max_len={max_len}"
            )
        if f"{crate}/fuzz/artifacts/" not in workflow:
            raise InventoryError(
                f"nightly workflow does not retain {crate} failure artifacts"
            )

        options = ROOT / crate / "fuzz" / f"{target}.options"
        expected_options = f"[libfuzzer]\nmax_len = {max_len}\n"
        try:
            actual_options = options.read_text()
        except OSError as error:
            raise InventoryError(f"cannot read {options.relative_to(ROOT)}: {error}")
        if actual_options != expected_options:
            raise InventoryError(
                f"{options.relative_to(ROOT)} must set max_len = {max_len}"
            )

        harness = ROOT / crate / f"fuzz/fuzz_targets/{target}.rs"
        try:
            harness_text = harness.read_text()
        except OSError as error:
            raise InventoryError(f"cannot read {harness.relative_to(ROOT)}: {error}")
        if f"data.len() > {max_len:_}" not in harness_text:
            raise InventoryError(
                f"{harness.relative_to(ROOT)} must reject inputs above {max_len} bytes"
            )


def validate_seed_corpus(seed_contents: Mapping[str, bytes]) -> None:
    """Pin the three small inputs that give the new coverage deterministic roots."""
    errors: list[str] = []
    for path, expected in EXPECTED_SEEDS.items():
        actual = seed_contents.get(path)
        if actual is None:
            errors.append(f"missing pinned seed {path}")
        elif actual != expected:
            errors.append(f"pinned seed bytes differ: {path}")
    if errors:
        raise InventoryError("; ".join(errors))


def repository_inventory() -> dict[str, tuple[str, ...]]:
    discovered = tuple(
        sorted(
            manifest.parent.parent.relative_to(ROOT).as_posix()
            for manifest in ROOT.glob("crates/*/fuzz/Cargo.toml")
        )
    )
    manifest_targets = {
        crate: enumerate_manifest_targets(crate) for crate in EXPECTED_TARGETS
    }
    source_targets = {
        crate: enumerate_source_targets(crate) for crate in EXPECTED_TARGETS
    }
    validate_inventory(manifest_targets, source_targets, discovered)
    try:
        builder = (ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (ROOT / ".github/workflows/fuzz.yml").read_text()
    except OSError as error:
        raise InventoryError(f"cannot read fuzz pipeline configuration: {error}")
    validate_pipeline_enrollment(builder, workflow)
    seed_contents: dict[str, bytes] = {}
    for path in EXPECTED_SEEDS:
        try:
            seed_contents[path] = (ROOT / path).read_bytes()
        except OSError as error:
            raise InventoryError(f"cannot read pinned seed {path}: {error}")
    validate_seed_corpus(seed_contents)
    return manifest_targets


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the exact 19-target cargo-fuzz inventory."
    )
    parser.add_argument(
        "--print-targets",
        action="store_true",
        help="print validated '<crate> <target>' rows for build scripts",
    )
    args = parser.parse_args()

    try:
        inventory = repository_inventory()
    except InventoryError as error:
        print(f"fuzz target inventory check failed: {error}", file=sys.stderr)
        return 1

    if args.print_targets:
        for crate in sorted(inventory):
            for target in inventory[crate]:
                print(crate, target)
    else:
        print(f"fuzz target inventory check passed: exactly {EXPECTED_COUNT} targets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
