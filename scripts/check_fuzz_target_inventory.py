#!/usr/bin/env python3
"""Fail closed when the cargo-fuzz target inventory drifts."""

from __future__ import annotations

import argparse
import ast
import hashlib
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
    "crates/policy": ("compile_chain", "dataset_parse", "explain_walk", "rpol_compile"),
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
EXPECTED_COUNT = 21
WIRE_NIGHTLY_MAX_LENS = {
    "decode_bgpls": 4_096,
    "decode_evpn": 4_096,
    "decode_flowspec": 4_096,
    "decode_labeled": 4_096,
    "decode_message": 65_535,
    "decode_open": 4_077,
    "decode_route_refresh": 65_516,
    "decode_rtc": 4_096,
    "decode_update": 65_516,
    "decode_vpn": 4_096,
    "encode_evpn": 4_096,
    "parse_rd": 4_096,
}
WIRE_HOSTED_CONTRACTS = {
    "decode_message": (
        65_535,
        "decode_message(&mut buf, rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN)",
    ),
    "decode_open": (
        4_077,
        "if data.len()\n"
        "        > usize::from(rustbgpd_wire::MAX_MESSAGE_LEN)\n"
        "            - rustbgpd_wire::constants::HEADER_LEN\n"
        "    {\n"
        "        return;\n"
        "    }",
    ),
    "decode_route_refresh": (
        65_516,
        "if data.len()\n"
        "        > usize::from(rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN)\n"
        "            - rustbgpd_wire::constants::HEADER_LEN\n"
        "    {\n"
        "        return;\n"
        "    }",
    ),
    "decode_update": (
        65_516,
        "if data.len()\n"
        "        > usize::from(rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN)\n"
        "            - rustbgpd_wire::constants::HEADER_LEN\n"
        "    {\n"
        "        return;\n"
        "    }",
    ),
}
CAMPAIGN_BOUNDS: dict[str, tuple[str, int]] = {
    "crates/bfd": ("decode_bfd_control", 256),
    "crates/rpki": ("decode_rtr_pdu", 65_535),
}
WIRE_DICTIONARY_TARGETS = tuple(
    target for target in EXPECTED_TARGETS["crates/wire"] if target != "parse_rd"
)
EXPECTED_WIRE_DICTIONARY = b"""# BGP marker, message types, common path-attribute types, and AFI/SAFI tokens.
marker="\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff"
open="\\x01"
update="\\x02"
notification="\\x03"
keepalive="\\x04"
route_refresh="\\x05"
origin="\\x01"
as_path="\\x02"
next_hop="\\x03"
med="\\x04"
local_pref="\\x05"
community="\\x08"
mp_reach="\\x0e"
mp_unreach="\\x0f"
as4_path="\\x11"
large_community="\\x20"
afi_ipv4="\\x00\\x01"
afi_ipv6="\\x00\\x02"
safi_unicast="\\x01"
safi_labeled="\\x04"
safi_vpn="\\x80"
safi_evpn="\\x46"
"""
EXPECTED_WIRE_SEED_PATHS = (
    "crates/wire/fuzz/seeds/decode_bgpls/known_node",
    "crates/wire/fuzz/seeds/decode_evpn/imet_v4",
    "crates/wire/fuzz/seeds/decode_flowspec/ipv4_tcp_80",
    "crates/wire/fuzz/seeds/decode_labeled/announce_two_labels",
    "crates/wire/fuzz/seeds/decode_labeled/announce_v4",
    "crates/wire/fuzz/seeds/decode_labeled/withdraw_compat_v4",
    "crates/wire/fuzz/seeds/decode_message/keepalive",
    "crates/wire/fuzz/seeds/decode_open/open_caps",
    "crates/wire/fuzz/seeds/decode_route_refresh/borr",
    "crates/wire/fuzz/seeds/decode_route_refresh/extmsg-oversized-orf-roundtrip",
    "crates/wire/fuzz/seeds/decode_route_refresh/orf",
    "crates/wire/fuzz/seeds/decode_route_refresh/plain",
    "crates/wire/fuzz/seeds/decode_rtc/default",
    "crates/wire/fuzz/seeds/decode_rtc/full",
    "crates/wire/fuzz/seeds/decode_update/atomic_aggregate_with_aggregator",
    "crates/wire/fuzz/seeds/decode_update/malformed_next_hop_length",
    "crates/wire/fuzz/seeds/decode_vpn/vpnv4_single_label",
    "crates/wire/fuzz/seeds/encode_evpn/imet_v4_constructor",
    "crates/wire/fuzz/seeds/parse_rd/type0",
)
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
    # Generated from the public BGP-LS node constructor in bgpls.rs.
    "crates/wire/fuzz/seeds/decode_bgpls/known_node": bytes.fromhex(
        "0001001902000000000000002a010000040000fde80203000403000001"
    ),
    # Generated from the EVPN IMET round-trip fixture in evpn.rs.
    "crates/wire/fuzz/seeds/decode_evpn/imet_v4": bytes.fromhex(
        "03110000fde80000006400000064200a000001"
    ),
    # Generated from the IPv4 TCP/80 FlowSpec round-trip fixture in flowspec.rs.
    "crates/wire/fuzz/seeds/decode_flowspec/ipv4_tcp_80": bytes.fromhex(
        "0b01180a0000038106058150"
    ),
    # Canonical production KEEPALIVE encoding from keepalive.rs/message.rs.
    "crates/wire/fuzz/seeds/decode_message/keepalive": bytes.fromhex(
        "ffffffffffffffffffffffffffffffff001304"
    ),
    # Generated from the single-label VPNv4 round-trip fixture in vpn.rs.
    "crates/wire/fuzz/seeds/decode_vpn/vpnv4_single_label": bytes.fromhex(
        "70000c810000fde9000000640a0001"
    ),
    # Exact input grammar consumed by fuzz_targets/encode_evpn.rs for IMET.
    "crates/wire/fuzz/seeds/encode_evpn/imet_v4_constructor": bytes.fromhex(
        "030000fde80000006400000064010a000001"
    ),
    # Exact successful type-0 RD input from evpn.rs; deliberately no newline.
    "crates/wire/fuzz/seeds/parse_rd/type0": b"65000:100",
}
EXPECTED_SEED_SHA256 = {
    "crates/bfd/fuzz/seeds/decode_bfd_control/valid_down": "8d957e98d56df1f958c656f227080d6292b08650f28282a86efebc8c19f0ef1a",
    "crates/rpki/fuzz/seeds/decode_rtr_pdu/reset_query_v1": "3f33bec1b1e4e0e57201c2ff1b686e818650c8fc291d24d3076e571ae73b309c",
    "crates/wire/fuzz/seeds/decode_bgpls/known_node": "de440b029fb1601647c130a36a9deb92c1d9cf47d65541264baa1ec2d4ac3a18",
    "crates/wire/fuzz/seeds/decode_evpn/imet_v4": "02eaa7c86172f117702c97ae2bcdc9fe093a99309fd327d77941aa2c321ffb77",
    "crates/wire/fuzz/seeds/decode_flowspec/ipv4_tcp_80": "1cd834ffac49aca73ad096cdd34621e6678e05b7c16803db98a3002929629495",
    "crates/wire/fuzz/seeds/decode_labeled/announce_two_labels": "e798f0a78d309eb0bf8d92c71a629c7cf48c3dc8b8a05903fd5d481449ebdb5c",
    "crates/wire/fuzz/seeds/decode_labeled/announce_v4": "9c83a82a45560c32507bedd06f86a80eb745b4de18186b79e13c827c2e930474",
    "crates/wire/fuzz/seeds/decode_labeled/withdraw_compat_v4": "0e452a4cd801a768a575a49f269bf370a442e6c7e5aa731f69f87cd590d6dc84",
    "crates/wire/fuzz/seeds/decode_message/keepalive": "bdd86dabb355d0ba54dfad1043129ac6a1115749648beafce2b60163d828d46a",
    "crates/wire/fuzz/seeds/decode_open/open_caps": "4d7f31b821201e08e9d68cee39a61bc247b88f533c87a2d20a681793cd872b6f",
    "crates/wire/fuzz/seeds/decode_route_refresh/borr": "cbd95ae5ef8810691e3fc7efb7c39ef9ffb661135d858aa0ccc81fc74a0160ae",
    "crates/wire/fuzz/seeds/decode_route_refresh/extmsg-oversized-orf-roundtrip": "7bb0934aa79f55b57a63723edbaadd2f80f957f6285e7803d3840bf9858b5178",
    "crates/wire/fuzz/seeds/decode_route_refresh/orf": "02263e81c0556c1dbf0631dface945f40e0138eee76bb743e92038f78b3e4942",
    "crates/wire/fuzz/seeds/decode_route_refresh/plain": "76cc5805dab9b4eacefdb477f498020fd82bccdbc9c6a2d9ce10586ac85512b4",
    "crates/wire/fuzz/seeds/decode_rtc/default": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "crates/wire/fuzz/seeds/decode_rtc/full": "c4748e06a968344ffd94f7227f9f1ac8c5665ac3fd589d2e067775b892a5f19e",
    "crates/wire/fuzz/seeds/decode_update/atomic_aggregate_with_aggregator": "80c288de430d77b93eebaa32dafe70aca9f8419b7dd1b0f76980badafa6bf330",
    "crates/wire/fuzz/seeds/decode_update/malformed_next_hop_length": "2dba0dd0f3cfa2b63cb9406db9298b1bb6b0008419aa6591cf213b522263ff70",
    "crates/wire/fuzz/seeds/decode_vpn/vpnv4_single_label": "c0c5cea7a721e0e1e7348b62d5d079968beec6c739f72e2fd80c7ca0a2efec2b",
    "crates/wire/fuzz/seeds/encode_evpn/imet_v4_constructor": "46c8256c29f509d9aef3209750fcdf935cd0cbb2936692b65a5f85bf2897cf20",
    "crates/wire/fuzz/seeds/parse_rd/type0": "32d1dcb763d1b36497a4993e088047e25be3dedb9068ec718a531f397bd2372d",
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
    if (
        tuple(
            target for target in EXPECTED_TARGETS["crates/wire"] if target != "parse_rd"
        )
        != WIRE_DICTIONARY_TARGETS
    ):
        raise InventoryError("wire dictionary target roster differs from inventory")
    if (
        'if [ "$dir" = "crates/wire" ] && [ "$name" != "parse_rd" ]; then\n'
        '      cp "fuzz/bgp.dict" "$OUT/$name.dict"\n'
        "    fi" not in builder
    ):
        raise InventoryError("shared hosted builder wire dictionary enrollment differs")

    wire_block = re.search(
        r"(?ms)^      - name: [^\n]+\n        run: \|\n(?P<body>.*?cd crates/wire.*?)(?=^      - name:|\Z)",
        workflow,
    )
    if wire_block is None:
        raise InventoryError("nightly workflow has no crates/wire campaign")
    wire_body = wire_block.group("body")
    bound_rows = re.findall(
        r"(?m)^\s+(?P<target>[a-z][a-z0-9_]*)\) max_len=(?P<max_len>[0-9]+) ;;$",
        wire_body,
    )
    bound_targets = [target for target, _ in bound_rows]
    if len(bound_targets) != len(set(bound_targets)):
        raise InventoryError("nightly wire max_len dispatch has duplicate targets")
    actual_bounds = {target: int(max_len) for target, max_len in bound_rows}
    if actual_bounds != WIRE_NIGHTLY_MAX_LENS:
        raise InventoryError(
            "nightly wire target-specific max_len dispatch differs: "
            f"expected {WIRE_NIGHTLY_MAX_LENS}, got {actual_bounds}"
        )
    if 'case "$t" in' not in wire_body:
        raise InventoryError("nightly wire max_len dispatch has no case statement")
    if (
        '*) echo "wire fuzz target has no reviewed max_len: $t" >&2; exit 1 ;;'
        not in wire_body
    ):
        raise InventoryError("nightly wire max_len dispatch has no fail-closed default")
    if '-max_len="$max_len"' not in wire_body:
        raise InventoryError("nightly wire campaign does not use its selected max_len")
    if (
        "dict_args=()\n"
        '            [ "$t" != parse_rd ] && dict_args+=("-dict=fuzz/bgp.dict")'
        not in wire_body
        or '"${dict_args[@]}"' not in wire_body
    ):
        raise InventoryError("nightly wire dictionary enrollment differs")

    if tuple(sorted(WIRE_NIGHTLY_MAX_LENS)) != EXPECTED_TARGETS["crates/wire"]:
        raise InventoryError("nightly wire max_len map differs from target inventory")

    for target, (hosted_max_len, required_source) in WIRE_HOSTED_CONTRACTS.items():
        options = ROOT / "crates/wire/fuzz" / f"{target}.options"
        expected_options = f"[libfuzzer]\nmax_len = {hosted_max_len}\n"
        try:
            actual_options = options.read_text()
        except OSError as error:
            raise InventoryError(f"cannot read {options.relative_to(ROOT)}: {error}")
        if actual_options != expected_options:
            raise InventoryError(
                f"{options.relative_to(ROOT)} must set max_len = " f"{hosted_max_len}"
            )

        harness = ROOT / f"crates/wire/fuzz/fuzz_targets/{target}.rs"
        try:
            harness_text = harness.read_text()
        except OSError as error:
            raise InventoryError(f"cannot read {harness.relative_to(ROOT)}: {error}")
        if required_source not in harness_text:
            raise InventoryError(
                f"{harness.relative_to(ROOT)} must enforce its "
                "reviewed max_len contract"
            )

    for crate, (target, max_len) in CAMPAIGN_BOUNDS.items():
        crate_block = re.search(
            rf"(?ms)^      - name: [^\n]+\n        run: \|\n(?P<body>.*?cd {re.escape(crate)}.*?)(?=^      - name:|\Z)",
            workflow,
        )
        if crate_block is None:
            raise InventoryError(f"nightly workflow has no {crate} campaign")
        body = crate_block.group("body")
        if f"grep -Fxq {target}" not in body:
            raise InventoryError(f"nightly workflow does not require {crate}/{target}")
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


def _literal_assignment(source: str, name: str) -> object:
    try:
        module = ast.parse(source)
    except SyntaxError as error:
        raise InventoryError(f"corpus cache helper is not valid Python: {error}")
    for node in module.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            try:
                return ast.literal_eval(node.value)
            except (ValueError, TypeError) as error:
                raise InventoryError(
                    f"corpus cache helper {name} must be a literal"
                ) from error
    raise InventoryError(f"corpus cache helper is missing {name}")


def validate_wire_corpus_cache_contract(
    workflow: str, cache_helper: str, dictionary: bytes
) -> None:
    """Pin the bounded main-lineage cache and dictionary lifecycle."""
    if dictionary != EXPECTED_WIRE_DICTIONARY:
        raise InventoryError("wire BGP dictionary bytes differ")

    helper_contract = {
        "TARGET_MAX_LENS": WIRE_NIGHTLY_MAX_LENS,
        "MAX_BYTES": 16_777_216,
        "MAX_FILES": 20_000,
        "SCHEMA": 1,
        "MANIFEST": "manifest.json",
        "CORPUS": "corpus",
    }
    for name, expected in helper_contract.items():
        actual = _literal_assignment(cache_helper, name)
        if actual != expected:
            raise InventoryError(
                f"corpus cache helper {name} differs: expected {expected}, got {actual}"
            )

    required_fragments = {
        "non-cancelling concurrency": (
            "concurrency:\n  group: fuzz-wire-corpus-main\n  cancel-in-progress: false"
        ),
        "90-minute job timeout": "timeout-minutes: 90",
        "main writer guard": (
            "WIRE_CORPUS_WRITER: ${{ github.ref == 'refs/heads/main' && "
            "(github.event_name == 'schedule' || "
            "github.event_name == 'workflow_dispatch') }}"
        ),
        "temporary cache staging": (
            "WIRE_CACHE_BUNDLE: ${{ runner.temp }}/wire-corpus-cache"
        ),
        "standalone restore action": "uses: actions/cache/restore@v6",
        "standalone save action": "uses: actions/cache/save@v6",
        "reviewed cargo-fuzz": "cargo install cargo-fuzz --version 0.13.2 --locked",
        "main lineage key": "wire-fuzz-corpus-v1-main-",
        "unique run key": "${{ github.run_id }}-${{ github.run_attempt }}",
        "matched-key validation": (
            "RESTORE_MATCHED_KEY: "
            "${{ steps.wire-corpus-restore.outputs.cache-matched-key }}"
        ),
        "restore outcome handling": (
            "RESTORE_OUTCOME: ${{ steps.wire-corpus-restore.outcome }}"
        ),
        "matched-key receipt": (
            'echo "wire corpus cache matched key: $RESTORE_MATCHED_KEY"'
        ),
        "tracked-seed fallback": '--cache-hit "$cache_hit"',
        "post-install staging cleanup": 'rm -rf -- "$WIRE_CACHE_BUNDLE"',
        "post-run cap skip": 'if [ "$status" -eq 3 ]; then',
        "crash retention": "retention-days: 14",
    }
    for label, fragment in required_fragments.items():
        if fragment not in workflow:
            raise InventoryError(f"nightly wire corpus cache lacks {label}")
    if workflow.count("wire-fuzz-corpus-v1-main-") != 3:
        raise InventoryError("nightly wire corpus cache main lineage key count differs")
    if workflow.count("${{ github.run_id }}-${{ github.run_attempt }}") != 2:
        raise InventoryError("nightly wire corpus cache unique run key count differs")
    if "WIRE_SEALED_BUNDLE" in workflow:
        raise InventoryError("nightly wire corpus cache has distinct seal staging")

    restore_block = re.search(
        r"(?ms)^      - name: Restore bounded wire corpus cache\n(?P<body>.*?)(?=^      - name:)",
        workflow,
    )
    save_block = re.search(
        r"(?ms)^      - name: Save bounded wire corpus cache\n(?P<body>.*?)(?=^      - name:|\Z)",
        workflow,
    )
    if restore_block is None or "continue-on-error: true" not in restore_block.group(
        "body"
    ):
        raise InventoryError("cache restore outage is not an explicit fallback")
    if save_block is None or "continue-on-error: true" not in save_block.group("body"):
        raise InventoryError("cache save outage can fail the completed campaign")
    cache_path = "path: ${{ env.WIRE_CACHE_BUNDLE }}"
    if (
        cache_path not in restore_block.group("body")
        or cache_path not in save_block.group("body")
        or workflow.count(cache_path) != 2
    ):
        raise InventoryError("wire corpus cache action paths differ")

    ordered_steps = (
        "uses: actions/cache/restore@v6",
        "python3 scripts/fuzz_corpus_cache.py restore",
        'rm -rf -- "$WIRE_CACHE_BUNDLE"',
        "- name: Fuzz wire decoders",
        "python3 scripts/fuzz_corpus_cache.py seal",
        "uses: actions/cache/save@v6",
    )
    positions = [workflow.find(fragment) for fragment in ordered_steps]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise InventoryError(
            "wire corpus restore, campaign, seal, and save order differs"
        )


def validate_seed_corpus(seed_contents: Mapping[str, bytes]) -> None:
    """Pin the complete reviewed seed enrollment and byte identity."""
    errors: list[str] = []
    hashed_wire_paths = tuple(
        sorted(
            path
            for path in EXPECTED_SEED_SHA256
            if path.startswith("crates/wire/fuzz/seeds/")
        )
    )
    if hashed_wire_paths != EXPECTED_WIRE_SEED_PATHS:
        errors.append("wire seed path roster differs from its byte-digest roster")
    expected_paths = set(EXPECTED_SEED_SHA256)
    actual_paths = set(seed_contents)
    if actual_paths != expected_paths:
        errors.append(
            "tracked seed paths differ: "
            f"expected {sorted(expected_paths)}, got {sorted(actual_paths)}"
        )
    for path, expected in EXPECTED_SEEDS.items():
        actual = seed_contents.get(path)
        if actual is None:
            errors.append(f"missing pinned seed {path}")
        elif actual != expected:
            errors.append(f"pinned seed bytes differ: {path}")
    for path, expected_digest in EXPECTED_SEED_SHA256.items():
        actual = seed_contents.get(path)
        if actual is None:
            continue
        actual_digest = hashlib.sha256(actual).hexdigest()
        if actual_digest != expected_digest:
            errors.append(f"pinned seed digest differs: {path}")
    for path in EXPECTED_WIRE_SEED_PATHS:
        target = Path(path).parts[-2]
        actual = seed_contents.get(path)
        if actual is not None and len(actual) > WIRE_NIGHTLY_MAX_LENS[target]:
            errors.append(
                f"pinned seed exceeds {target} max_len: {path} has {len(actual)} bytes"
            )
    if errors:
        raise InventoryError("; ".join(errors))


def repository_seed_contents() -> dict[str, bytes]:
    seed_roots = {
        "crates/bfd/fuzz/seeds": {"decode_bfd_control"},
        "crates/rpki/fuzz/seeds": {"decode_rtr_pdu"},
        "crates/wire/fuzz/seeds": set(EXPECTED_TARGETS["crates/wire"]),
    }
    seed_contents: dict[str, bytes] = {}
    for relative_root, expected_targets in seed_roots.items():
        root = ROOT / relative_root
        try:
            entries = tuple(root.iterdir())
        except OSError as error:
            raise InventoryError(f"cannot enumerate {relative_root}: {error}")
        actual_targets = {entry.name for entry in entries}
        if actual_targets != expected_targets:
            raise InventoryError(
                f"{relative_root} target directories differ: "
                f"expected {sorted(expected_targets)}, got {sorted(actual_targets)}"
            )
        for target_dir in entries:
            if target_dir.is_symlink() or not target_dir.is_dir():
                raise InventoryError(
                    f"tracked seed target must be a real directory: "
                    f"{target_dir.relative_to(ROOT)}"
                )
            try:
                seeds = tuple(target_dir.iterdir())
            except OSError as error:
                raise InventoryError(
                    f"cannot enumerate {target_dir.relative_to(ROOT)}: {error}"
                )
            for seed in seeds:
                if seed.is_symlink() or not seed.is_file():
                    raise InventoryError(
                        f"tracked seed must be a regular file: {seed.relative_to(ROOT)}"
                    )
                path = seed.relative_to(ROOT).as_posix()
                try:
                    seed_contents[path] = seed.read_bytes()
                except OSError as error:
                    raise InventoryError(f"cannot read pinned seed {path}: {error}")
    return seed_contents


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
        cache_helper = (ROOT / "scripts/fuzz_corpus_cache.py").read_text()
        dictionary = (ROOT / "crates/wire/fuzz/bgp.dict").read_bytes()
    except OSError as error:
        raise InventoryError(f"cannot read fuzz pipeline configuration: {error}")
    validate_pipeline_enrollment(builder, workflow)
    validate_wire_corpus_cache_contract(workflow, cache_helper, dictionary)
    validate_seed_corpus(repository_seed_contents())
    return manifest_targets


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(f"Verify the exact {EXPECTED_COUNT}-target cargo-fuzz inventory.")
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
