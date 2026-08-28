#!/usr/bin/env python3
"""Mutation proofs for the fail-closed cargo-fuzz inventory gate."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_fuzz_target_inventory as inventory


def exact_inventory() -> dict[str, tuple[str, ...]]:
    return dict(inventory.EXPECTED_TARGETS)


class FuzzTargetInventoryTests(unittest.TestCase):
    def test_cli_help_uses_enforced_target_count(self) -> None:
        result = subprocess.run(
            [sys.executable, str(Path(inventory.__file__)), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            f"{inventory.EXPECTED_COUNT}-target cargo-fuzz inventory",
            result.stdout,
        )

    def test_repository_inventory_is_exact(self) -> None:
        actual = inventory.repository_inventory()
        self.assertEqual(actual, inventory.EXPECTED_TARGETS)
        self.assertEqual(
            sum(len(targets) for targets in actual.values()),
            inventory.EXPECTED_COUNT,
        )
        self.assertEqual(
            actual["crates/mrt"],
            ("snapshot_reader_drain", "warm_bundle_manifest"),
        )
        self.assertEqual(actual["crates/bfd"], ("decode_bfd_control",))
        self.assertEqual(actual["crates/rpki"], ("decode_rtr_pdu",))

    def test_every_single_manifest_target_omission_is_rejected(self) -> None:
        for crate, targets in inventory.EXPECTED_TARGETS.items():
            for omitted in targets:
                with self.subTest(crate=crate, omitted=omitted):
                    mutated = exact_inventory()
                    mutated[crate] = tuple(
                        target for target in targets if target != omitted
                    )
                    with self.assertRaisesRegex(
                        inventory.InventoryError, "targets differ"
                    ):
                        inventory.validate_inventory(
                            mutated,
                            inventory.EXPECTED_TARGETS,
                            tuple(inventory.EXPECTED_TARGETS),
                        )

    def test_every_single_source_target_omission_is_rejected(self) -> None:
        for crate, targets in inventory.EXPECTED_TARGETS.items():
            for omitted in targets:
                with self.subTest(crate=crate, omitted=omitted):
                    mutated = exact_inventory()
                    mutated[crate] = tuple(
                        target for target in targets if target != omitted
                    )
                    with self.assertRaisesRegex(
                        inventory.InventoryError, "sources differ"
                    ):
                        inventory.validate_inventory(
                            inventory.EXPECTED_TARGETS,
                            mutated,
                            tuple(inventory.EXPECTED_TARGETS),
                        )

    def test_unexpected_fuzz_crate_is_rejected(self) -> None:
        with self.assertRaisesRegex(inventory.InventoryError, "fuzz crate set differs"):
            inventory.validate_inventory(
                inventory.EXPECTED_TARGETS,
                inventory.EXPECTED_TARGETS,
                (*inventory.EXPECTED_TARGETS, "crates/injected"),
            )

    def test_duplicate_global_target_name_is_rejected(self) -> None:
        mutated = exact_inventory()
        wire_targets = list(mutated["crates/wire"])
        wire_targets[0] = "parse_rt"
        mutated["crates/wire"] = tuple(sorted(wire_targets))
        with mock.patch.object(inventory, "EXPECTED_TARGETS", mutated):
            with self.assertRaisesRegex(inventory.InventoryError, "globally unique"):
                inventory.validate_inventory(mutated, mutated, tuple(mutated))

    def test_empty_enumeration_is_rejected(self) -> None:
        def empty_runner(*args, **kwargs):
            del args, kwargs
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps({"packages": []}), stderr=""
            )

        with self.assertRaisesRegex(inventory.InventoryError, "no binary targets"):
            inventory.enumerate_manifest_targets("crates/mrt", runner=empty_runner)

    def test_failed_enumeration_is_rejected(self) -> None:
        def failed_runner(*args, **kwargs):
            del args, kwargs
            return subprocess.CompletedProcess(
                args=[], returncode=42, stdout="", stderr="injected metadata failure"
            )

        with self.assertRaisesRegex(
            inventory.InventoryError, "injected metadata failure"
        ):
            inventory.enumerate_manifest_targets("crates/mrt", runner=failed_runner)

    def test_redirected_manifest_target_is_rejected(self) -> None:
        def redirected_runner(*args, **kwargs):
            del args, kwargs
            target = (
                inventory.ROOT / "crates/mrt/fuzz/fuzz_targets/snapshot_reader_drain.rs"
            )
            metadata = {
                "packages": [
                    {
                        "targets": [
                            {
                                "name": "warm_bundle_manifest",
                                "kind": ["bin"],
                                "src_path": str(target),
                            }
                        ]
                    }
                ]
            }
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps(metadata), stderr=""
            )

        with self.assertRaisesRegex(inventory.InventoryError, "points to"):
            inventory.enumerate_manifest_targets("crates/mrt", runner=redirected_runner)

    def test_every_hosted_builder_crate_omission_is_rejected(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        for crate in inventory.EXPECTED_TARGETS:
            with self.subTest(crate=crate):
                mutated = builder.replace(f" {crate}", "", 1)
                with self.assertRaisesRegex(
                    inventory.InventoryError, "builder fuzz-crate roster"
                ):
                    inventory.validate_pipeline_enrollment(mutated, workflow)

    def test_hosted_options_copy_omission_is_rejected(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        mutated = builder.replace(
            'cp "fuzz/$name.options" "$OUT/$name.options"', "cp omitted", 1
        )
        with self.assertRaisesRegex(inventory.InventoryError, "target options"):
            inventory.validate_pipeline_enrollment(mutated, workflow)

    def test_wire_dictionary_enrollment_is_exact_on_both_build_paths(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        self.assertEqual(
            inventory.WIRE_DICTIONARY_TARGETS,
            tuple(
                target
                for target in inventory.EXPECTED_TARGETS["crates/wire"]
                if target != "parse_rd"
            ),
        )
        mutations = (
            (
                builder.replace(
                    'cp "fuzz/bgp.dict" "$OUT/$name.dict"', "cp omitted", 1
                ),
                workflow,
                "hosted",
            ),
            (
                builder,
                workflow.replace(
                    '[ "$t" != parse_rd ] && dict_args+=("-dict=fuzz/bgp.dict")',
                    "dict_args=()",
                    1,
                ),
                "nightly",
            ),
        )
        for changed_builder, changed_workflow, path in mutations:
            with self.subTest(path=path), self.assertRaisesRegex(
                inventory.InventoryError, "dictionary enrollment"
            ):
                inventory.validate_pipeline_enrollment(
                    changed_builder, changed_workflow
                )

    def test_wire_nightly_target_specific_bound_drift_is_rejected(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        for target, max_len in inventory.WIRE_NIGHTLY_MAX_LENS.items():
            with self.subTest(target=target, mutation="changed"):
                mutated = workflow.replace(
                    f"{target}) max_len={max_len} ;;",
                    f"{target}) max_len={max_len + 1} ;;",
                    1,
                )
                with self.assertRaisesRegex(
                    inventory.InventoryError, "target-specific max_len"
                ):
                    inventory.validate_pipeline_enrollment(builder, mutated)

            with self.subTest(target=target, mutation="omitted"):
                mutated = workflow.replace(
                    f"              {target}) max_len={max_len} ;;\n", "", 1
                )
                with self.assertRaisesRegex(
                    inventory.InventoryError, "target-specific max_len"
                ):
                    inventory.validate_pipeline_enrollment(builder, mutated)

    def test_wire_nightly_bound_dispatch_is_fail_closed(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        mutations = (
            (
                'case "$t" in',
                'case "$omitted" in',
                "case statement",
            ),
            (
                '*) echo "wire fuzz target has no reviewed max_len: $t" >&2; exit 1 ;;',
                "*) max_len=4096 ;;",
                "fail-closed default",
            ),
            (
                '-max_len="$max_len"',
                "-max_len=4096",
                "selected max_len",
            ),
        )
        for old, new, error in mutations:
            with self.subTest(error=error):
                mutated = workflow.replace(old, new, 1)
                with self.assertRaisesRegex(inventory.InventoryError, error):
                    inventory.validate_pipeline_enrollment(builder, mutated)

    def test_wire_extended_message_target_options_are_load_bearing(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        read_text = Path.read_text

        for target, (hosted_max_len, _) in inventory.WIRE_HOSTED_CONTRACTS.items():
            options = inventory.ROOT / "crates/wire/fuzz" / f"{target}.options"

            def changed_options(path, *args, **kwargs):
                if path == options:
                    return f"[libfuzzer]\nmax_len = {hosted_max_len - 1}\n"
                return read_text(path, *args, **kwargs)

            with self.subTest(target=target):
                with mock.patch.object(Path, "read_text", changed_options):
                    with self.assertRaisesRegex(inventory.InventoryError, "must set"):
                        inventory.validate_pipeline_enrollment(builder, workflow)

    def test_wire_hosted_harness_limits_are_load_bearing(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        read_text = Path.read_text

        for target, (_, required_source) in inventory.WIRE_HOSTED_CONTRACTS.items():
            harness = inventory.ROOT / f"crates/wire/fuzz/fuzz_targets/{target}.rs"

            def removed_hosted_limit(path, *args, **kwargs):
                text = read_text(path, *args, **kwargs)
                if path == harness:
                    return text.replace(
                        required_source, "/* reviewed bound omitted */", 1
                    )
                return text

            with self.subTest(target=target):
                with mock.patch.object(Path, "read_text", removed_hosted_limit):
                    with self.assertRaisesRegex(
                        inventory.InventoryError, "reviewed max_len contract"
                    ):
                        inventory.validate_pipeline_enrollment(builder, workflow)

    def test_body_decoder_full_guard_is_load_bearing(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        read_text = Path.read_text
        mutations = (
            ("            - rustbgpd_wire::constants::HEADER_LEN\n", ""),
            ("rustbgpd_wire::constants::HEADER_LEN", "19"),
        )

        for target in ("decode_open", "decode_route_refresh", "decode_update"):
            harness = inventory.ROOT / f"crates/wire/fuzz/fuzz_targets/{target}.rs"
            for old, new in mutations:

                def changed_guard(path, *args, **kwargs):
                    text = read_text(path, *args, **kwargs)
                    if path == harness:
                        return text.replace(old, new, 1)
                    return text

                with self.subTest(target=target, replacement=new or "removed"):
                    with mock.patch.object(Path, "read_text", changed_guard):
                        with self.assertRaisesRegex(
                            inventory.InventoryError, "reviewed max_len contract"
                        ):
                            inventory.validate_pipeline_enrollment(builder, workflow)

    def test_new_nightly_campaign_omission_is_rejected(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        for crate, (target, _) in inventory.CAMPAIGN_BOUNDS.items():
            with self.subTest(crate=crate):
                mutated = workflow.replace(
                    f"grep -Fxq {target}", "grep -Fxq omitted", 1
                )
                with self.assertRaisesRegex(
                    inventory.InventoryError, "does not require"
                ):
                    inventory.validate_pipeline_enrollment(builder, mutated)

    def test_new_campaign_bound_drift_is_rejected(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        for crate, (_, max_len) in inventory.CAMPAIGN_BOUNDS.items():
            with self.subTest(crate=crate):
                mutated = workflow.replace(
                    f"-max_len={max_len}", f"-max_len={max_len + 1}", 1
                )
                with self.assertRaisesRegex(inventory.InventoryError, "max_len"):
                    inventory.validate_pipeline_enrollment(builder, mutated)

    def test_new_campaign_artifact_omission_is_rejected(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        for crate in inventory.CAMPAIGN_BOUNDS:
            with self.subTest(crate=crate):
                mutated = workflow.replace(f"{crate}/fuzz/artifacts/", "omitted/", 1)
                with self.assertRaisesRegex(
                    inventory.InventoryError, "failure artifacts"
                ):
                    inventory.validate_pipeline_enrollment(builder, mutated)

    def test_new_campaign_options_and_harness_bounds_are_load_bearing(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        read_text = Path.read_text

        for crate, (target, max_len) in inventory.CAMPAIGN_BOUNDS.items():
            options = inventory.ROOT / crate / "fuzz" / f"{target}.options"
            harness = inventory.ROOT / crate / f"fuzz/fuzz_targets/{target}.rs"

            def changed_options(path, *args, **kwargs):
                if path == options:
                    return f"[libfuzzer]\nmax_len = {max_len + 1}\n"
                return read_text(path, *args, **kwargs)

            with self.subTest(crate=crate, guard="hosted-options"):
                with mock.patch.object(Path, "read_text", changed_options):
                    with self.assertRaisesRegex(inventory.InventoryError, "must set"):
                        inventory.validate_pipeline_enrollment(builder, workflow)

            def removed_harness_guard(path, *args, **kwargs):
                text = read_text(path, *args, **kwargs)
                if path == harness:
                    return text.replace(f"data.len() > {max_len:_}", "false", 1)
                return text

            with self.subTest(crate=crate, guard="harness-bound"):
                with mock.patch.object(Path, "read_text", removed_harness_guard):
                    with self.assertRaisesRegex(
                        inventory.InventoryError, "must reject"
                    ):
                        inventory.validate_pipeline_enrollment(builder, workflow)

    def test_every_pinned_seed_omission_and_byte_change_is_rejected(self) -> None:
        contents = inventory.repository_seed_contents()
        self.assertEqual(set(contents), set(inventory.EXPECTED_SEED_SHA256))
        self.assertEqual(
            tuple(
                sorted(
                    path
                    for path in contents
                    if path.startswith("crates/wire/fuzz/seeds/")
                )
            ),
            inventory.EXPECTED_WIRE_SEED_PATHS,
        )
        self.assertEqual(
            {Path(path).parts[-2] for path in inventory.EXPECTED_WIRE_SEED_PATHS},
            set(inventory.EXPECTED_TARGETS["crates/wire"]),
        )
        for path, expected in contents.items():
            with self.subTest(path=path, mutation="omitted"):
                mutated = dict(contents)
                del mutated[path]
                with self.assertRaisesRegex(
                    inventory.InventoryError, "tracked seed paths differ"
                ):
                    inventory.validate_seed_corpus(mutated)
            with self.subTest(path=path, mutation="changed"):
                mutated = dict(contents)
                mutated[path] = expected + b"changed"
                with self.assertRaisesRegex(
                    inventory.InventoryError, "bytes differ|digest differs"
                ):
                    inventory.validate_seed_corpus(mutated)

    def test_unexpected_tracked_seed_is_rejected(self) -> None:
        mutated = inventory.repository_seed_contents()
        mutated["crates/wire/fuzz/seeds/decode_message/unreviewed"] = b"extra"
        with self.assertRaisesRegex(
            inventory.InventoryError, "tracked seed paths differ"
        ):
            inventory.validate_seed_corpus(mutated)

    def test_wire_dictionary_bytes_and_cache_helper_contract_are_load_bearing(
        self,
    ) -> None:
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        helper = (inventory.ROOT / "scripts/fuzz_corpus_cache.py").read_text()
        dictionary = (inventory.ROOT / "crates/wire/fuzz/bgp.dict").read_bytes()
        inventory.validate_wire_corpus_cache_contract(workflow, helper, dictionary)

        with self.assertRaisesRegex(inventory.InventoryError, "dictionary bytes"):
            inventory.validate_wire_corpus_cache_contract(
                workflow, helper, dictionary + b"changed"
            )

        for name, old, new in (
            ("file cap", "MAX_FILES = 20_000", "MAX_FILES = 20_001"),
            ("byte cap", "MAX_BYTES = 16_777_216", "MAX_BYTES = 16_777_217"),
            ("schema", "SCHEMA = 1", "SCHEMA = 2"),
            ("target map", '"decode_bgpls": 4_096', '"decode_bgpls": 4_095'),
        ):
            with self.subTest(contract=name), self.assertRaisesRegex(
                inventory.InventoryError, "corpus cache helper"
            ):
                inventory.validate_wire_corpus_cache_contract(
                    workflow, helper.replace(old, new, 1), dictionary
                )

    def test_wire_cache_workflow_mutations_are_rejected(self) -> None:
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        helper = (inventory.ROOT / "scripts/fuzz_corpus_cache.py").read_text()
        dictionary = (inventory.ROOT / "crates/wire/fuzz/bgp.dict").read_bytes()
        mutations = (
            ("main guard", "github.ref == 'refs/heads/main'", "true"),
            ("restore action", "actions/cache/restore@v6", "actions/cache/restore@v5"),
            ("save action", "actions/cache/save@v6", "actions/cache/save@v5"),
            (
                "cargo-fuzz version",
                "cargo install cargo-fuzz --version 0.13.2 --locked",
                "cargo install cargo-fuzz --locked",
            ),
            (
                "staging",
                "${{ runner.temp }}/wire-corpus-cache",
                "crates/wire/fuzz/corpus",
            ),
            ("file lineage", "wire-fuzz-corpus-v1-main-", "wire-corpus-"),
            ("run key", "${{ github.run_id }}-${{ github.run_attempt }}", "static"),
            (
                "matched-key receipt",
                'echo "wire corpus cache matched key: $RESTORE_MATCHED_KEY"',
                "echo cache-hit",
            ),
            ("manifest validation", '--cache-hit "$cache_hit"', "--cache-hit false"),
            ("timeout", "timeout-minutes: 90", "timeout-minutes: 0"),
            ("retention", "retention-days: 14", "retention-days: 90"),
            (
                "post-install cleanup",
                'rm -rf -- "$WIRE_CACHE_BUNDLE"',
                "true # staging cleanup removed",
            ),
        )
        for name, old, new in mutations:
            with self.subTest(contract=name), self.assertRaisesRegex(
                inventory.InventoryError, "wire corpus cache"
            ):
                inventory.validate_wire_corpus_cache_contract(
                    workflow.replace(old, new, 1), helper, dictionary
                )

    def test_wire_cache_outage_and_step_order_are_load_bearing(self) -> None:
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        helper = (inventory.ROOT / "scripts/fuzz_corpus_cache.py").read_text()
        dictionary = (inventory.ROOT / "crates/wire/fuzz/bgp.dict").read_bytes()
        restore_start = workflow.index("- name: Restore bounded wire corpus cache")
        restore_continue = workflow.index("continue-on-error: true", restore_start)
        save_start = workflow.index("- name: Save bounded wire corpus cache")
        save_continue = workflow.index("continue-on-error: true", save_start)
        cache_path = "path: ${{ runner.temp }}/wire-corpus-cache"
        save_path = workflow.index(cache_path, save_start)
        for name, position in (
            ("restore", restore_continue),
            ("save", save_continue),
        ):
            mutated = (
                workflow[:position]
                + "continue-on-error: false"
                + workflow[position + len("continue-on-error: true") :]
            )
            with self.subTest(path=name), self.assertRaisesRegex(
                inventory.InventoryError, "outage"
            ):
                inventory.validate_wire_corpus_cache_contract(
                    mutated, helper, dictionary
                )

        distinct_save_path = (
            workflow[:save_path]
            + "path: ${{ runner.temp }}/wire-corpus-save"
            + workflow[save_path + len(cache_path) :]
        )
        with self.assertRaisesRegex(inventory.InventoryError, "action paths differ"):
            inventory.validate_wire_corpus_cache_contract(
                distinct_save_path, helper, dictionary
            )

        steps = workflow.index("    steps:\n")
        invalid_job_env = (
            workflow[:steps]
            + "      WIRE_CACHE_BUNDLE: ${{ runner.temp }}/wire-corpus-cache\n"
            + workflow[steps:]
        )
        with self.assertRaisesRegex(
            inventory.InventoryError, "runner context in job env"
        ):
            inventory.validate_wire_corpus_cache_contract(
                invalid_job_env, helper, dictionary
            )

        missing_steps = workflow.replace("    steps:\n", "    workflow-steps:\n", 1)
        with self.assertRaisesRegex(inventory.InventoryError, "lacks steps marker"):
            inventory.validate_wire_corpus_cache_contract(
                missing_steps, helper, dictionary
            )

        reordered = workflow.replace(
            "python3 scripts/fuzz_corpus_cache.py seal",
            "python3 scripts/fuzz_corpus_cache.py restore",
            1,
        )
        with self.assertRaisesRegex(inventory.InventoryError, "order differs"):
            inventory.validate_wire_corpus_cache_contract(reordered, helper, dictionary)


if __name__ == "__main__":
    unittest.main()
