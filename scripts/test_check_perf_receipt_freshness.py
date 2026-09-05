#!/usr/bin/env python3
"""Destructive proofs for the performance-receipt integrity contract."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_perf_receipt_freshness as checker


ROOT = checker.ROOT
MANIFEST_TEXT = checker.MANIFEST.read_text(encoding="utf-8")
MANIFEST = checker.parse_manifest(MANIFEST_TEXT)


def receipt_item(manifest: dict[str, object], path: str) -> dict[str, str]:
    return next(item for item in manifest["receipts"] if item["path"] == path)


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class TemporaryReceiptRepository:
    """A deterministic release graph independent of the developer checkout."""

    receipt = "docs/perf/fixture-receipt.md"
    measured_on = "2026-01-02"

    def __enter__(self) -> TemporaryReceiptRepository:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.commit_number = 0
        self.run("init", "-q", "-b", "main")
        self.run("config", "user.name", "Receipt Contract Test")
        self.run("config", "user.email", "receipt-contract@example.invalid")
        self.run("config", "commit.gpgsign", "false")

        (self.root / "graph.txt").write_text("common base\n", encoding="utf-8")
        self.common_commit = self.commit("common base")

        self.run("checkout", "-q", "-b", "measurement")
        (self.root / "measurement.txt").write_text("off-main measurement\n", encoding="utf-8")
        self.measured_commit = self.commit("measure receipt")
        self.receipt_tag = "receipt/fixture-2026-01"
        self.run("tag", self.receipt_tag, self.measured_commit)

        self.run("checkout", "-q", "main")
        (self.root / "landed.txt").write_text("landed implementation\n", encoding="utf-8")
        self.release_commit = self.commit("land implementation")
        self.run("tag", "v0.1.0", self.release_commit)

        self.write_contract_files()
        self.commit("add front-door receipt contract")
        self.run("tag", "v0.2.0")
        self.commit("release 0.3.0", allow_empty=True)
        self.run("tag", "v0.3.0")
        self.commit("release 0.4.0", allow_empty=True)
        self.run("tag", "v0.4.0")
        self.manifest = checker.parse_manifest(
            (self.root / "docs/perf/receipt-provenance.json").read_text(encoding="utf-8")
        )
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.temporary.cleanup()

    def git_environment(self, **overrides: str) -> dict[str, str]:
        environment = {
            **os.environ,
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": str(self.root / ".disabled-hooks"),
        }
        environment.update(overrides)
        return environment

    def run(
        self,
        *arguments: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ("git", *arguments),
            cwd=self.root,
            env=self.git_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if check and result.returncode:
            self.fail(
                f"git {' '.join(arguments)} failed ({result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
        return result

    def fail(self, detail: str) -> None:
        raise AssertionError(detail)

    def commit(self, message: str, *, allow_empty: bool = False) -> str:
        self.run("add", "-A")
        self.commit_number += 1
        timestamp = f"2026-01-{self.commit_number:02d}T00:00:00+00:00"
        environment = self.git_environment(
            GIT_AUTHOR_NAME="Receipt Contract Test",
            GIT_AUTHOR_EMAIL="receipt-contract@example.invalid",
            GIT_AUTHOR_DATE=timestamp,
            GIT_COMMITTER_NAME="Receipt Contract Test",
            GIT_COMMITTER_EMAIL="receipt-contract@example.invalid",
            GIT_COMMITTER_DATE=timestamp,
        )
        arguments = ["git", "commit", "-q", "-m", message]
        if allow_empty:
            arguments.append("--allow-empty")
        result = subprocess.run(
            arguments,
            cwd=self.root,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode:
            self.fail(
                f"git commit failed ({result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
        return self.run("rev-parse", "HEAD").stdout.strip()

    def write(self, relative: str, contents: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    def write_contract_files(self) -> None:
        claims = (
            ("docs/perf/README.md", "Fixture performance claim"),
            ("docs/BENCHMARKS.md", "Fixture benchmark claim"),
            ("docs/COMPARISON.md", "Fixture comparison claim"),
            ("docs/ixp-evaluation.md", "Fixture evaluation claim"),
        )
        manifest = {
            "schema": 1,
            "release_window": 3,
            "front_doors": list(checker.FRONT_DOORS),
            "receipts": [
                {
                    "path": self.receipt,
                    "measured_commit": self.measured_commit,
                    "release_commit": self.release_commit,
                    "measured_on": self.measured_on,
                }
            ],
            "claims": [
                {"source": source, "anchor": anchor, "receipt": self.receipt}
                for source, anchor in sorted(claims)
            ],
        }
        self.write(
            "docs/perf/receipt-provenance.json",
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        )
        self.write(
            self.receipt,
            "# Fixture receipt\n\n"
            f"Measured commit: `{self.measured_commit}`\n\n"
            f"Release commit: `{self.release_commit}`\n",
        )
        self.write(
            "docs/perf/README.md",
            "- **Fixture performance claim** [receipt](fixture-receipt.md)\n",
        )
        self.write(
            "docs/BENCHMARKS.md",
            "Fixture benchmark claim uses the [receipt](perf/fixture-receipt.md).\n",
        )
        self.write(
            "docs/COMPARISON.md",
            "Fixture comparison claim uses the [receipt](perf/fixture-receipt.md).\n",
        )
        self.write(
            "docs/ixp-evaluation.md",
            "| Claim | Evidence |\n"
            "| --- | --- |\n"
            "| Fixture evaluation claim | [receipt](perf/fixture-receipt.md) |\n",
        )
        self.write(
            ".github/workflows/public-docs-contract.yml",
            "steps:\n"
            "  - uses: actions/checkout@v7\n"
            "    with:\n"
            "      fetch-depth: 0\n"
            "  - run: |\n"
            "      python3 -m unittest -v scripts/test_check_perf_receipt_freshness.py\n"
            "      python3 scripts/check_perf_receipt_freshness.py\n",
        )
        self.write(
            "docs/RELEASE_CHECKLIST.md",
            "Validate docs/perf/receipt-provenance.json against:\n"
            + "".join(f"- {source}\n" for source in checker.FRONT_DOORS),
        )
        self.write(
            "docs/RECEIPTS.md",
            "See [the manifest](perf/receipt-provenance.json) and "
            "[checker](../scripts/check_perf_receipt_freshness.py).\n",
        )

    def add_next_stable_release(self) -> None:
        self.commit("release 0.5.0", allow_empty=True)
        self.run("tag", "v0.5.0")

    def add_measured_date_to_claims(self) -> None:
        for relative, anchor in (
            ("docs/perf/README.md", "Fixture performance claim"),
            ("docs/BENCHMARKS.md", "Fixture benchmark claim"),
            ("docs/COMPARISON.md", "Fixture comparison claim"),
            ("docs/ixp-evaluation.md", "Fixture evaluation claim"),
        ):
            path = self.root / relative
            contents = path.read_text(encoding="utf-8")
            path.write_text(
                contents.replace(anchor, f"{anchor}, measured {self.measured_on}", 1),
                encoding="utf-8",
            )


class PerfReceiptFreshnessTests(unittest.TestCase):
    maxDiff = None

    def errors(
        self,
        manifest: dict[str, object] | None = None,
        overrides: dict[str, str] | None = None,
    ) -> list[str]:
        return checker.check_contract(ROOT, MANIFEST if manifest is None else manifest, overrides)

    def assert_red(
        self,
        needle: str,
        manifest: dict[str, object] | None = None,
        overrides: dict[str, str] | None = None,
    ) -> None:
        errors = self.errors(manifest, overrides)
        self.assertTrue(any(needle in error for error in errors), errors)

    def test_live_contract_is_green(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_manifest_is_canonical_json(self) -> None:
        self.assertEqual(
            MANIFEST_TEXT,
            json.dumps(json.loads(MANIFEST_TEXT), indent=2, ensure_ascii=False) + "\n",
        )

    def test_manifest_shape_fails_closed(self) -> None:
        with self.assertRaisesRegex(checker.ContractError, "invalid JSON"):
            checker.parse_manifest("{")
        document = json.loads(MANIFEST_TEXT)
        document["unexpected"] = True
        with self.assertRaisesRegex(checker.ContractError, "contain only"):
            checker.parse_manifest(json.dumps(document))
        document = json.loads(MANIFEST_TEXT)
        document["release_window"] = 4
        with self.assertRaisesRegex(checker.ContractError, "release_window must be 3"):
            checker.parse_manifest(json.dumps(document))

    def test_manifest_requires_all_four_front_doors(self) -> None:
        document = json.loads(MANIFEST_TEXT)
        document["front_doors"].pop()
        with self.assertRaisesRegex(checker.ContractError, "exact ordered four-file"):
            checker.parse_manifest(json.dumps(document))

        document = json.loads(MANIFEST_TEXT)
        document["claims"] = [
            claim for claim in document["claims"] if claim["source"] != "docs/ixp-evaluation.md"
        ]
        with self.assertRaisesRegex(checker.ContractError, "exercise every front door"):
            checker.parse_manifest(json.dumps(document))

    def test_manifest_order_and_references_fail_closed(self) -> None:
        document = json.loads(MANIFEST_TEXT)
        document["receipts"].reverse()
        with self.assertRaisesRegex(checker.ContractError, "sorted by path"):
            checker.parse_manifest(json.dumps(document))

        document = json.loads(MANIFEST_TEXT)
        document["claims"][0]["receipt"] = "docs/perf/not-manifested.md"
        with self.assertRaisesRegex(checker.ContractError, "unmanifested receipt"):
            checker.parse_manifest(json.dumps(document))

    def test_manifest_rejects_bad_commit_and_date_fields(self) -> None:
        document = json.loads(MANIFEST_TEXT)
        document["receipts"][0]["measured_commit"] = "8f1c920e"
        with self.assertRaisesRegex(checker.ContractError, "full lowercase commit SHA"):
            checker.parse_manifest(json.dumps(document))

        document = json.loads(MANIFEST_TEXT)
        document["receipts"][0]["measured_on"] = "2026-08-99"
        with self.assertRaisesRegex(checker.ContractError, "ISO date"):
            checker.parse_manifest(json.dumps(document))

    def test_missing_or_duplicate_claim_anchor_is_red(self) -> None:
        summary = text("docs/perf/README.md")
        self.assert_red(
            "occurs 0 times",
            overrides={
                "docs/perf/README.md": summary.replace(
                    "- **IRR-scale filter reload**", "- **IRR reload**", 1
                )
            },
        )
        self.assert_red(
            "occurs 2 times",
            overrides={"docs/perf/README.md": summary + "\n- **IRR-scale filter reload** duplicate\n"},
        )

    def test_claim_must_link_the_manifested_receipt(self) -> None:
        comparison = text("docs/COMPARISON.md")
        self.assert_red(
            "receipt links differ from its manifest",
            overrides={
                "docs/COMPARISON.md": comparison.replace(
                    "perf/route-server-1000-2026-07.md",
                    "perf/not-the-receipt.md",
                    1,
                )
            },
        )

    def test_unmanifested_receipt_link_in_an_enforced_block_is_red(self) -> None:
        summary = text("docs/perf/README.md")
        mutated = summary.replace(
            "[1000-peer scale receipt](scale-receipt-2026-07.md)",
            "[1000-peer scale receipt](scale-receipt-2026-07.md) and "
            "[another receipt](route-server-1000-2026-07.md)",
            1,
        )
        self.assert_red(
            "receipt links differ from its manifest",
            overrides={"docs/perf/README.md": mutated},
        )

    def test_each_stale_claim_requires_its_exact_date(self) -> None:
        comparison = text("docs/COMPARISON.md")
        for old, expected in (("measured 2026-07-26", "measured 2026-07-26"),):
            with self.subTest(old=old):
                self.assert_red(
                    f"must carry exact phrase '{expected}'",
                    overrides={"docs/COMPARISON.md": comparison.replace(old, "measured later", 1)},
                )

    def test_stale_claim_cannot_hide_behind_a_manifest_exception(self) -> None:
        manifest = copy.deepcopy(MANIFEST)
        receipt_item(manifest, "docs/perf/v0.61.0-final-performance-2026-07.md").pop(
            "measured_on"
        )
        self.assert_red("has no manifested measured_on date", manifest)

    def test_fresh_claim_does_not_require_a_date(self) -> None:
        original = text("docs/perf/README.md")
        summary = original.replace("  measured 2026-08-30\n", "", 1)
        self.assertNotEqual(original, summary)
        self.assertEqual(self.errors(overrides={"docs/perf/README.md": summary}), [])

    def test_receipt_must_record_manifested_provenance(self) -> None:
        path = "docs/perf/ixp-matrix-2026-07.md"
        self.assert_red(
            "does not record its manifested measured_commit",
            overrides={path: text(path).replace("ba5717b4", "not-a-commit")},
        )

    def test_temporary_git_unknown_commit_is_red(self) -> None:
        with TemporaryReceiptRepository() as fixture:
            unknown = "0" * 40
            manifest = copy.deepcopy(fixture.manifest)
            item = receipt_item(manifest, fixture.receipt)
            item["measured_commit"] = unknown
            receipt = (fixture.root / fixture.receipt).read_text(encoding="utf-8")
            errors = checker.check_contract(
                fixture.root,
                manifest,
                {fixture.receipt: receipt + f"\nMeasured commit: `{unknown}`\n"},
            )
            self.assertTrue(any("rev-parse --verify" in error for error in errors), errors)

    def test_temporary_git_release_without_stable_tag_is_red(self) -> None:
        with TemporaryReceiptRepository() as fixture:
            untagged = fixture.commit("valid but unreleased", allow_empty=True)
            self.assertEqual(fixture.run("rev-parse", "--verify", untagged).returncode, 0)
            self.assertIn(
                fixture.receipt_tag,
                checker.commit_tags(fixture.root, fixture.measured_commit),
            )
            manifest = copy.deepcopy(fixture.manifest)
            item = receipt_item(manifest, fixture.receipt)
            item["release_commit"] = untagged
            receipt = (fixture.root / fixture.receipt).read_text(encoding="utf-8")
            errors = checker.check_contract(
                fixture.root,
                manifest,
                {fixture.receipt: receipt + f"\nRelease commit: `{untagged}`\n"},
            )
            expected = f"release commit {untagged} is contained by no stable release tag"
            self.assertTrue(any(expected in error for error in errors), errors)

    def test_temporary_git_untagged_measurement_requires_source_equivalent(self) -> None:
        with TemporaryReceiptRepository() as fixture:
            fixture.run("tag", "-d", fixture.receipt_tag)
            errors = checker.check_contract(fixture.root, fixture.manifest)
            expected = (
                f"measured commit {fixture.measured_commit} is contained by no git tag"
            )
            self.assertTrue(any(expected in error for error in errors), errors)

    def test_temporary_git_source_equivalent_sibling_measurement_is_red(self) -> None:
        with TemporaryReceiptRepository() as fixture:
            fixture.run("tag", "-d", fixture.receipt_tag)
            manifest = copy.deepcopy(fixture.manifest)
            item = receipt_item(manifest, fixture.receipt)
            item["source_equivalent"] = True
            errors = checker.check_contract(fixture.root, manifest)
            expected = (
                f"source-equivalent release commit {fixture.release_commit} "
                f"is not an ancestor of measured commit {fixture.measured_commit}"
            )
            self.assertTrue(any(expected in error for error in errors), errors)

    def test_temporary_git_source_equivalent_descendant_measurement_is_green(self) -> None:
        with TemporaryReceiptRepository() as fixture:
            measured_commit = fixture.commit("post-release measurement", allow_empty=True)
            manifest = copy.deepcopy(fixture.manifest)
            item = receipt_item(manifest, fixture.receipt)
            item["measured_commit"] = measured_commit
            item["source_equivalent"] = True
            receipt = (fixture.root / fixture.receipt).read_text(encoding="utf-8")
            self.assertEqual(
                checker.check_contract(
                    fixture.root,
                    manifest,
                    {fixture.receipt: receipt + f"\nMeasured commit: `{measured_commit}`\n"},
                ),
                [],
            )

    def test_temporary_git_off_main_measurement_and_landed_sibling_are_green(self) -> None:
        with TemporaryReceiptRepository() as fixture:
            self.assertEqual(
                fixture.run(
                    "merge-base", fixture.measured_commit, fixture.release_commit
                ).stdout.strip(),
                fixture.common_commit,
            )
            self.assertNotEqual(
                fixture.run(
                    "merge-base",
                    "--is-ancestor",
                    fixture.measured_commit,
                    fixture.release_commit,
                    check=False,
                ).returncode,
                0,
            )
            self.assertNotEqual(
                fixture.run(
                    "merge-base",
                    "--is-ancestor",
                    fixture.release_commit,
                    fixture.measured_commit,
                    check=False,
                ).returncode,
                0,
            )
            self.assertIn(
                fixture.receipt_tag,
                checker.commit_tags(fixture.root, fixture.measured_commit),
            )
            self.assertIn("v0.1.0", checker.commit_tags(fixture.root, fixture.release_commit))
            self.assertEqual(checker.check_contract(fixture.root, fixture.manifest), [])

    def test_temporary_git_next_release_requires_exact_measured_date(self) -> None:
        with TemporaryReceiptRepository() as fixture:
            self.assertEqual(checker.check_contract(fixture.root, fixture.manifest), [])
            fixture.add_next_stable_release()
            errors = checker.check_contract(fixture.root, fixture.manifest)
            expected = f"must carry exact phrase 'measured {fixture.measured_on}'"
            self.assertEqual(sum(expected in error for error in errors), 4, errors)
            fixture.add_measured_date_to_claims()
            self.assertEqual(checker.check_contract(fixture.root, fixture.manifest), [])

    def test_workflow_checklist_and_index_wiring_fail_closed(self) -> None:
        cases = (
            (
                ".github/workflows/public-docs-contract.yml",
                "fetch-depth: 0",
                "must contain 'fetch-depth: 0' exactly once",
            ),
            (
                ".github/workflows/public-docs-contract.yml",
                "python3 scripts/check_perf_receipt_freshness.py",
                "must contain 'python3 scripts/check_perf_receipt_freshness.py' exactly once",
            ),
            (
                "docs/RELEASE_CHECKLIST.md",
                "docs/perf/receipt-provenance.json",
                "must contain required fragment 'docs/perf/receipt-provenance.json'",
            ),
            (
                "docs/RECEIPTS.md",
                "../scripts/check_perf_receipt_freshness.py",
                "must contain required fragment '../scripts/check_perf_receipt_freshness.py'",
            ),
        )
        for path, fragment, error in cases:
            with self.subTest(path=path, fragment=fragment):
                self.assert_red(error, overrides={path: text(path).replace(fragment, "removed", 1)})

    def test_zero_inbound_links_are_advisory_inventory(self) -> None:
        self.assertEqual(
            checker.unlinked_receipts(ROOT),
            [
                "docs/perf/event-history-producer-2026-07.md",
                "docs/perf/persisted-config-serialization-2026-08.md",
                "docs/perf/private-single-best-fanout-2026-07.md",
                "docs/perf/shared-source-ordering-2026-07.md",
                "docs/perf/vpn-rib-query-occupancy-method.md",
            ],
        )
        self.assertEqual(self.errors(), [])

    def test_supersession_links_are_direct_and_non_destructive(self) -> None:
        self.assertIn(
            "[realistic-mix receipt](irr-reload-realistic-mix-2026-08.md)",
            text("docs/perf/irr-reload-comparison-2026-08.md"),
        )
        self.assertIn(
            "[noise-floor recheck](attr-intern-hashing-recheck-2026-08.md)",
            text("docs/perf/attr-intern-hashing-2026-08.md"),
        )


if __name__ == "__main__":
    unittest.main()
