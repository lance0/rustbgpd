#!/usr/bin/env python3
"""Mutation tests for the wire fuzz corpus cache boundary."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fuzz_corpus_cache as cache


class CorpusCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.seeds = self.root / "seeds"
        for target in cache.TARGET_MAX_LENS:
            target_dir = self.seeds / target
            target_dir.mkdir(parents=True)
            (target_dir / "seed").write_bytes(target.encode())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def bundle(self) -> Path:
        live = self.root / "live-source"
        cache._copy_corpus(self.seeds, live)
        output = self.root / "bundle"
        saved, _ = cache.seal(live, output)
        self.assertTrue(saved)
        return output

    def test_seed_only_restore_is_explicit_and_exact(self) -> None:
        live = self.root / "live"
        detail = cache.restore(self.root / "missing", self.seeds, live, False)
        self.assertIn("tracked seeds only", detail)
        self.assertIn("12 files/", detail)
        self.assertEqual(cache.inventory(live), cache.inventory(self.seeds))

    def test_valid_bundle_round_trip_is_deterministic(self) -> None:
        bundle = self.bundle()
        before = (bundle / cache.MANIFEST).read_bytes()
        cache.validate_bundle(bundle)
        live = self.root / "restored"
        detail = cache.restore(bundle, self.seeds, live, True)
        self.assertRegex(detail, r"manifest_sha256=[0-9a-f]{64}$")
        second = self.root / "second"
        saved, detail = cache.seal(live, second)
        self.assertTrue(saved)
        self.assertRegex(detail, r"manifest_sha256=[0-9a-f]{64}$")
        self.assertEqual(before, (second / cache.MANIFEST).read_bytes())
        manifest = json.loads(before)
        paths = [row["path"] for row in manifest["files"]]
        self.assertEqual(paths, sorted(paths))

    def test_every_target_omission_and_extra_is_rejected(self) -> None:
        for target in cache.TARGET_MAX_LENS:
            with self.subTest(target=target):
                omitted = self.root / f"omitted-{target}"
                cache._copy_corpus(self.seeds, omitted)
                (omitted / target / "seed").unlink()
                (omitted / target).rmdir()
                with self.assertRaisesRegex(
                    cache.CorpusError, "target directories differ"
                ):
                    cache.inventory(omitted)
        extra = self.root / "extra"
        cache._copy_corpus(self.seeds, extra)
        (extra / "unexpected").mkdir()
        with self.assertRaisesRegex(cache.CorpusError, "target directories differ"):
            cache.inventory(extra)

    def test_links_nesting_and_oversized_inputs_are_rejected(self) -> None:
        for kind in ("link", "nesting", "oversized"):
            mutated = self.root / kind
            cache._copy_corpus(self.seeds, mutated)
            target = "decode_bgpls"
            if kind == "link":
                os.symlink(mutated / target / "seed", mutated / target / "link")
                error = "regular files"
            elif kind == "nesting":
                (mutated / target / "nested").mkdir()
                error = "regular files"
            else:
                (mutated / target / "large").write_bytes(b"x" * 4097)
                error = "max_len"
            with self.subTest(kind=kind), self.assertRaisesRegex(
                cache.CorpusError, error
            ):
                cache.inventory(mutated)

    def test_manifest_byte_size_and_shape_mutations_are_rejected(self) -> None:
        for index, mutation in enumerate(
            ("bytes", "manifest", "non_utf8", "extra", "link")
        ):
            live = self.root / f"source-{index}"
            cache._copy_corpus(self.seeds, live)
            bundle = self.root / f"bundle-{index}"
            saved, _ = cache.seal(live, bundle)
            self.assertTrue(saved)
            if mutation == "bytes":
                (bundle / cache.CORPUS / "decode_bgpls" / "seed").write_bytes(
                    b"changed"
                )
            elif mutation == "manifest":
                value = json.loads((bundle / cache.MANIFEST).read_text())
                value["schema"] = 99
                (bundle / cache.MANIFEST).write_text(json.dumps(value))
            elif mutation == "non_utf8":
                (bundle / cache.MANIFEST).write_bytes(b"\xff")
            elif mutation == "extra":
                (bundle / "extra").write_text("unexpected")
            else:
                (bundle / cache.MANIFEST).unlink()
                os.symlink(
                    bundle / cache.CORPUS / "decode_bgpls" / "seed",
                    bundle / cache.MANIFEST,
                )
            with self.subTest(mutation=mutation):
                if mutation == "non_utf8":
                    with self.assertRaisesRegex(
                        cache.CorpusError, "cannot read cache manifest"
                    ):
                        cache.validate_bundle(bundle)
                else:
                    with self.assertRaises(cache.CorpusError):
                        cache.validate_bundle(bundle)

    def test_invalid_matched_bundle_fails_before_live_install(self) -> None:
        bundle = self.bundle()
        (bundle / cache.MANIFEST).write_text("{}")
        live = self.root / "live"
        with self.assertRaisesRegex(cache.CorpusError, "manifest does not match"):
            cache.restore(bundle, self.seeds, live, True)
        self.assertFalse(live.exists())

    def test_existing_destinations_are_rejected(self) -> None:
        live = self.root / "live"
        live.mkdir()
        with self.assertRaisesRegex(cache.CorpusError, "must not exist"):
            cache.restore(self.root / "missing", self.seeds, live, False)

    def test_over_cap_seal_skips_without_output(self) -> None:
        live = self.root / "live"
        cache._copy_corpus(self.seeds, live)
        with mock.patch.object(cache, "MAX_FILES", 1), mock.patch.object(
            cache.hashlib, "sha256", wraps=cache.hashlib.sha256
        ) as sha256:
            saved, detail = cache.seal(live, self.root / "output")
        self.assertFalse(saved)
        self.assertIn("skipping save", detail)
        self.assertEqual(sha256.call_count, 1)
        self.assertFalse((self.root / "output").exists())

    def test_restore_rejects_file_and_byte_caps(self) -> None:
        for name, limit in (("MAX_FILES", 1), ("MAX_BYTES", 1)):
            with self.subTest(limit=name), mock.patch.object(cache, name, limit):
                with self.assertRaisesRegex(cache.CorpusError, "exceeds caps"):
                    cache.inventory(self.seeds)


if __name__ == "__main__":
    unittest.main()
