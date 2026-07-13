#!/usr/bin/env python3
"""Adversarial tests for the retained build-input fence."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from build_fence import (
    BuildFenceError,
    cargo_config_candidates,
    forbidden_environment,
    validate_cargo_configs,
)


class BuildEnvironmentFenceTests(unittest.TestCase):
    def test_every_override_family_is_rejected(self) -> None:
        names = {
            "RUSTFLAGS",
            "RUSTDOCFLAGS",
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTC_CUSTOM_WRAPPER",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_INCREMENTAL",
            "CARGO_PROFILE_RELEASE_LTO",
            "CARGO_BUILD_JOBS",
            "CARGO_TARGET_DIR",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
            "CC",
            "CC_x86_64_unknown_linux_gnu",
            "CFLAGS",
            "CFLAGS_x86_64_unknown_linux_gnu",
            "LDFLAGS",
            "LDFLAGS_x86_64_unknown_linux_gnu",
        }
        self.assertEqual(forbidden_environment({name: "x" for name in names}), sorted(names))

    def test_non_override_toolchain_locations_are_allowed(self) -> None:
        self.assertEqual(
            forbidden_environment(
                {
                    "CARGO_HOME": "/cache/cargo",
                    "RUSTUP_HOME": "/cache/rustup",
                    "RUSTUP_TOOLCHAIN": "stable",
                }
            ),
            [],
        )


class CargoConfigFenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.source = self.root / "outer" / "source"
        (self.source / ".cargo").mkdir(parents=True)
        (self.source / ".cargo" / "config.toml").write_text(
            "[build]\nrustdocflags = ['-D', 'warnings']\n", encoding="utf-8"
        )
        self.cargo_home = self.root / "cargo-home"
        self.cargo_home.mkdir()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_only_archived_source_config_is_allowed(self) -> None:
        self.assertEqual(
            validate_cargo_configs(self.source, self.cargo_home),
            self.source.resolve() / ".cargo" / "config.toml",
        )

    def test_legacy_source_config_is_rejected(self) -> None:
        (self.source / ".cargo" / "config").write_text("[build]\n", encoding="utf-8")
        with self.assertRaisesRegex(BuildFenceError, "external Cargo config"):
            validate_cargo_configs(self.source, self.cargo_home)

    def test_ancestor_config_is_rejected(self) -> None:
        ancestor = self.source.parent / ".cargo"
        ancestor.mkdir()
        (ancestor / "config.toml").write_text("[build]\n", encoding="utf-8")
        found = cargo_config_candidates(self.source, self.cargo_home)
        self.assertIn(ancestor / "config.toml", found)
        with self.assertRaisesRegex(BuildFenceError, "external Cargo config"):
            validate_cargo_configs(self.source, self.cargo_home)

    def test_cargo_home_config_is_rejected(self) -> None:
        (self.cargo_home / "config").write_text("[build]\n", encoding="utf-8")
        with self.assertRaisesRegex(BuildFenceError, "external Cargo config"):
            validate_cargo_configs(self.source, self.cargo_home)

    def test_missing_or_symlinked_source_config_is_rejected(self) -> None:
        allowed = self.source / ".cargo" / "config.toml"
        allowed.unlink()
        allowed.symlink_to(self.cargo_home / "missing")
        with self.assertRaisesRegex(BuildFenceError, "one regular"):
            validate_cargo_configs(self.source, self.cargo_home)

    def test_symlinked_source_cargo_directory_is_rejected(self) -> None:
        cargo_dir = self.source / ".cargo"
        for child in cargo_dir.iterdir():
            child.unlink()
        cargo_dir.rmdir()
        external = self.root / "external-cargo"
        external.mkdir()
        (external / "config.toml").write_text("[build]\n", encoding="utf-8")
        cargo_dir.symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(BuildFenceError, "regular directory"):
            validate_cargo_configs(self.source, self.cargo_home)


if __name__ == "__main__":
    unittest.main()
