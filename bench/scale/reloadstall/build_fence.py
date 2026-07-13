#!/usr/bin/env python3
"""Fail-closed build-environment and Cargo-configuration fence."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Mapping


FORBIDDEN_EXACT = {
    "CC",
    "CFLAGS",
    "LDFLAGS",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_INCREMENTAL",
}
FORBIDDEN_PREFIXES = (
    "CC_",
    "CFLAGS_",
    "LDFLAGS_",
    "CARGO_BUILD_",
    "CARGO_PROFILE_",
    "CARGO_TARGET_",
)


class BuildFenceError(ValueError):
    """The retained build would inherit an uncontrolled input."""


def forbidden_environment(environ: Mapping[str, str]) -> list[str]:
    rejected: list[str] = []
    for name in environ:
        if (
            name in FORBIDDEN_EXACT
            or name.startswith(FORBIDDEN_PREFIXES)
            or (name.startswith("RUSTC") and name.endswith("_WRAPPER"))
        ):
            rejected.append(name)
    return sorted(set(rejected))


def cargo_config_candidates(source_root: Path, cargo_home: Path) -> list[Path]:
    """Return every external Cargo config that can affect a source-root build."""
    source_root = source_root.resolve(strict=True)
    cargo_home = cargo_home.resolve(strict=False)
    allowed = source_root / ".cargo" / "config.toml"
    candidates: set[Path] = set()

    legacy_source_config = source_root / ".cargo" / "config"
    if legacy_source_config.exists() or legacy_source_config.is_symlink():
        candidates.add(legacy_source_config)

    current = source_root.parent
    while True:
        for filename in ("config", "config.toml"):
            candidate = current / ".cargo" / filename
            if candidate.exists() or candidate.is_symlink():
                candidates.add(candidate)
        if current == current.parent:
            break
        current = current.parent

    for filename in ("config", "config.toml"):
        candidate = cargo_home / filename
        if candidate != allowed and (candidate.exists() or candidate.is_symlink()):
            candidates.add(candidate)
    return sorted(candidates, key=lambda path: str(path))


def validate_source_config(source_root: Path) -> Path:
    source_root = source_root.resolve(strict=True)
    cargo_dir = source_root / ".cargo"
    if not cargo_dir.is_dir() or cargo_dir.is_symlink():
        raise BuildFenceError("archived source .cargo must be a regular directory")
    allowed = cargo_dir / "config.toml"
    if not allowed.is_file() or allowed.is_symlink():
        raise BuildFenceError(
            "archived source must contain one regular .cargo/config.toml"
        )
    return allowed


def validate_environment(environ: Mapping[str, str]) -> None:
    rejected = forbidden_environment(environ)
    if rejected:
        raise BuildFenceError(
            "forbidden retained-build environment variables: " + ", ".join(rejected)
        )


def validate_cargo_configs(source_root: Path, cargo_home: Path) -> Path:
    allowed = validate_source_config(source_root)
    external = cargo_config_candidates(source_root, cargo_home)
    if external:
        raise BuildFenceError(
            "external Cargo config files are forbidden: "
            + ", ".join(str(path) for path in external)
        )
    return allowed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment-only", action="store_true")
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--cargo-home", type=Path)
    args = parser.parse_args()
    try:
        validate_environment(os.environ)
        if not args.environment_only:
            if args.source_root is None or args.cargo_home is None:
                parser.error("--source-root and --cargo-home are required")
            allowed = validate_cargo_configs(args.source_root, args.cargo_home)
            print(f"allowed_cargo_config={allowed}")
    except BuildFenceError as exc:
        print(f"error: {exc}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
