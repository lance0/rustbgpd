#!/usr/bin/env python3
"""Fail-closed build-environment and Cargo-configuration fence."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
from pathlib import Path
from typing import Mapping


REQUIRED_RUSTUP_TOOLCHAIN = "1.95.0-x86_64-unknown-linux-gnu"
FORBIDDEN_EXACT = {
    "AR",
    "ARFLAGS",
    "AS",
    "ASFLAGS",
    "CC",
    "CFLAGS",
    "CMAKE",
    "CMAKE_FLAGS",
    "CPP",
    "CPPFLAGS",
    "CRATE_CC_NO_DEFAULTS",
    "CXX",
    "CXXFLAGS",
    "HOST_AR",
    "HOST_CC",
    "HOST_CXX",
    "LD",
    "LDFLAGS",
    "LIBCLANG_PATH",
    "MAKE",
    "MAKEFLAGS",
    "NINJA",
    "PKG_CONFIG",
    "PROTOC",
    "RANLIB",
    "RANLIBFLAGS",
    "RING_PREGENERATE_ASM",
    "RUSTC_BOOTSTRAP",
    "RUSTC",
    "RUSTDOC",
    "RUSTC_WRAPPER",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "TARGET_AR",
    "TARGET_CC",
    "TARGET_CXX",
    "TARGET_RANLIB",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_INCREMENTAL",
}
FORBIDDEN_PREFIXES = (
    "AR_",
    "ARFLAGS_",
    "AS_",
    "ASFLAGS_",
    "BINDGEN_",
    "CC_",
    "CFLAGS_",
    "CMAKE_",
    "CPP_",
    "CPPFLAGS_",
    "CXX_",
    "CXXFLAGS_",
    "LD_",
    "LDFLAGS_",
    "LIBCLANG_",
    "MAKE_",
    "MAKEFLAGS_",
    "NINJA_",
    "PKG_CONFIG_",
    "PROTOC_",
    "RANLIB_",
    "RANLIBFLAGS_",
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
    requested_toolchain = environ.get("RUSTUP_TOOLCHAIN")
    if requested_toolchain not in (None, REQUIRED_RUSTUP_TOOLCHAIN):
        raise BuildFenceError(
            "RUSTUP_TOOLCHAIN must be unset or exactly "
            f"{REQUIRED_RUSTUP_TOOLCHAIN}, got {requested_toolchain!r}"
        )


def git_object_id(kind: str, payload: bytes) -> bytes:
    framed = f"{kind} {len(payload)}\0".encode() + payload
    # This repository uses Git's SHA-1 object format. This is an object
    # identity check, not a password/signature primitive.
    return hashlib.sha1(framed, usedforsecurity=False).digest()


def source_tree_id(directory: Path) -> bytes:
    """Reconstruct the Git tree identity of a complete extracted source tree."""
    rendered: list[tuple[bytes, bytes]] = []
    try:
        entries = list(os.scandir(directory))
    except OSError as exc:
        raise BuildFenceError(f"cannot scan extracted source tree {directory}: {exc}") from exc
    for entry in entries:
        encoded_name = entry.name.encode("utf-8")
        path = Path(entry.path)
        try:
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                mode = b"40000"
                object_id = source_tree_id(path)
                sort_key = encoded_name + b"/"
            elif stat.S_ISREG(metadata.st_mode):
                mode = b"100755" if metadata.st_mode & 0o111 else b"100644"
                object_id = git_object_id("blob", path.read_bytes())
                sort_key = encoded_name
            elif stat.S_ISLNK(metadata.st_mode):
                mode = b"120000"
                object_id = git_object_id("blob", os.readlink(path).encode("utf-8"))
                sort_key = encoded_name
            else:
                raise BuildFenceError(
                    f"unsupported extracted source entry type: {path}"
                )
        except (OSError, UnicodeError) as exc:
            raise BuildFenceError(f"cannot inspect extracted source entry {path}: {exc}") from exc
        rendered.append(
            (sort_key, mode + b" " + encoded_name + b"\0" + object_id)
        )
    payload = b"".join(row for _, row in sorted(rendered, key=lambda row: row[0]))
    return git_object_id("tree", payload)


def validate_source_tree(
    source_root: Path, expected_tree: str, *, require_immutable: bool
) -> None:
    if not expected_tree or len(expected_tree) != 40 or any(
        character not in "0123456789abcdef" for character in expected_tree
    ):
        raise BuildFenceError("expected source tree must be a lowercase 40-hex Git tree")
    actual = source_tree_id(source_root).hex()
    if actual != expected_tree:
        raise BuildFenceError(
            f"complete extracted source tree mismatch: actual={actual} expected={expected_tree}"
        )
    if require_immutable:
        for path in (source_root, *source_root.rglob("*")):
            try:
                mode = path.lstat().st_mode
            except OSError as exc:
                raise BuildFenceError(f"cannot stat extracted source entry {path}: {exc}") from exc
            # Symlink permission bits are not enforceable on Linux; their
            # identity is protected by the non-writable parent directory and
            # the complete Git-tree check above.
            if not stat.S_ISLNK(mode) and mode & 0o222:
                raise BuildFenceError(f"extracted source entry remains writable: {path}")


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
    parser.add_argument("--expected-tree")
    parser.add_argument("--require-immutable", action="store_true")
    args = parser.parse_args()
    try:
        validate_environment(os.environ)
        if not args.environment_only:
            if args.source_root is None or args.cargo_home is None:
                parser.error("--source-root and --cargo-home are required")
            allowed = validate_cargo_configs(args.source_root, args.cargo_home)
            if args.expected_tree is None:
                parser.error("--expected-tree is required")
            validate_source_tree(
                args.source_root,
                args.expected_tree,
                require_immutable=args.require_immutable,
            )
            print(f"allowed_cargo_config={allowed}")
            print(f"verified_source_tree={args.expected_tree}")
    except BuildFenceError as exc:
        print(f"error: {exc}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
