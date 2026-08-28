#!/usr/bin/env python3
"""Validate, restore, and seal the bounded nightly wire fuzz corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
from pathlib import Path

TARGET_MAX_LENS = {
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
    "encode_update": 4_096,
    "parse_rd": 4_096,
}
MAX_BYTES = 16_777_216
MAX_FILES = 20_000
SCHEMA = 1
MANIFEST = "manifest.json"
CORPUS = "corpus"


class CorpusError(RuntimeError):
    """The cached corpus violates its reviewed trust boundary."""


class CorpusCapExceeded(CorpusError):
    """The corpus crossed an aggregate save or restore bound."""

    def __init__(self, file_count: int, total_bytes: int) -> None:
        self.file_count = file_count
        self.total_bytes = total_bytes
        super().__init__(
            f"corpus exceeds caps: {file_count} files/{total_bytes} bytes; "
            f"limits are {MAX_FILES}/{MAX_BYTES}"
        )


def _reject_non_directory(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise CorpusError(f"cannot inspect {label} {path}: {error}") from error
    if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
        raise CorpusError(f"{label} must be a real directory: {path}")


def _reject_non_regular(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise CorpusError(f"cannot inspect {label} {path}: {error}") from error
    if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
        raise CorpusError(f"{label} must be a regular file: {path}")


def inventory(corpus: Path) -> tuple[list[dict[str, object]], int]:
    _reject_non_directory(corpus, "corpus")
    expected = set(TARGET_MAX_LENS)
    with os.scandir(corpus) as entries:
        actual = {entry.name for entry in entries}
    if actual != expected:
        raise CorpusError(
            f"target directories differ: expected {sorted(expected)}, got {sorted(actual)}"
        )
    rows: list[dict[str, object]] = []
    total = 0
    for target in sorted(expected):
        target_dir = corpus / target
        _reject_non_directory(target_dir, "target")
        with os.scandir(target_dir) as entries:
            target_entries = sorted(entries, key=lambda item: item.name)
        for entry in target_entries:
            path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            mode = metadata.st_mode
            if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                raise CorpusError(f"corpus entries must be regular files: {path}")
            size = metadata.st_size
            if size > TARGET_MAX_LENS[target]:
                raise CorpusError(
                    f"{target}/{entry.name} is {size} bytes; max_len is {TARGET_MAX_LENS[target]}"
                )
            next_count = len(rows) + 1
            next_total = total + size
            if next_count > MAX_FILES or next_total > MAX_BYTES:
                raise CorpusCapExceeded(next_count, next_total)
            total = next_total
            rows.append(
                {
                    "path": f"{target}/{entry.name}",
                    "size": size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    return rows, total


def manifest(rows: list[dict[str, object]], total: int) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "files": rows,
        "file_count": len(rows),
        "total_bytes": total,
    }


def _read_manifest(path: Path) -> dict[str, object]:
    _reject_non_regular(path, "cache manifest")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CorpusError(f"cannot read cache manifest {path}: {error}") from error
    if not isinstance(value, dict):
        raise CorpusError("cache manifest must be an object")
    return value


def validate_bundle(bundle: Path) -> tuple[int, int, str]:
    _reject_non_directory(bundle, "cache bundle")
    with os.scandir(bundle) as entries:
        names = {entry.name for entry in entries}
    if names != {MANIFEST, CORPUS}:
        raise CorpusError(f"cache bundle entries differ: {sorted(names)}")
    rows, total = inventory(bundle / CORPUS)
    expected = manifest(rows, total)
    actual = _read_manifest(bundle / MANIFEST)
    if actual != expected:
        raise CorpusError("cache manifest does not match corpus bytes")
    digest = hashlib.sha256((bundle / MANIFEST).read_bytes()).hexdigest()
    return len(rows), total, digest


def _fresh_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise CorpusError(f"destination must not exist: {path}")
    path.mkdir(parents=True)


def _copy_corpus(source: Path, destination: Path) -> None:
    _fresh_directory(destination)
    for target in sorted(TARGET_MAX_LENS):
        shutil.copytree(source / target, destination / target, symlinks=False)


def restore(cache_bundle: Path, seeds: Path, live: Path, cache_hit: bool) -> str:
    if live.exists() or live.is_symlink():
        raise CorpusError(f"live corpus must not exist before restore: {live}")
    if cache_hit:
        file_count, total, digest = validate_bundle(cache_bundle)
        _copy_corpus(cache_bundle / CORPUS, live)
        inventory(live)
        return (
            f"restored validated cached corpus: {file_count} files/{total} bytes; "
            f"manifest_sha256={digest}"
        )
    rows, total = inventory(seeds)
    _copy_corpus(seeds, live)
    inventory(live)
    return (
        f"cache unavailable; using tracked seeds only: {len(rows)} files/{total} bytes"
    )


def seal(live: Path, output: Path) -> tuple[bool, str]:
    try:
        rows, total = inventory(live)
    except CorpusCapExceeded as error:
        return False, (
            "corpus crossed save caps "
            f"({error.file_count} files/{error.total_bytes} bytes); skipping save"
        )
    _fresh_directory(output)
    _copy_corpus(live, output / CORPUS)
    (output / MANIFEST).write_text(
        json.dumps(manifest(rows, total), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    validate_bundle(output)
    manifest_digest = hashlib.sha256((output / MANIFEST).read_bytes()).hexdigest()
    return (
        True,
        f"sealed {len(rows)} files/{total} bytes; manifest_sha256={manifest_digest}",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("--cache-bundle", type=Path, required=True)
    restore_parser.add_argument("--seeds", type=Path, required=True)
    restore_parser.add_argument("--live", type=Path, required=True)
    restore_parser.add_argument("--cache-hit", choices=("true", "false"), required=True)
    seal_parser = subparsers.add_parser("seal")
    seal_parser.add_argument("--live", type=Path, required=True)
    seal_parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "restore":
            print(
                restore(
                    args.cache_bundle, args.seeds, args.live, args.cache_hit == "true"
                )
            )
            return 0
        saved, detail = seal(args.live, args.output)
        print(detail)
        return 0 if saved else 3
    except CorpusError as error:
        print(f"wire fuzz corpus cache rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
