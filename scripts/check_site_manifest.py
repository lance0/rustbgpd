#!/usr/bin/env python3
"""Validate docs/site-manifest.json: site destination -> repository source."""

import json
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]


def unique_entries(pairs):
    entries = {}
    for destination, source in pairs:
        if destination in entries:
            raise ValueError(f"duplicate destination: {destination}")
        entries[destination] = source
    return entries


def load_manifest(root: Path) -> dict[str, str]:
    entries = json.loads(
        (root / "docs/site-manifest.json").read_text(encoding="utf-8"),
        object_pairs_hook=unique_entries,
    )
    if not isinstance(entries, dict) or not entries:
        raise ValueError("site manifest must be a nonempty destination/source object")
    sources = set()
    missing = []
    for destination, source in entries.items():
        for label, value in (("destination", destination), ("source", source)):
            if (
                not isinstance(value, str)
                or "\\" in value
                or value.startswith("/")
                or any(part in ("", ".", "..") for part in value.split("/"))
                or PurePosixPath(value).suffix != ".md"
            ):
                raise ValueError(f"invalid {label} path: {value!r}")
        if any(str(parent) in entries for parent in PurePosixPath(destination).parents):
            raise ValueError(f"destination is inside another output file: {destination}")
        for reserved in ("index.md", "meta.json", "cookbook/meta.json", "source.json"):
            if destination == reserved or destination.startswith(f"{reserved}/"):
                raise ValueError(f"{reserved} is maintained by the site")
        if not source.startswith("docs/"):
            raise ValueError(f"source must be under docs/: {source}")
        if source in sources:
            raise ValueError(f"duplicate source: {source}")
        sources.add(source)
        path = root / source
        if not path.resolve().is_relative_to((root / "docs").resolve()):
            raise ValueError(f"source escapes docs/: {source}")
        if not path.is_file():
            missing.append(source)
    if missing:
        raise ValueError("missing source files:\n  " + "\n  ".join(missing))
    return entries


if __name__ == "__main__":
    try:
        load_manifest(ROOT)
    except (OSError, ValueError) as error:
        print(f"site manifest: {error}", file=sys.stderr)
        sys.exit(1)
    print("site manifest: OK")
