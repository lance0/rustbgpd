#!/usr/bin/env python3
"""Check that the embedding crate map matches locked, offline Cargo metadata."""

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "docs" / "EMBEDDING.md"
COMMAND = (
    "cargo",
    "metadata",
    "--locked",
    "--offline",
    "--format-version",
    "1",
    "--no-deps",
)
BEGIN = "<!-- BEGIN EMBEDDING CRATE MAP -->"
END = "<!-- END EMBEDDING CRATE MAP -->"
SCOPE = (
    "All Cargo workspace packages are listed. Internal dependencies include "
    "normal and build dependencies, including target-specific dependencies; "
    "dev dependencies are excluded."
)


def cargo_metadata(root: Path = ROOT) -> dict:
    result = subprocess.run(COMMAND, cwd=root, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "cargo metadata failed")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"invalid cargo metadata JSON: {error}") from error


def expected_rows(metadata: dict) -> dict[str, tuple[str, tuple[str, ...]]]:
    members = set(metadata["workspace_members"])
    packages = [package for package in metadata["packages"] if package["id"] in members]
    names = {package["name"] for package in packages}
    rows = {}
    for package in packages:
        dependencies = sorted(
            {
                dependency["name"]
                for dependency in package["dependencies"]
                if dependency.get("kind") in (None, "build")
                and dependency.get("path") is not None
                and dependency["name"] in names
            }
        )
        publish = "Disabled" if package.get("publish") == [] else "Enabled"
        rows[package["name"]] = (publish, tuple(dependencies))
    return rows


def table_rows(document: str) -> list[tuple[str, str, str]]:
    if document.count(BEGIN) != 1 or document.count(END) != 1:
        raise ValueError("crate-map markers must each appear exactly once")
    _, _, rest = document.partition(BEGIN)
    body, _, _ = rest.partition(END)
    rows = []
    for line in body.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4 or cells[0] == "Package" or set(cells[0]) <= {"-"}:
            continue
        name = (
            cells[0][1:-1]
            if cells[0].startswith("`") and cells[0].endswith("`")
            else cells[0]
        )
        rows.append((name, cells[1], cells[2]))
    return rows


def diagnostic(kind: str, detail: str) -> str:
    return f"EMBEDDING_CRATE_MAP_{kind}: {detail}"


def check(document: str, metadata: dict) -> list[str]:
    errors = []
    if document.count(f"{END}\n\n{SCOPE}\n") != 1:
        errors.append(diagnostic("SCOPE", "checked-scope sentence differs"))
    try:
        rows = table_rows(document)
        expected = expected_rows(metadata)
    except ValueError as error:
        return errors + [diagnostic("SCOPE", str(error))]
    except (KeyError, TypeError) as error:
        return errors + [diagnostic("METADATA", str(error))]

    counts = Counter(name for name, _, _ in rows)
    actual = set(counts)
    for name in sorted(set(expected) - actual):
        errors.append(diagnostic("MISSING", name))
    for name in sorted(actual - set(expected)):
        errors.append(diagnostic("EXTRA", name))
    for name in sorted(name for name, count in counts.items() if count != 1):
        errors.append(diagnostic("DUPLICATE", name))

    by_name = {name: (publish, dependencies) for name, publish, dependencies in rows}
    for name in sorted(set(expected) & actual):
        if counts[name] != 1:
            continue
        publish, dependencies = by_name[name]
        expected_publish, expected_dependencies = expected[name]
        if publish != expected_publish:
            errors.append(
                diagnostic(
                    "PUBLISH",
                    f"{name} documented={publish} metadata={expected_publish}",
                )
            )
        rendered = (
            "None"
            if not expected_dependencies
            else ", ".join(f"`{dependency}`" for dependency in expected_dependencies)
        )
        if dependencies != rendered:
            errors.append(
                diagnostic(
                    "DEPS",
                    f"{name} documented=[{dependencies}] metadata=[{rendered}]",
                )
            )
    return errors


def main() -> int:
    if len(sys.argv) > 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} [EMBEDDING.md]")
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else DOCUMENT
    try:
        errors = check(path.read_text(encoding="utf-8"), cargo_metadata())
    except (OSError, RuntimeError) as error:
        errors = [diagnostic("METADATA", str(error))]
    if errors:
        print("\n".join(errors), file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
