#!/usr/bin/env python3
"""Validate front-door performance claims and receipt provenance.

The structured manifest names the performance claims that function as project
front doors.  Git proves when each measured revision first entered a release;
old evidence remains publishable only when its claim carries an exact
``measured YYYY-MM-DD`` label.  Receipt files outside the front-door manifest
are still inventoried for inbound links, but an orphan is advisory rather than
a release failure.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "perf" / "receipt-provenance.json"
WORKFLOW = ROOT / ".github" / "workflows" / "public-docs-contract.yml"
CHECKLIST = ROOT / "docs" / "RELEASE_CHECKLIST.md"
RECEIPTS_INDEX = ROOT / "docs" / "RECEIPTS.md"

FRONT_DOORS = (
    "docs/perf/README.md",
    "docs/BENCHMARKS.md",
    "docs/COMPARISON.md",
    "docs/ixp-evaluation.md",
)
RELEASE_WINDOW = 3
COMMIT = re.compile(r"[0-9a-f]{40}")
SEMVER_TAG = re.compile(r"v(\d+)\.(\d+)\.(\d+)")
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


class ContractError(ValueError):
    """A malformed manifest cannot be checked safely."""


def safe_repo_path(value: object, *, suffix: str | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"repository path must be a nonempty string, got {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or value != path.as_posix():
        raise ContractError(f"repository path is not normalized and relative: {value!r}")
    if suffix is not None and not value.endswith(suffix):
        raise ContractError(f"repository path must end in {suffix!r}: {value!r}")
    return value


def parse_manifest(text: str) -> dict[str, object]:
    try:
        manifest = json.loads(text)
    except json.JSONDecodeError as error:
        raise ContractError(f"invalid JSON at line {error.lineno}: {error.msg}") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema",
        "release_window",
        "front_doors",
        "receipts",
        "claims",
    }:
        raise ContractError(
            "manifest must contain only schema, release_window, front_doors, receipts, and claims"
        )
    if manifest["schema"] != 1:
        raise ContractError(f"manifest schema must be 1, got {manifest['schema']!r}")
    if manifest["release_window"] != RELEASE_WINDOW:
        raise ContractError(
            f"manifest release_window must be {RELEASE_WINDOW}, got {manifest['release_window']!r}"
        )
    if manifest["front_doors"] != list(FRONT_DOORS):
        raise ContractError(
            "manifest front_doors must be the exact ordered four-file contract: "
            + ", ".join(FRONT_DOORS)
        )

    raw_receipts = manifest["receipts"]
    if not isinstance(raw_receipts, list) or not raw_receipts:
        raise ContractError("manifest receipts must be a nonempty list")
    receipt_paths: list[str] = []
    for item in raw_receipts:
        if (
            not isinstance(item, dict)
            or not set(item).issubset(
                {
                    "path",
                    "measured_commit",
                    "release_commit",
                    "measured_on",
                    "source_equivalent",
                }
            )
            or not {"path", "measured_commit"}.issubset(item)
        ):
            raise ContractError(
                "each receipt must contain path and measured_commit plus only "
                "optional release_commit, measured_on, and source_equivalent"
            )
        path = safe_repo_path(item["path"], suffix=".md")
        if not path.startswith("docs/perf/") or "/artifacts/" in path:
            raise ContractError(f"manifest receipt is outside docs/perf receipts: {path}")
        receipt_paths.append(path)
        for key in ("measured_commit", "release_commit"):
            if key in item and (
                not isinstance(item[key], str) or COMMIT.fullmatch(item[key]) is None
            ):
                raise ContractError(f"{path} {key} must be a full lowercase commit SHA")
        if "source_equivalent" in item:
            if item["source_equivalent"] is not True:
                raise ContractError(f"{path} source_equivalent must be true when present")
            if "release_commit" not in item:
                raise ContractError(f"{path} source_equivalent requires release_commit")
            if item["measured_commit"] == item["release_commit"]:
                raise ContractError(
                    f"{path} source_equivalent requires distinct measured and release commits"
                )
        if "measured_on" in item:
            try:
                measured = date.fromisoformat(item["measured_on"])
            except (TypeError, ValueError) as error:
                raise ContractError(f"{path} measured_on must be an ISO date") from error
            if measured.isoformat() != item["measured_on"]:
                raise ContractError(f"{path} measured_on must be a canonical ISO date")
    if receipt_paths != sorted(set(receipt_paths)):
        raise ContractError("manifest receipts must be sorted by path and unique")

    raw_claims = manifest["claims"]
    if not isinstance(raw_claims, list) or not raw_claims:
        raise ContractError("manifest claims must be a nonempty list")
    claim_keys: list[tuple[str, str, str]] = []
    for item in raw_claims:
        if not isinstance(item, dict) or set(item) != {"source", "anchor", "receipt"}:
            raise ContractError("each claim must contain only source, anchor, and receipt")
        source = safe_repo_path(item["source"], suffix=".md")
        receipt = safe_repo_path(item["receipt"], suffix=".md")
        anchor = item["anchor"]
        if source not in FRONT_DOORS:
            raise ContractError(f"claim source is not a front door: {source}")
        if receipt not in receipt_paths:
            raise ContractError(f"claim references unmanifested receipt: {receipt}")
        if not isinstance(anchor, str) or len(anchor.strip()) < 12:
            raise ContractError(f"claim anchor must be a specific nonempty string: {anchor!r}")
        claim_keys.append((source, anchor, receipt))
    if claim_keys != sorted(set(claim_keys)):
        raise ContractError("manifest claims must be sorted by source/anchor/receipt and unique")
    sources = {source for source, _, _ in claim_keys}
    if sources != set(FRONT_DOORS):
        raise ContractError(
            "manifest claims must exercise every front door; missing "
            + ", ".join(sorted(set(FRONT_DOORS) - sources))
        )
    claimed_receipts = {receipt for _, _, receipt in claim_keys}
    if claimed_receipts != set(receipt_paths):
        raise ContractError(
            "manifest receipts and claimed receipts differ: "
            f"unclaimed={sorted(set(receipt_paths) - claimed_receipts)}"
        )
    return manifest


def git_lines(root: Path, *arguments: str) -> list[str]:
    result = subprocess.run(
        ("git", *arguments),
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ContractError(f"git {' '.join(arguments)} failed: {detail}")
    return result.stdout.splitlines()


def stable_release_tags(root: Path) -> list[tuple[tuple[int, int, int], str]]:
    tags = []
    for tag in git_lines(root, "tag", "--list"):
        match = SEMVER_TAG.fullmatch(tag)
        if match is not None:
            tags.append((tuple(int(part) for part in match.groups()), tag))
    tags.sort()
    if not tags:
        raise ContractError("repository has no stable vMAJOR.MINOR.PATCH release tags")
    return tags


def commit_tags(root: Path, commit: str) -> list[str]:
    resolved = git_lines(root, "rev-parse", "--verify", f"{commit}^{{commit}}")
    if resolved != [commit]:
        raise ContractError(f"commit {commit} did not resolve exactly")
    return git_lines(root, "tag", "--contains", commit)


def is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ("git", "merge-base", "--is-ancestor", ancestor, descendant),
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode in (0, 1):
        return result.returncode == 0
    detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
    raise ContractError(
        f"git merge-base --is-ancestor {ancestor} {descendant} failed: {detail}"
    )


def claim_block(document: str, anchor: str) -> str:
    starts = [match.start() for match in re.finditer(re.escape(anchor), document)]
    if len(starts) != 1:
        raise ContractError(f"claim anchor {anchor!r} occurs {len(starts)} times")
    position = starts[0]
    line_start = document.rfind("\n", 0, position) + 1
    line_end = document.find("\n", position)
    line_end = len(document) if line_end < 0 else line_end
    line = document[line_start:line_end]
    if line.startswith("|"):
        return line
    if line.startswith("- "):
        next_item = re.search(r"(?m)^- ", document[line_end + 1 :])
        end = len(document) if next_item is None else line_end + 1 + next_item.start()
        return document[line_start:end]
    paragraph_end = re.search(r"\n\s*\n", document[line_start:])
    end = len(document) if paragraph_end is None else line_start + paragraph_end.start()
    return document[line_start:end]


def resolved_receipt_links(root: Path, source: str, block: str) -> set[str]:
    resolved: set[str] = set()
    source_dir = (root / source).parent
    for raw_target in MARKDOWN_LINK.findall(block):
        target = unquote(urlsplit(raw_target.strip().split()[0]).path)
        if not target or target.startswith("/"):
            continue
        try:
            path = (source_dir / target).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            continue
        if path.startswith("docs/perf/") and path.endswith(".md"):
            resolved.add(path)
    return resolved


def contract_text(root: Path, relative: str, overrides: dict[str, str] | None = None) -> str:
    if overrides is not None and relative in overrides:
        return overrides[relative]
    return (root / relative).read_text(encoding="utf-8")


def check_house_contract(
    root: Path, errors: list[str], overrides: dict[str, str] | None = None
) -> None:
    expected = {
        root / WORKFLOW.relative_to(ROOT): (
            "fetch-depth: 0",
            "python3 -m unittest -v scripts/test_check_perf_receipt_freshness.py",
            "python3 scripts/check_perf_receipt_freshness.py",
        ),
        root / CHECKLIST.relative_to(ROOT): (
            "docs/perf/receipt-provenance.json",
            *FRONT_DOORS,
        ),
        root / RECEIPTS_INDEX.relative_to(ROOT): (
            "perf/receipt-provenance.json",
            "../scripts/check_perf_receipt_freshness.py",
        ),
    }
    for path, fragments in expected.items():
        relative = path.relative_to(root).as_posix()
        try:
            text = contract_text(root, relative, overrides)
        except OSError as error:
            errors.append(f"cannot read house-contract file {relative}: {error}")
            continue
        for fragment in fragments:
            count = text.count(fragment)
            if path == root / WORKFLOW.relative_to(ROOT) and count != 1:
                errors.append(
                    f"{path.relative_to(root)} must contain {fragment!r} exactly once, "
                    f"found {count}"
                )
            elif path != root / WORKFLOW.relative_to(ROOT) and count == 0:
                errors.append(
                    f"{path.relative_to(root)} must contain required fragment {fragment!r}"
                )


def check_contract(
    root: Path,
    manifest: dict[str, object],
    overrides: dict[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    check_house_contract(root, errors, overrides)
    try:
        releases = stable_release_tags(root)
    except ContractError as error:
        return errors + [str(error)]
    release_names = [name for _, name in releases]
    current_release = release_names[-1]

    receipt_by_path = {item["path"]: item for item in manifest["receipts"]}
    release_ages: dict[str, int] = {}
    for path, item in receipt_by_path.items():
        try:
            receipt = contract_text(root, path, overrides)
        except OSError as error:
            errors.append(f"cannot read manifested receipt {path}: {error}")
            continue
        measured_commit = item["measured_commit"]
        for key in ("measured_commit", "release_commit"):
            commit = item.get(key)
            if commit is not None and commit not in receipt and commit[:8] not in receipt:
                errors.append(f"{path} does not record its manifested {key} {commit}")
        try:
            measured_tags = commit_tags(root, measured_commit)
        except ContractError as error:
            errors.append(f"{path}: {error}")
            continue
        # An explicitly source-equivalent measurement may live past the tagged
        # release commit; its distinct release_commit still must resolve to a
        # stable tag below. Ordinary untagged measurements remain invalid.
        if not measured_tags and not item.get("source_equivalent", False):
            errors.append(f"{path} measured commit {measured_commit} is contained by no git tag")
        release_commit = item.get("release_commit", measured_commit)
        try:
            release_tags = set(commit_tags(root, release_commit))
        except ContractError as error:
            errors.append(f"{path}: {error}")
            continue
        containing = [tag for tag in release_names if tag in release_tags]
        if not containing:
            errors.append(
                f"{path} release commit {release_commit} is contained by no stable release tag"
            )
            continue
        if item.get("source_equivalent", False):
            try:
                release_is_ancestor = is_ancestor(root, release_commit, measured_commit)
            except ContractError as error:
                errors.append(f"{path}: {error}")
                continue
            if not release_is_ancestor:
                errors.append(
                    f"{path} source-equivalent release commit {release_commit} "
                    f"is not an ancestor of measured commit {measured_commit}"
                )
                continue
        first_release = containing[0]
        release_ages[path] = release_names.index(current_release) - release_names.index(
            first_release
        )

    documents: dict[str, str] = {}
    for source in FRONT_DOORS:
        try:
            documents[source] = contract_text(root, source, overrides)
        except OSError as error:
            errors.append(f"cannot read front door {source}: {error}")

    claims_by_block: dict[tuple[str, str], set[str]] = {}
    for claim in manifest["claims"]:
        claims_by_block.setdefault((claim["source"], claim["anchor"]), set()).add(claim["receipt"])
    for (source, anchor), expected_receipts in claims_by_block.items():
        if source not in documents:
            continue
        try:
            block = claim_block(documents[source], anchor)
        except ContractError as error:
            errors.append(f"{source}: {error}")
            continue
        actual_receipts = resolved_receipt_links(root, source, block)
        if actual_receipts != expected_receipts:
            errors.append(
                f"{source} claim {anchor!r} receipt links differ from its manifest: "
                f"actual={sorted(actual_receipts)} expected={sorted(expected_receipts)}"
            )
        for receipt in expected_receipts:
            age = release_ages.get(receipt)
            # Age counts stable-release transitions after first containment:
            # the containing release plus three later lines remains current,
            # and the fourth transition requires an exact measured-on date.
            if age is None or age <= RELEASE_WINDOW:
                continue
            measured_on = receipt_by_path[receipt].get("measured_on")
            if measured_on is None:
                errors.append(
                    f"{source} stale claim for {receipt} has no manifested measured_on date"
                )
                continue
            phrase = f"measured {measured_on}"
            if phrase not in block:
                errors.append(
                    f"{source} stale claim for {receipt} must carry exact phrase {phrase!r}"
                )
    return errors


def tracked_markdown(root: Path) -> list[Path]:
    result = subprocess.run(
        ("git", "ls-files", "-z", "--", "*.md"),
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip() or f"exit {result.returncode}"
        raise ContractError(f"git ls-files for Markdown failed: {detail}")
    return [root / value.decode() for value in result.stdout.split(b"\0") if value]


def unlinked_receipts(root: Path) -> list[str]:
    receipts = {
        path.resolve(): path.relative_to(root).as_posix()
        for path in (root / "docs" / "perf").glob("*.md")
    }
    inbound = {path: 0 for path in receipts}
    for source in tracked_markdown(root):
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as error:
            raise ContractError(f"cannot read tracked Markdown {source.relative_to(root)}: {error}")
        for raw_target in MARKDOWN_LINK.findall(text):
            target = unquote(urlsplit(raw_target.strip().split()[0]).path)
            if not target or target.startswith("/"):
                continue
            resolved = (source.parent / target).resolve()
            if resolved in inbound and resolved != source.resolve():
                inbound[resolved] += 1
    return sorted(receipts[path] for path, count in inbound.items() if count == 0)


def main() -> int:
    try:
        manifest = parse_manifest(MANIFEST.read_text(encoding="utf-8"))
        errors = check_contract(ROOT, manifest)
        orphans = unlinked_receipts(ROOT)
    except (OSError, ContractError) as error:
        errors = [str(error)]
        orphans = []
    for error in errors:
        print(f"performance receipt integrity check failed: {error}", file=sys.stderr)
    for path in orphans:
        print(f"performance receipt advisory: no inbound Markdown link to {path}")
    if not errors:
        print(
            "performance receipt integrity check passed: "
            f"{len(orphans)} unlinked receipt(s) reported"
        )
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
