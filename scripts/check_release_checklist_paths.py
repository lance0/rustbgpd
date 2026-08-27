#!/usr/bin/env python3
"""Validate release-checklist paths and source-to-proof trigger ownership.

A trigger list that names a path which no longer exists never fires: the
release gate it guards silently passes. This extracts every path-shaped
token from the document -- backticked prose paths in the trigger lists, and
bare paths inside the fenced reproduction blocks -- and checks each against
the working tree. Bare tokens are read only inside fenced code blocks, so
prose such as "docs/test improvements" is not mistaken for a path.

Path existence alone cannot catch an owner that is absent from the trigger
list or points at the wrong proof. The two release-proof tables therefore
carry a small, machine-checked semantic contract for the cross-module EVPN
Ethernet Segment owners whose regressions require M38, M66, and/or M67.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOTS = (
    r"(?:src|crates|tests|docs|scripts|bench|examples|proto|tools|share|"
    r"\.cargo|\.github|fuzz)"
)
GENERATED_PATH_PREFIX_SOURCES = {"share/systemd/": "examples/systemd/"}
BACKTICKED = re.compile(r"`([^`\s]+)`")
BARE = re.compile(rf"(?<![\w/`.-])({ROOTS}/[\w./-]*[\w/])")
IS_PATH = re.compile(rf"^{ROOTS}/")
REPOSITORY_PATH = re.compile(rf"^{ROOTS}/[\w./-]*[\w/]$")

DOCUMENT = Path("docs") / "RELEASE_CHECKLIST.md"
OWNER_PROOF_HEADER = "| Source owner | Required release proofs |"
PROOF_SOURCE_HEADER = "| Release proof | Topology | Assertion script |"

# Keep this deliberately narrow: these daemon owners cross the DF-election,
# operator-drain, and link-drain proof boundaries. Adding a new owner or proof
# is a reviewable change to both the checklist and this contract, rather than a
# heuristic inferred from prose.
REQUIRED_OWNER_PROOFS = {
    "src/evpn_es_drain.rs": frozenset({"M66", "M67"}),
    "src/evpn_es_link_drain.rs": frozenset({"M67"}),
    "src/evpn_segment.rs": frozenset({"M38", "M66", "M67"}),
}
REQUIRED_PROOF_SOURCES = {
    "M38": (
        "tests/interop/m38-evpn-df-election.clab.yml",
        "tests/interop/scripts/test-m38-evpn-df-election.sh",
    ),
    "M66": (
        "tests/interop/m66-evpn-es-drain-handover.clab.yml",
        "tests/interop/scripts/test-m66-evpn-es-drain-handover.sh",
    ),
    "M67": (
        "tests/interop/m67-evpn-link-drain-failover.clab.yml",
        "tests/interop/scripts/test-m67-evpn-link-drain-failover.sh",
    ),
}
PROOF_ID = re.compile(r"\bM\d+\b")
PROOF_LIST = re.compile(r"M\d+(?:,\s*M\d+)*")


def named_paths(document: str) -> dict[str, list[int]]:
    """Map each recognized repository-source path to its document lines."""
    found: dict[str, list[int]] = {}
    in_fence = False
    for number, line in enumerate(document.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        tokens = [match.group(1) for match in BACKTICKED.finditer(line)]
        if in_fence:
            tokens += [match.group(1) for match in BARE.finditer(line)]
        for token in tokens:
            if IS_PATH.match(token):
                source = token
                for (
                    generated,
                    repository_source,
                ) in GENERATED_PATH_PREFIX_SOURCES.items():
                    if token.startswith(generated):
                        source = repository_source + token.removeprefix(generated)
                        break
                found.setdefault(source, []).append(number)
    return found


def table_rows(
    document: str, header: str, columns: int
) -> tuple[list[tuple[int, list[str]]], list[str]]:
    """Return rows from the one Markdown table introduced by `header`."""
    lines = document.splitlines()
    matches = [index for index, line in enumerate(lines) if line.strip() == header]
    if len(matches) != 1:
        return [], [
            f"{DOCUMENT.as_posix()} must contain exactly one `{header}` table "
            f"header; found {len(matches)}"
        ]

    header_index = matches[0]
    if header_index + 1 >= len(lines) or not re.fullmatch(
        rf"\|(?:\s*:?-+:?\s*\|){{{columns}}}", lines[header_index + 1].strip()
    ):
        return [], [
            f"{DOCUMENT.as_posix()}:{header_index + 2} has a malformed separator "
            f"for the `{header}` table"
        ]

    rows = []
    for index in range(header_index + 2, len(lines)):
        line = lines[index].strip()
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != columns:
            return [], [
                f"{DOCUMENT.as_posix()}:{index + 1} has {len(cells)} columns in "
                f"the `{header}` table; expected {columns}"
            ]
        rows.append((index + 1, cells))
    if not rows:
        return [], [
            f"{DOCUMENT.as_posix()}:{header_index + 1} has no rows under "
            f"the `{header}` table"
        ]
    return rows, []


def release_proof_errors(document: str) -> list[str]:
    """Validate the checklist's semantic owner-to-proof contract."""
    owner_rows, errors = table_rows(document, OWNER_PROOF_HEADER, 2)
    proof_rows, proof_errors = table_rows(document, PROOF_SOURCE_HEADER, 3)
    errors.extend(proof_errors)
    if errors:
        return errors

    owner_proofs: dict[str, tuple[int, frozenset[str]]] = {}
    for line, cells in owner_rows:
        owner_match = re.fullmatch(r"`([^`]+)`", cells[0])
        proofs = frozenset(PROOF_ID.findall(cells[1]))
        if owner_match is None or not REPOSITORY_PATH.fullmatch(
            owner_match.group(1)
        ):
            errors.append(
                f"{DOCUMENT.as_posix()}:{line} release-proof owner must be one "
                "backticked repository-source path"
            )
            continue
        owner = owner_match.group(1)
        if not PROOF_LIST.fullmatch(cells[1]):
            errors.append(
                f"{DOCUMENT.as_posix()}:{line} release-proof owner `{owner}` "
                "must use a comma-separated M-number proof list"
            )
        if owner in owner_proofs:
            errors.append(
                f"{DOCUMENT.as_posix()}:{line} duplicates release-proof owner `{owner}`"
            )
            continue
        owner_proofs[owner] = (line, proofs)

    proof_sources: dict[str, tuple[int, tuple[str, str]]] = {}
    for line, cells in proof_rows:
        proof_match = re.fullmatch(r"`(M\d+)`", cells[0])
        topology_match = re.fullmatch(r"`([^`]+)`", cells[1])
        script_match = re.fullmatch(r"`([^`]+)`", cells[2])
        if (
            proof_match is None
            or topology_match is None
            or script_match is None
            or not REPOSITORY_PATH.fullmatch(topology_match.group(1))
            or not REPOSITORY_PATH.fullmatch(script_match.group(1))
        ):
            errors.append(
                f"{DOCUMENT.as_posix()}:{line} proof-source rows require a "
                "backticked M-number, topology path, and assertion-script path"
            )
            continue
        proof = proof_match.group(1)
        if proof in proof_sources:
            errors.append(
                f"{DOCUMENT.as_posix()}:{line} duplicates release proof `{proof}`"
            )
            continue
        proof_sources[proof] = (
            line,
            (topology_match.group(1), script_match.group(1)),
        )

    for owner, required in REQUIRED_OWNER_PROOFS.items():
        mapping = owner_proofs.get(owner)
        if mapping is None:
            errors.append(
                f"{DOCUMENT.as_posix()} is missing required release-proof owner "
                f"mapping for `{owner}`"
            )
            continue
        line, actual = mapping
        missing = sorted(required - actual)
        if missing:
            errors.append(
                f"{DOCUMENT.as_posix()}:{line} release-proof owner `{owner}` is "
                f"missing required proofs: {', '.join(missing)}"
            )

    referenced_proofs = set().union(
        *(proofs for _, proofs in owner_proofs.values())
    )
    for proof in sorted(referenced_proofs):
        if proof not in proof_sources:
            errors.append(
                f"{DOCUMENT.as_posix()} release-proof owner mapping references "
                f"`{proof}` without a proof-source row"
            )

    for proof, required_sources in REQUIRED_PROOF_SOURCES.items():
        source_mapping = proof_sources.get(proof)
        if source_mapping is None:
            errors.append(
                f"{DOCUMENT.as_posix()} is missing required proof-source mapping "
                f"for `{proof}`"
            )
            continue
        line, actual_sources = source_mapping
        if actual_sources != required_sources:
            errors.append(
                f"{DOCUMENT.as_posix()}:{line} proof-source mapping for `{proof}` "
                f"must be `{required_sources[0]}` and `{required_sources[1]}`"
            )

    return errors


def check(root: Path) -> tuple[int, list[str]]:
    """Return (paths checked, errors) for the checklist under `root`."""
    document = (root / DOCUMENT).read_text(encoding="utf-8")
    found = named_paths(document)
    if not found:
        return 0, [
            f"no paths were extracted from {DOCUMENT.as_posix()}, "
            "so the parse is broken"
        ]
    errors = release_proof_errors(document)
    for token, lines in sorted(found.items()):
        if not (root / token.rstrip("/")).exists():
            where = ",".join(str(number) for number in lines)
            errors.append(
                f"{DOCUMENT.as_posix()}:{where} resolves to `{token}`, which does "
                "not exist in the tree; the gate it triggers can never fire"
            )
    return len(found), errors


def main() -> int:
    if len(sys.argv) > 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} [REPO_ROOT]")
    default = Path(__file__).resolve().parents[1]
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else default
    checked, errors = check(root)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"release checklist path check passed: validated {checked} recognized "
        "repository-source path tokens"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
