#!/usr/bin/env python3
"""Fail closed when the IXP Manager documentation drifts from its contract.

Five documents restate facts that `tests/compat/ixp-manager-birdseye/contract.json`
pins executably, and each has drifted silently before:

- the Birdwatcher adapter README's reason-id tables versus
  `reject_reasons.active_ids` / `defined_only_ids` / `fallback_id` / `display`;
- the same README's capability table versus `runtime_supported` / `unsupported`;
- `docs/INTEROP.md`, which defines the IXP Manager M-series receipt claims;
- `docs/RECEIPTS.md`, `docs/OPERATIONAL_PROOF.md`, and `docs/milestones.md`,
  which must each carry a row for every M-series receipt that
  `docs/INTEROP.md` claims in its IXP Manager sections.

The checks parse the markdown tables positively; an absent table or an empty
M-number set is itself a failure, because a guard that cannot fail is worse
than no guard.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "tests" / "compat" / "ixp-manager-birdseye" / "contract.json"
README = ROOT / "examples" / "birdwatcher-adapter" / "README.md"
INTEROP = ROOT / "docs" / "INTEROP.md"
RECEIPTS = ROOT / "docs" / "RECEIPTS.md"
PROOF = ROOT / "docs" / "OPERATIONAL_PROOF.md"
MILESTONES = ROOT / "docs" / "milestones.md"

REASON_HEADER = ("Retained cause", "IXP Manager reason id", "Bird's Eye display")
DEFINED_ONLY_HEADER = ("Defined-only id", "Bird's Eye display", "Emitted as")
CAPABILITY_HEADER = ("Contract capability", "Status", "Adapter surface")
M_NUMBER = re.compile(r"\bM\d+[a-z]?\b")
HEADING = re.compile(r"^(#+)\s+(.*)$")


def _cells(line: str) -> tuple[str, ...]:
    return tuple(cell.strip() for cell in line.strip().strip("|").split("|"))


def table_rows(document: str, header: tuple[str, ...]) -> list[tuple[str, ...]] | None:
    """Body rows of the one markdown table whose header row is `header`."""
    lines = document.splitlines()
    starts = [i for i, line in enumerate(lines) if _cells(line) == header]
    if len(starts) != 1:
        return None
    rows: list[tuple[str, ...]] = []
    for line in lines[starts[0] + 2 :]:  # skip the |---| separator
        if not line.lstrip().startswith("|"):
            break
        rows.append(_cells(line))
    return rows


def check_reason_ids(readme: str, contract: dict) -> list[str]:
    reasons = contract["reject_reasons"]
    display = {int(k): v for k, v in reasons["display"].items()}
    active = set(reasons["active_ids"])
    defined_only = set(reasons["defined_only_ids"])
    fallback = reasons["fallback_id"]
    errors: list[str] = []

    rows = table_rows(readme, REASON_HEADER)
    if rows is None:
        return [f"README reason-id table with header {REASON_HEADER} not found exactly once"]
    seen: dict[int, str] = {}
    for row in rows:
        if len(row) != 3 or not row[1].isdigit():
            errors.append(f"README reason-id row is malformed: {row}")
            continue
        seen[int(row[1])] = row[2]
    if fallback not in seen:
        errors.append(f"README reason-id table has no fallback row for id {fallback}")
    tabulated = set(seen) - {fallback}
    if tabulated != active:
        errors.append(
            "README reason-id table ids do not match contract active_ids: "
            f"table={sorted(tabulated)} contract={sorted(active)}"
        )
    for reason_id in sorted(tabulated & active):
        if seen[reason_id] != display[reason_id]:
            errors.append(
                f"README reason id {reason_id} displays {seen[reason_id]!r}, "
                f"contract says {display[reason_id]!r}"
            )

    rows = table_rows(readme, DEFINED_ONLY_HEADER)
    if rows is None:
        return errors + [
            f"README defined-only table with header {DEFINED_ONLY_HEADER} not found exactly once"
        ]
    seen = {}
    for row in rows:
        if len(row) != 3 or not row[0].isdigit() or not row[2].isdigit():
            errors.append(f"README defined-only row is malformed: {row}")
            continue
        seen[int(row[0])] = row[1]
        if int(row[2]) != fallback:
            errors.append(f"README defined-only id {row[0]} is emitted as {row[2]}, not {fallback}")
    if set(seen) != defined_only:
        errors.append(
            "README defined-only table ids do not match contract defined_only_ids: "
            f"table={sorted(seen)} contract={sorted(defined_only)}"
        )
    for reason_id in sorted(set(seen) & defined_only):
        if seen[reason_id] != display[reason_id]:
            errors.append(
                f"README defined-only id {reason_id} displays {seen[reason_id]!r}, "
                f"contract says {display[reason_id]!r}"
            )
    return errors


def check_capabilities(readme: str, contract: dict) -> list[str]:
    rows = table_rows(readme, CAPABILITY_HEADER)
    if rows is None:
        return [f"README capability table with header {CAPABILITY_HEADER} not found exactly once"]
    errors: list[str] = []
    status: dict[str, str] = {}
    for row in rows:
        if len(row) != 3 or not (row[0].startswith("`") and row[0].endswith("`")):
            errors.append(f"README capability row is malformed: {row}")
            continue
        if row[1] not in ("supported", "unsupported"):
            errors.append(f"README capability {row[0]} has unknown status {row[1]!r}")
            continue
        status[row[0].strip("`")] = row[1]
    for key, expected in (("runtime_supported", "supported"), ("unsupported", "unsupported")):
        contract_set = set(contract[key])
        table_set = {slug for slug, value in status.items() if value == expected}
        if table_set != contract_set:
            errors.append(
                f"README capabilities marked {expected} do not match contract {key}: "
                f"table={sorted(table_set)} contract={sorted(contract_set)}"
            )
    return errors


def interop_ixp_receipts(interop: str) -> set[str]:
    """M-numbers claimed inside INTEROP.md's IXP Manager headings and CI bullets."""
    found: set[str] = set()
    level = None
    for line in interop.splitlines():
        heading = HEADING.match(line)
        if heading:
            depth = len(heading.group(1))
            if level is not None and depth <= level:
                level = None
            if "ixp" in heading.group(2).lower():
                level = depth
                continue
        if level is not None or line.lstrip().startswith("- **IXP"):
            found.update(M_NUMBER.findall(line))
    return found


def receipt_rows(receipts: str, header: str = "Receipt") -> set[str]:
    """M-numbers in the first cell of every `| <header> | ... |` table row."""
    found: set[str] = set()
    in_table = False
    for line in receipts.splitlines():
        if not line.lstrip().startswith("|"):
            in_table = False
            continue
        first = _cells(line)[0]
        if first == header:
            in_table = True
        elif in_table:
            found.update(M_NUMBER.findall(first))
    return found


def check_receipts(interop: str, receipts: str, proof: str, milestones: str) -> list[str]:
    claimed = interop_ixp_receipts(interop)
    if not claimed:
        return ["INTEROP.md IXP Manager sections name no M-series receipts; the walk is broken"]
    errors: list[str] = []
    # OPERATIONAL_PROOF.md keys its compact index by `| Receipts | Coverage |`.
    for name, rows in (
        ("RECEIPTS.md", receipt_rows(receipts)),
        ("OPERATIONAL_PROOF.md", receipt_rows(proof, "Receipts")),
        ("milestones.md", receipt_rows(milestones, "ID")),
    ):
        for m in sorted(claimed - rows, key=lambda m: (len(m), m)):
            errors.append(
                f"INTEROP.md claims {m} in its IXP Manager sections but {name} has no row for it"
            )
    return errors


def check(
    readme: str,
    contract: dict,
    interop: str,
    receipts: str,
    proof: str,
    milestones: str,
) -> list[str]:
    return (
        check_reason_ids(readme, contract)
        + check_capabilities(readme, contract)
        + check_receipts(interop, receipts, proof, milestones)
    )


def main() -> int:
    try:
        errors = check(
            README.read_text(encoding="utf-8"),
            json.loads(CONTRACT.read_text(encoding="utf-8")),
            INTEROP.read_text(encoding="utf-8"),
            RECEIPTS.read_text(encoding="utf-8"),
            PROOF.read_text(encoding="utf-8"),
            MILESTONES.read_text(encoding="utf-8"),
        )
    except (OSError, KeyError, ValueError) as error:
        errors = [f"cannot load the IXP Manager contract surface: {error!r}"]
    for error in errors:
        print(f"IXP Manager docs check failed: {error}", file=sys.stderr)
    if not errors:
        print("IXP Manager docs check passed")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
