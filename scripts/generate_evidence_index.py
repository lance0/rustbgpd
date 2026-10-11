#!/usr/bin/env python3
"""Generate the capability table, curated interop leg index and lab index.

Sources: the `capabilities` section of docs/reference/v1-stable-surface.json,
the `# leg:` headers of curated interop drivers, and the `# lab:` headers of
labs/*/lab.sh. `--check` (the default) fails when a generated output is stale;
`--write` regenerates them.

A driver joins the curated index by carrying a header directly after its
shebang; drivers without one are outside the index, not unproven:

    # leg: m14  slug: route-reflector
    # proves: <bounded scope of the dated evidence>
    # claims: <behavior keys, from CLAIM_KEYS>
    # evidence: <repo path>[#<heading anchor>]
    # pinned: <peer versions and date of that evidence>
    #

The leg key is the driver basename without `test-` and `.sh`, so two drivers
under one M-number stay separate legs. Every lab must carry
`# lab: <directory>  slug: <slug>` and `# summary: ...`, ended the same way.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = "docs/reference/v1-stable-surface.json"
CAPABILITIES_OUT = "docs/reference/capabilities.md"
LABS_OUT = "labs/README.md"
INTEROP_DOC = "docs/interop.md"
DRIVERS = "tests/interop/scripts"
BEGIN = "<!-- BEGIN GENERATED: scripts/generate_evidence_index.py -->"
END = "<!-- END GENERATED -->"
# Behavior observed by a leg's dated evidence. Not a maturity ladder, and
# deliberately without `stable`: compatibility comes from the inventory.
CLAIM_KEYS = ("encoded", "stored", "selected", "advertised")
SLUG = r"[a-z0-9]+(?:-[a-z0-9]+)*"
LEG_HEAD = re.compile(rf"# leg: (m\d+[a-z]?)  slug: ({SLUG})")
LAB_HEAD = re.compile(rf"# lab: ({SLUG})  slug: ({SLUG})")
FIELD = re.compile(r"# ([a-z]+): (\S.*)")
LEG_FIELDS = {"proves", "claims", "evidence", "pinned"}
LAB_FIELDS = {"summary"}


class MetadataError(ValueError):
    pass


def read_header(path: Path, head: re.Pattern, prefix: str, fields: set[str]):
    lines = path.read_text().splitlines()
    if len(lines) < 2 or not lines[1].startswith(prefix):
        return None
    name = f"{path.parent.name}/{path.name}"
    match = head.fullmatch(lines[1])
    if not match:
        raise MetadataError(f"{name}: malformed header line {lines[1]!r}")
    record = {}
    for line in lines[2:]:
        if line == "#":
            break
        field = FIELD.fullmatch(line)
        if not field or field[1] not in fields:
            raise MetadataError(
                f"{name}: header line {line!r} is not one of {sorted(fields)}; "
                "end the header with a bare '#' line"
            )
        if field[1] in record:
            raise MetadataError(f"{name}: duplicate header key {field[1]!r}")
        record[field[1]] = field[2].strip()
    else:
        raise MetadataError(f"{name}: header is not ended by a bare '#' line")
    missing = fields - record.keys()
    if missing:
        raise MetadataError(f"{name}: header is missing {sorted(missing)}")
    return match, record


def heading_anchors(path: Path) -> set[str]:
    anchors, seen, fenced = set(), {}, False
    for line in path.read_text().splitlines():
        if line.startswith("```"):
            fenced = not fenced
        heading = None if fenced else re.match(r"#{1,6} (.+)", line)
        if heading:
            slug = re.sub(r"[^\w\- ]", "", heading[1].strip().lower()).replace(" ", "-")
            count = seen.get(slug, 0)
            seen[slug] = count + 1
            anchors.add(slug if count == 0 else f"{slug}-{count}")
    return anchors


def check_reference(root: Path, reference: str, label: str) -> None:
    path, _, anchor = reference.partition("#")
    parts = PurePosixPath(path)
    if parts.is_absolute() or ".." in parts.parts or not (root / parts).is_file():
        raise MetadataError(f"{label}: evidence {path!r} is not a file in the repository")
    if anchor and anchor not in heading_anchors(root / parts):
        raise MetadataError(f"{label}: evidence anchor #{anchor} is not a heading of {path}")


def load_legs(root: Path) -> dict[str, dict]:
    legs = {}
    for path in sorted((root / DRIVERS).glob("test-m*.sh")):
        parsed = read_header(path, LEG_HEAD, "# leg", LEG_FIELDS)
        if parsed is None:
            continue
        match, record = parsed
        key = path.name.removeprefix("test-").removesuffix(".sh")
        if not key.startswith(f"{match[1]}-"):
            raise MetadataError(f"{path.name}: header names {match[1]} but the driver is {key}")
        claims = record["claims"].split()
        if len(claims) != len(set(claims)) or not set(claims) <= set(CLAIM_KEYS):
            raise MetadataError(
                f"{path.name}: claims {claims} must be distinct keys from {list(CLAIM_KEYS)}"
            )
        topology = re.search(r'^TOPO="([^"]+)"$', path.read_text(), re.MULTILINE)
        if not topology or not (root / f"tests/interop/{topology[1]}.clab.yml").is_file():
            raise MetadataError(f"{path.name}: TOPO does not name a tests/interop/*.clab.yml")
        check_reference(root, record["evidence"], path.name)
        legs[key] = record | {
            "slug": match[2],
            "claims": claims,
            "driver": path.relative_to(root).as_posix(),
            "topology": f"tests/interop/{topology[1]}.clab.yml",
        }
    return legs


def load_labs(root: Path) -> dict[str, dict]:
    labs, slugs = {}, {}
    for path in sorted((root / "labs").glob("*/lab.sh")):
        parsed = read_header(path, LAB_HEAD, "# lab", LAB_FIELDS)
        name = path.parent.name
        if parsed is None:
            raise MetadataError(f"labs/{name}/lab.sh has no '# lab:' header")
        match, record = parsed
        if match[1] != name:
            raise MetadataError(f"labs/{name}/lab.sh header names lab {match[1]!r}")
        if match[2] in slugs:
            raise MetadataError(f"labs {slugs[match[2]]} and {name} both claim slug {match[2]!r}")
        slugs[match[2]] = name
        labs[name] = record | {"slug": match[2]}
    recipe = re.search(r"^\s+([a-z|-]+)\) exec bash \"labs/", (root / "justfile").read_text(), re.M)
    if not recipe or sorted(recipe[1].split("|")) != sorted(labs):
        raise MetadataError(f"justfile lab names do not match labs/*/lab.sh {sorted(labs)}")
    return labs


def surface_classification(inventory: dict, surface: str) -> str | None:
    grpc, config = inventory["grpc"], inventory["config"]
    head, _, tail = surface.partition(".")
    if head.endswith("Service"):
        for key, label in (("stable_method_sets", "stable"),
                           ("scoped_rr_only_method_sets", "scoped_rr_only")):
            if any(s["service"] == head and tail in s["methods"] for s in grpc[key]):
                return label
        if {surface, head} & set(grpc["explicitly_outside_v1"]):
            return "outside_v1"
        return None
    for entry in config["explicitly_unstable_roots"]:
        if entry["path"] == surface:
            return entry["classification"]
    if any(s["definition"] == head and tail in s["fields"] for s in config["stable_fields"]):
        return "stable"
    return None


def cell(text: str) -> str:
    return text.replace("|", "\\|")


def link(text: str, target: str, source: str) -> str:
    path, _, anchor = target.partition("#")
    relative = os.path.relpath(path, os.path.dirname(source))
    return f"[{text}]({relative}{'#' + anchor if anchor else ''})"


def ordered(claims: list[str]) -> str:
    return ", ".join(f"`{key}`" for key in CLAIM_KEYS if key in claims)


def header(source: str) -> str:
    return (
        f"<!-- Generated by scripts/generate_evidence_index.py from {source}. "
        "Do not edit by hand; run `python3 scripts/generate_evidence_index.py --write`. -->"
    )


def render_capabilities(inventory: dict, legs: dict) -> str:
    out = CAPABILITIES_OUT
    roles = {role["id"]: role["classification"] for role in inventory["roles"]}
    rows = []
    for row in inventory["capabilities"]["rows"]:
        evidence, recipes, behavior = [], [], []
        for item in row["evidence"]:
            leg = legs.get(item["leg"])
            if leg is None:
                raise MetadataError(f"capability {row['id']}: unknown leg {item['leg']!r}")
            behavior.append(f"{ordered(item['claims'])} (`{item['leg']}`)")
            evidence.append(f"{link(item['leg'], leg['evidence'], out)}: {leg['pinned']}")
            recipes.append(
                f"{link(Path(leg['driver']).name, leg['driver'], out)} on "
                f"{link(Path(leg['topology']).name, leg['topology'], out)}"
            )
        compatibility = [f"role `{r}`: {roles[r]}" for r in row["roles"]]
        for surface in row["surfaces"]:
            classification = surface_classification(inventory, surface)
            if classification is None:
                raise MetadataError(f"capability {row['id']}: {surface} is not inventoried")
            compatibility.append(f"`{surface}`: {classification}")
        rows.append(" | ".join([
            f"`{row['id']}`",
            cell(row["scope"]),
            cell(", ".join(row["excludes"])),
            "<br>".join(behavior),
            cell("<br>".join(evidence)),
            "<br>".join(recipes),
            "<br>".join(compatibility) or "none inventoried",
        ]))
    return "\n".join([
        "# Capability evidence",
        "",
        header(f"the capabilities section of {INVENTORY} and interop driver headers"),
        "",
        "This table connects a few scoped capabilities to the interop evidence behind them.",
        "It is navigation, not a promotion mechanism: compatibility comes only from the",
        "roles and inventoried surfaces in [`v1-stable-surface.json`](v1-stable-surface.json),",
        "explained in [Stability and compatibility](stability.md). A capability absent",
        "from this table is not cataloged; that does not make it unsupported.",
        "",
        "Behavior keys name what the dated evidence observed: `encoded`, `stored`,",
        "`selected`, and `advertised`. They are independent facts, not a maturity",
        "ladder. Pinned evidence is the historical run that established the claim; the",
        "current recipe is today's driver and topology, whose image pins may be newer.",
        "",
        "| Capability | Scope | Not covered | Observed behavior | Pinned evidence | Current recipe | Compatibility |",
        "|---|---|---|---|---|---|---|",
        *[f"| {row} |" for row in rows],
        "",
    ])


def render_leg_index(legs: dict) -> str:
    rows = [
        f"| `{key}` | `{leg['slug']}` | {cell(leg['proves'])} | {ordered(leg['claims'])} | "
        f"{link('dated evidence', leg['evidence'], INTEROP_DOC)}: {cell(leg['pinned'])} | "
        f"{link(Path(leg['driver']).name, leg['driver'], INTEROP_DOC)} on "
        f"{link(Path(leg['topology']).name, leg['topology'], INTEROP_DOC)} |"
        for key, leg in legs.items()
    ]
    return "\n".join([
        BEGIN,
        header("interop driver headers"),
        "",
        "A curated subset of legs with a reviewed driver header. Drivers without",
        "one are outside this index, not unproven. Each slug is a navigation name",
        "shared with its cookbook page and operator lab; the leg key stays the",
        "driver's M-series identity. Pinned evidence is historical; the current",
        "driver and topology may pin newer images.",
        "",
        "| Leg | Slug | Proves | Behavior keys | Pinned evidence | Current recipe |",
        "|---|---|---|---|---|---|",
        *rows,
        END,
    ])


def render_labs(root: Path, labs: dict, legs: dict) -> str:
    rows = []
    for name, lab in labs.items():
        cookbook = f"docs/cookbook/{lab['slug']}.md"
        related = [
            link(f"`{key}`", leg["driver"], LABS_OUT)
            for key, leg in legs.items() if leg["slug"] == lab["slug"]
        ]
        rows.append(
            f"| `just lab {name}` | `{lab['slug']}` | {cell(lab['summary'])} | "
            f"{link(lab['slug'], cookbook, LABS_OUT) if (root / cookbook).is_file() else 'none'} | "
            f"{', '.join(related) or 'none indexed'} |"
        )
    return "\n".join([
        "# Operator labs",
        "",
        header("labs/*/lab.sh and interop driver headers"),
        "",
        "Each lab runs with `just lab <name> up|verify|break|explain|down`; the",
        f"walkthrough is {link('Operator labs', 'docs/tutorials/operator-labs.md', LABS_OUT)}.",
        "The slug is the shared navigation name for the lab, its cookbook page, and",
        f"the {link('curated interop legs', INTEROP_DOC + '#curated-leg-index', LABS_OUT)}.",
        "Related legs are protocol evidence for the scenario; they do not certify the",
        "lab's fault and explain phases.",
        "",
        "| Lab | Slug | Exercise | Cookbook | Related interop legs |",
        "|---|---|---|---|---|",
        *rows,
        "",
    ])


def expected_outputs(root: Path) -> dict[str, str]:
    inventory = json.loads((root / INVENTORY).read_text())
    legs = load_legs(root)
    labs = load_labs(root)
    interop = (root / INTEROP_DOC).read_text()
    if interop.count(BEGIN) != 1 or interop.count(END) != 1:
        raise MetadataError(f"{INTEROP_DOC} must contain one generated leg-index block")
    before, rest = interop.split(BEGIN)
    after = rest.split(END)[1]
    return {
        CAPABILITIES_OUT: render_capabilities(inventory, legs),
        LABS_OUT: render_labs(root, labs, legs),
        INTEROP_DOC: before + render_leg_index(legs) + after,
    }


def stale_outputs(root: Path) -> list[str]:
    stale = []
    for path, text in expected_outputs(root).items():
        target = root / path
        if not target.is_file() or target.read_text() != text:
            stale.append(path)
    return stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="regenerate the outputs")
    parser.add_argument("--check", action="store_true", help="fail on stale outputs (default)")
    args = parser.parse_args(argv)
    try:
        if args.write:
            for path, text in expected_outputs(ROOT).items():
                (ROOT / path).write_text(text)
            return 0
        stale = stale_outputs(ROOT)
    except (MetadataError, KeyError, TypeError, OSError, json.JSONDecodeError) as error:
        print(f"evidence index: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    if stale:
        print(
            f"evidence index is stale: {', '.join(stale)}; run "
            "`python3 scripts/generate_evidence_index.py --write`",
            file=sys.stderr,
        )
        return 1
    print("evidence index: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
