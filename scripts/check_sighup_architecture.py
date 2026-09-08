#!/usr/bin/env python3
"""Check architecture route coverage against the Rust enum and classifier.

This checks the structured route inventory and detailed-reference links, not
the meaning of family conditions or settlement prose. Those still need source
review and the classifier's Rust regressions; no behavior model is duplicated.
"""

import importlib.util
import re
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECTION = "### Config Reload (SIGHUP)"
HEADER = "| Route | Settlement |"
LINKS = (
    "../reference/operations.md#configuration-reload-sighup",
    "../reference/reload-matrix.md#sighup-reload-routes",
)
SPEC = importlib.util.spec_from_file_location(
    "dashboard_check", Path(__file__).with_name("check-grafana-dashboard.py")
)
RUST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUST)


def source_routes(source: str) -> set[str]:
    # Limit the shared lexer to the two rustfmt-shaped top-level items. A
    # changed item shape fails closed in rust_braced_body below.
    items = re.findall(
        r"^pub (?:enum SighupReloadRoute\b|fn classify_sighup_reload\b).*?^}",
        source, re.MULTILINE | re.DOTALL,
    )
    syntax, _ = RUST.rust_lex("\n".join(items))
    enum = RUST.rust_braced_body(
        syntax, r"\bpub enum SighupReloadRoute\s*\{", "SighupReloadRoute"
    )
    variants = set(re.findall(r"^    (\w+)\s*(?:,|\{|\()", enum, re.MULTILINE))
    classifier = RUST.rust_braced_body(
        syntax,
        r"\bpub fn classify_sighup_reload\([^)]*\)\s*->\s*SighupReloadRoute\s*\{",
        "classify_sighup_reload",
    )
    returned = set(re.findall(r"\bSighupReloadRoute::(\w+)", classifier))
    if not variants or variants != returned:
        raise ValueError(
            f"enum/classifier route mismatch: enum={sorted(variants)}, "
            f"classifier={sorted(returned)}"
        )
    return variants


def check(document: str, source: str) -> list[str]:
    try:
        expected = source_routes(source)
        sections = re.findall(rf"^{re.escape(SECTION)}\n(.*?)(?=^### |\Z)",
                              document, re.MULTILINE | re.DOTALL)
        if len(sections) != 1:
            raise ValueError("expected one Config Reload (SIGHUP) section")
        section = sections[0]
        tables = re.findall(
            rf"^{re.escape(HEADER)}\n\|[-| ]+\|\n((?:\|[^\n]+\|\n)+)",
            section, re.MULTILINE,
        )
        if len(tables) != 1:
            raise ValueError("expected one Route / Settlement table")
        rows = []
        for line in tables[0].splitlines():
            row = re.fullmatch(r"\| `(\w+)` \| ([^|]+) \|", line)
            if row is None or not row[2].strip():
                raise ValueError(f"malformed route row: {line}")
            rows.append(row[1])
    except ValueError as error:
        return [str(error)]
    counts = Counter(rows)
    errors = [f"missing route: {name}" for name in sorted(expected - counts.keys())]
    errors += [f"unknown route: {name}" for name in sorted(counts.keys() - expected)]
    errors += [f"duplicate route: {name}" for name, count in counts.items() if count > 1]
    for target in LINKS:
        if not re.search(rf"\[[^\]\n]+\]\({re.escape(target)}\)", section):
            errors.append(f"missing detailed-reference link: {target}")
    return errors


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT
    try:
        errors = check(
            (root / "docs/explanation/architecture.md").read_text(encoding="utf-8"),
            (root / "src/config/mod.rs").read_text(encoding="utf-8"),
        )
    except OSError as error:
        errors = [str(error)]
    for error in errors:
        print(f"SIGHUP architecture check: {error}", file=sys.stderr)
    if not errors:
        print("SIGHUP architecture route coverage and reference links passed")
    return bool(errors)


if __name__ == "__main__":
    sys.exit(main())
