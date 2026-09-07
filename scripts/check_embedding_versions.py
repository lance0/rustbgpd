#!/usr/bin/env python3
"""Check or refresh the published-crate examples without release-specific code."""

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("wire", "fsm", "rpki")
PUBLISHED_RECORD = Path("docs/reference/published-crate-versions.json")
EMBEDDING = Path("docs/reference/embedding.md")
WIRE_README = Path("crates/wire/README.md")
RPKI_README = Path("crates/rpki/README.md")
START = "<!-- published-crate-versions:start -->"
END = "<!-- published-crate-versions:end -->"
SECTIONS = {
    "boundary": (2, "Published-crate release boundary"),
    "decode": (3, "Decode an UPDATE (codec-only — the canonical embedder)"),
    "session": (3, 'Build a session (codec + FSM — the "minimal speaker" consumer)'),
    "rpki": (3, "Validate an origin (RPKI table — the synchronous consumer)"),
}
EXAMPLES = {"decode": ("wire",), "session": ("wire", "fsm"), "rpki": ("wire", "rpki")}
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
MANIFESTS = {
    "wire": ("rustbgpd-wire", Path("crates/wire/Cargo.toml"), "crates/wire"),
    "fsm": ("rustbgpd-fsm", Path("crates/fsm/Cargo.toml"), "crates/fsm"),
    "rpki": ("rustbgpd-rpki", Path("crates/rpki/Cargo.toml"), "crates/rpki"),
}
HEADING = re.compile(r"^(#{1,6})\s+(?:\d+(?:\.\d+)*\.?\s+)?(.+?)\s*$", re.MULTILINE)
SECTION_HEADING = re.compile(r"^(#{2,3})\s+", re.MULTILINE)


def section(document: str, level: int, title: str) -> tuple[str, str | None]:
    headings = [match for match in HEADING.finditer(document) if match[2] == title]
    if len(headings) != 1 or len(headings[0][1]) != level:
        state = "missing" if not headings else "duplicate-or-wrong-level"
        return "", f"semantic-heading:{title}:{state}"
    heading = headings[0]
    end = len(document)
    for following in SECTION_HEADING.finditer(document, heading.end()):
        if len(following[1]) <= level:
            end = following.start()
            break
    return document[heading.end() : end], None


def manifest_versions(root: Path = ROOT) -> dict[str, str]:
    root_manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    workspace_dependencies = root_manifest.get("workspace", {}).get("dependencies", {})
    versions = {}
    for package, (cargo_name, relative_manifest, expected_path) in MANIFESTS.items():
        manifest = tomllib.loads((root / relative_manifest).read_text(encoding="utf-8"))
        package_table = manifest.get("package", {})
        if package_table.get("name") != cargo_name:
            raise ValueError(f"manifest-package-name:{package}")
        version = package_table.get("version")
        if not isinstance(version, str):
            raise ValueError(f"manifest-package-version:{package}")
        if package_table.get("publish") in (False, []):
            raise ValueError(f"manifest-publish-disabled:{package}")

        dependency = workspace_dependencies.get(cargo_name)
        if not isinstance(dependency, dict):
            raise ValueError(f"workspace-pin:{package}")
        if dependency.get("version") != version or dependency.get("path") != expected_path:
            raise ValueError(f"workspace-pin:{package}")
        versions[package] = version
    return versions


def validate_versions(versions: object) -> dict[str, str]:
    if not isinstance(versions, dict) or set(versions) != set(PACKAGES):
        raise ValueError("published-version-record:package-set")
    for package, version in versions.items():
        if not isinstance(version, str) or not VERSION.fullmatch(version):
            raise ValueError(f"published-version-record:version:{package}")
    return versions


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate-json-key:{key}")
        result[key] = value
    return result


def published_versions(root: Path = ROOT) -> dict[str, str]:
    return validate_versions(
        json.loads(
            (root / PUBLISHED_RECORD).read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
    )


def version_block(body: str) -> str:
    if body.count(START) != 1 or body.count(END) != 1:
        raise ValueError("published-version-table:markers")
    start, end = body.index(START), body.index(END)
    if start >= end:
        raise ValueError("published-version-table:marker-order")
    return body[start : end + len(END)]


def assignment(package: str) -> re.Pattern:
    return re.compile(rf'^rustbgpd-{package}[ \t]*=[ \t]*"([^"]+)"[ \t]*$', re.MULTILINE)


def path_assignment(package: str) -> re.Pattern:
    return re.compile(
        rf'^rustbgpd-{package} = \{{ version = "([^"\n]+)", path = "\.\./rustbgpd/crates/{package}" \}}$',
        re.MULTILINE,
    )


def render_readme(readme: str, packages: tuple, prepared: dict, published: dict) -> str:
    for package in packages:
        readme = replace_section(
            readme,
            2,
            "Usage",
            lambda body, p=package: path_assignment(p).sub(
                f'rustbgpd-{p} = {{ version = "{prepared[p]}", path = "../rustbgpd/crates/{p}" }}',
                assignment(p).sub(f'rustbgpd-{p} = "{published[p]}"', body),
            ),
        )
    return readme


def check(
    document: str,
    prepared_versions: dict[str, str] | None = None,
    published: dict[str, str] | None = None,
    wire_readme: str | None = None,
    rpki_readme: str | None = None,
) -> list[str]:
    errors: list[str] = []
    sections = {}
    for name, (level, title) in SECTIONS.items():
        sections[name], error = section(document, level, title)
        if error:
            errors.append(error)
    if errors:
        return errors

    try:
        if prepared_versions is None:
            prepared_versions = manifest_versions()
        validate_versions(prepared_versions)
        published = published_versions() if published is None else validate_versions(published)
        if wire_readme is None:
            wire_readme = (ROOT / WIRE_README).read_text(encoding="utf-8")
        if rpki_readme is None:
            rpki_readme = (ROOT / RPKI_README).read_text(encoding="utf-8")
        block = version_block(sections["boundary"])
    except (OSError, ValueError) as error:
        return [str(error)]

    rows = re.findall(
        r"^\|[ \t]*`rustbgpd-([^`]+)`[ \t]*\|[ \t]*`([^`]+)`[ \t]*\|[ \t]*`([^`]+)`[ \t]*\|[ \t]*$",
        block,
        re.MULTILINE,
    )
    if len(rows) != len(PACKAGES) or {p: v for p, v, _ in rows} != published:
        errors.append("current-boundary-version")
    if len(rows) != len(PACKAGES) or {p: v for p, _, v in rows} != prepared_versions:
        errors.append("prepared-boundary-version")
    for name, packages in EXAMPLES.items():
        for package in packages:
            found = assignment(package).findall(sections[name])
            if not found or any(version != published[package] for version in found):
                errors.append(f"{package}-snippet-version:{name}")
    for name, readme, packages in (
        ("wire", wire_readme, ("wire",)),
        ("rpki", rpki_readme, ("wire", "rpki")),
    ):
        usage, error = section(readme, 2, "Usage")
        if error:
            errors.append(f"{name}-readme:{error}")
        for package in packages:
            found = assignment(package).findall(usage)
            if not found or any(version != published[package] for version in found):
                errors.append(f"{name}-readme-registry-version:{package}")
            if path_assignment(package).findall(usage) != [prepared_versions[package]]:
                errors.append(f"{name}-readme-path-version:{package}")
    return errors


def replace_section(document: str, level: int, title: str, transform) -> str:
    body, error = section(document, level, title)
    if error:
        raise ValueError(error)
    heading = next(match for match in HEADING.finditer(document) if match[2] == title)
    return document[: heading.end()] + transform(body) + document[heading.end() + len(body) :]


def render(document: str, wire_readme: str, prepared: dict, published: dict) -> tuple[str, str]:
    table = "\n".join(
        [
            START,
            "| Crate | Published examples | Working tree |",
            "|---|---|---|",
            *(f"| `rustbgpd-{p}` | `{published[p]}` | `{prepared[p]}` |" for p in PACKAGES),
            END,
        ]
    )
    document = replace_section(
        document, *SECTIONS["boundary"], lambda body: body.replace(version_block(body), table, 1)
    )
    for name, packages in EXAMPLES.items():
        for package in packages:
            document = replace_section(
                document,
                *SECTIONS[name],
                lambda body, p=package: assignment(p).sub(f'rustbgpd-{p} = "{published[p]}"', body),
            )
    wire_readme = render_readme(wire_readme, ("wire",), prepared, published)
    return document, wire_readme


def verify_registry(versions: dict[str, str]) -> None:
    for package, version in versions.items():
        name = f"rustbgpd-{package}"
        request = Request(
            f"https://crates.io/api/v1/crates/{name}/{version}",
            headers={"User-Agent": "rustbgpd-release-docs (https://github.com/lance0/rustbgpd)"},
        )
        with urlopen(request, timeout=15) as response:
            payload = json.load(response, object_pairs_hook=unique_object)
        release = payload.get("version") if isinstance(payload, dict) else None
        if not isinstance(release, dict) or (
            release.get("crate") != name
            or release.get("num") != version
            or release.get("yanked") is not False
        ):
            raise ValueError(f"registry-version-unavailable:{name}:{version}")


def update(root: Path = ROOT, *, refresh: bool = False) -> list[Path]:
    prepared = manifest_versions(root)
    published = published_versions(root)
    if refresh:
        published = validate_versions(prepared)
    original = {
        p: (root / p).read_text(encoding="utf-8")
        for p in (EMBEDDING, WIRE_README, RPKI_README, PUBLISHED_RECORD)
    }
    document, readme = render(original[EMBEDDING], original[WIRE_README], prepared, published)
    rpki_readme = render_readme(original[RPKI_README], ("wire", "rpki"), prepared, published)
    errors = check(document, prepared, published, readme, rpki_readme)
    if errors:
        raise ValueError("\n".join(errors))
    # Resolve every registry response before changing any local file. A partial
    # publish leaves the previous coordinated examples intact.
    if refresh:
        verify_registry(published)
    updated = {
        EMBEDDING: document,
        WIRE_README: readme,
        RPKI_README: rpki_readme,
        PUBLISHED_RECORD: json.dumps(published, indent=2) + "\n",
    }
    changed = [path for path, text in updated.items() if text != original[path]]
    for path in changed:
        (root / path).write_text(updated[path], encoding="utf-8")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "document", nargs="?", type=Path, help="alternative embedding guide to check"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--write", action="store_true", help="sync examples from the offline record and manifests"
    )
    mode.add_argument(
        "--refresh",
        action="store_true",
        help="verify all manifest versions on crates.io, then sync",
    )
    args = parser.parse_args()
    if args.document and (args.write or args.refresh):
        parser.error("an alternative document is supported only in check mode")
    try:
        if args.write or args.refresh:
            changed = update(refresh=args.refresh)
            for path in changed:
                print(f"updated {path}")
            if not changed:
                print("published-crate examples are up to date")
            return 0
        errors = check((args.document or ROOT / EMBEDDING).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        errors = [str(error)]
    if errors:
        print("\n".join(errors), file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
