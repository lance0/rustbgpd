#!/usr/bin/env python3
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("wire", "fsm", "rpki")
PUBLISHED_VERSIONS = {"wire": "0.19.0", "fsm": "0.6.0", "rpki": "0.1.0"}
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


def labeled_paragraph(body: str, label: str) -> tuple[str, str | None]:
    paragraphs = [paragraph for paragraph in body.strip().split("\n\n") if paragraph]
    matches = [paragraph for paragraph in paragraphs if paragraph.startswith(label)]
    if len(matches) != 1:
        return "", f"boundary-paragraph:{label}"
    return matches[0], None


def check(document: str, prepared_versions: dict[str, str] | None = None) -> list[str]:
    errors: list[str] = []
    requested = {
        "map": (2, "Crate map and publish status"),
        "boundary": (2, "Published-crate release boundary"),
        "decode": (3, "Decode an UPDATE (codec-only — the canonical embedder)"),
        "session": (3, 'Build a session (codec + FSM — the "minimal speaker" consumer)'),
        "rpki": (3, "Validate an origin (RPKI table — the synchronous consumer)"),
        "publish": (2, "Which crate to publish next, and why"),
    }
    sections = {}
    for name, (level, title) in requested.items():
        sections[name], error = section(document, level, title)
        if error:
            errors.append(error)
    if errors:
        return errors

    if prepared_versions is None:
        try:
            prepared_versions = manifest_versions()
        except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
            return [f"manifest-version-contract:{error}"]
    if set(prepared_versions) != set(PACKAGES):
        return ["manifest-version-contract:package-set"]

    map_status = re.sub(r"\s+", " ", sections["map"])
    expected_map_status = (
        "`rustbgpd-wire`, `rustbgpd-fsm`, and `rustbgpd-rpki` all have "
        "registry-published releases; `rustbgpd-rpki` is on the registry from "
        "its first release, `0.1.0`."
    )
    if expected_map_status not in map_status:
        errors.append("publication-map-state")

    registry_boundary, error = labeled_paragraph(
        sections["boundary"], "Registry-visible releases are"
    )
    if error:
        errors.append(error)
    prepared_boundary, error = labeled_paragraph(
        sections["boundary"], "The prepared package boundary is"
    )
    if error:
        errors.append(error)
    if errors:
        return errors

    package_pattern = "|".join(PACKAGES)
    published = re.findall(rf"`rustbgpd-({package_pattern}) ([^`]+)`", registry_boundary)
    if len(published) != len(PUBLISHED_VERSIONS) or dict(published) != PUBLISHED_VERSIONS:
        errors.append("current-boundary-version")

    prepared = re.findall(rf"`rustbgpd-({package_pattern}) ([^`]+)`", prepared_boundary)
    if len(prepared) != len(PACKAGES) or dict(prepared) != prepared_versions:
        errors.append("prepared-boundary-version")

    examples = {
        "wire": (sections["decode"], sections["session"], sections["rpki"]),
        "fsm": (sections["session"],),
        "rpki": (sections["rpki"],),
    }
    for package, bodies in examples.items():
        assignment = re.compile(rf'^rustbgpd-{package} = "([^"]+)"$', re.MULTILINE)
        found = [match for body in bodies for match in assignment.findall(body)]
        if not found or any(version != PUBLISHED_VERSIONS[package] for version in found):
            errors.append(f"{package}-snippet-version")

    # An entry carries "; `X` prepared" only while the working tree runs ahead of
    # the registry. Omitting the clause is itself a claim -- that the manifest
    # version is the published one -- so it is compared against the manifest
    # either way, and a staged version cannot hide by dropping the clause.
    publish = re.findall(
        rf"^\d+\. \*\*`rustbgpd-({package_pattern})` \(published as `([^`]+)`"
        r"(?:; `([^`]+)` prepared)?\)\.\*\*",
        sections["publish"],
        re.MULTILINE,
    )
    published_status = {package: version for package, version, _ in publish}
    prepared_status = {
        package: prepared or version for package, version, prepared in publish
    }
    if (
        len(publish) != len(PUBLISHED_VERSIONS)
        or published_status != PUBLISHED_VERSIONS
        or prepared_status != prepared_versions
    ):
        errors.append("publish-status-version")

    rpki_pair = re.findall(
        r"first `([^`]+)` release starts directly on wire `([^`]+)`",
        sections["publish"],
    )
    if rpki_pair != [(PUBLISHED_VERSIONS["rpki"], PUBLISHED_VERSIONS["wire"])]:
        errors.append("rpki-wire-pair")

    fsm_pair = re.findall(
        r"The `([^`]+)` line pairs with wire `([^`]+)`",
        sections["publish"],
    )
    if fsm_pair != [(PUBLISHED_VERSIONS["fsm"], PUBLISHED_VERSIONS["wire"])]:
        errors.append("fsm-wire-pair")

    return errors


def main() -> int:
    if len(sys.argv) > 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} [EMBEDDING.md]")
    default = ROOT / "docs" / "reference" / "embedding.md"
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else default
    errors = check(path.read_text(encoding="utf-8"))
    if errors:
        print("\n".join(errors), file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
