#!/usr/bin/env python3
import re
import sys
from pathlib import Path


PACKAGES = ("wire", "fsm", "rpki")
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


def check(document: str) -> list[str]:
    errors: list[str] = []
    requested = {
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

    boundary = sections["boundary"].lstrip().split("\n\n", 1)[0]
    package_pattern = "|".join(PACKAGES)
    current = re.findall(rf"`rustbgpd-({package_pattern}) ([^`]+)`", boundary)
    versions = dict(current)
    if len(current) != len(PACKAGES) or set(versions) != set(PACKAGES):
        return ["current-boundary-version"]

    examples = {
        "wire": (sections["decode"], sections["session"], sections["rpki"]),
        "fsm": (sections["session"],),
        "rpki": (sections["rpki"],),
    }
    for package, bodies in examples.items():
        assignment = re.compile(rf'^rustbgpd-{package} = "([^"]+)"$', re.MULTILINE)
        found = [match for body in bodies for match in assignment.findall(body)]
        if found != [versions[package]] * len(bodies):
            errors.append(f"{package}-snippet-version")

    publish = re.findall(
        rf"^\d+\. \*\*`rustbgpd-({package_pattern})` \(published as `([^`]+)`\)\.\*\*",
        sections["publish"],
        re.MULTILINE,
    )
    if len(publish) != len(PACKAGES) or dict(publish) != versions:
        errors.append("publish-status-version")

    return errors


def main() -> int:
    if len(sys.argv) > 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} [EMBEDDING.md]")
    default = Path(__file__).resolve().parents[1] / "docs" / "EMBEDDING.md"
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else default
    errors = check(path.read_text(encoding="utf-8"))
    if errors:
        print("\n".join(errors), file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
