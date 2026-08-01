#!/usr/bin/env python3
import re
import sys
from pathlib import Path


PACKAGES = ("wire", "fsm")


def section(document: str, start: str, end: str) -> str:
    rest = document.partition(start)[2].partition("\n")[2]
    body, marker, _ = rest.partition(end)
    return body if marker else ""


def check(document: str) -> list[str]:
    errors: list[str] = []
    boundary = section(document, "## 7. ", "## 8. ").lstrip().split("\n\n", 1)[0]
    current = re.findall(r"`rustbgpd-(wire|fsm) ([^`]+)`", boundary)
    versions = dict(current)
    if len(current) != len(PACKAGES) or set(versions) != set(PACKAGES):
        return ["current-boundary-version"]

    examples = {
        "wire": (
            section(document, "### 3.1 ", "### 3.2 "),
            section(document, "### 3.3 ", "### 3.4 "),
        ),
        "fsm": (section(document, "### 3.3 ", "### 3.4 "),),
    }
    for package, bodies in examples.items():
        assignment = re.compile(rf'^rustbgpd-{package} = "([^"]+)"$', re.MULTILINE)
        found = [match for body in bodies for match in assignment.findall(body)]
        if found != [versions[package]] * len(bodies):
            errors.append(f"{package}-snippet-version")

    publish = re.findall(
        r"^\d+\. \*\*`rustbgpd-(wire|fsm)` \(published as `([^`]+)`\)\.\*\*",
        section(document, "## 4. ", "## 5. "),
        re.MULTILINE,
    )
    if len(publish) != len(PACKAGES) or dict(publish) != versions:
        errors.append("publish-status-version")

    if re.search(r"\bprepared\b", document, re.IGNORECASE):
        errors.append("forbidden-prepared")
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
