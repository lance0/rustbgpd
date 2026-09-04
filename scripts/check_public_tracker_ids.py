#!/usr/bin/env python3
"""Fail closed when public documentation cites a private tracker issue ID.

The published doc surface — everything under `docs/` plus the top-level
public markdown — is read by people who have no access to the project's
issue tracker. A bare `LAN-123` in that text is an unresolvable reference:
it names evidence the reader cannot reach and cannot even identify. The
project convention is to name the thing directly, link the ADR, or cite the
GitHub PR number instead.

The surface is discovered from the tracked tree rather than a maintained
file list, so a doc added tomorrow is covered the day it lands instead of
passing vacuously. An empty scan set is itself a failure: a guard that
cannot fail is worse than no guard.

Sealed perf-receipt artifacts are exempt. Their bytes are pinned by a
`SHA256SUMS`, so editing the prose would invalidate published evidence
checksums; they are frozen captures, not living documentation. The
exemption is derived from the seal files themselves rather than a hand-kept
list, so it narrows automatically as receipts age out and cannot be widened
by editing this guard.

Exported runtime text is the one crate-source surface fenced here. Crate
sources stay outside the document scan (see the scope note below), but two
kinds of string literal inside them leave the repository at runtime:
Prometheus metric help text and `tracing` event messages. An operator
reading `/metrics` or a log line cannot resolve a tracker ID any more than
a doc reader can, so those literals are matched by shape — a metric
`Opts::new`/`IntGauge::new`-style registration or a `warn!`-family macro
call — while comments, lint `reason` strings, test modules, and test
directories keep the conventional in-repository cross-reference.
"""

from __future__ import annotations

import gzip
import hashlib
import re
import stat
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# Anything under `docs/`, plus the top-level files a first-time reader lands
# on. CHANGELOG.md, ROADMAP.md, and ROADMAP_HISTORY.md are deliberately out of
# scope: released and completed sections are historical records that must not
# be rewritten, while current roadmap work may have only a tracker item as its
# public name.
#
# The rest of the tree — `bench/`, `examples/`, `scripts/`, crate sources —
# is deliberately out of scope too (settled with LAN-957, the same
# narrow-the-rule-to-what-matters call as the host-path-identifier
# decision): those files are read by people working inside the repository,
# where a tracker ID is the conventional cross-reference, and a stale one
# in a harness README costs that reader very little. Known mentions outside
# the fence (e.g. bench/scale/rrharness/README.md) are accepted, not
# missed. Do not widen the scan without a new recorded decision.
SCANNED_PREFIXES = ("docs/",)
SCANNED_FILES = frozenset(
    {
        "README.md",
        "ARCHITECTURE.md",
        "CONTRIBUTING.md",
        "KNOWN_ISSUES.md",
        "SECURITY.md",
        "SUPPORT.md",
    }
)

# Binary blobs and compressed captures carry no reviewable prose.
SKIPPED_SUFFIXES = frozenset({".gz", ".png", ".svg", ".zst", ".bin"})

# Exported runtime text: `.rs` files under the daemon and crate source trees,
# minus test directories and `tests.rs` modules. Within them only string
# literals inside these call shapes are exported — metric registrations
# (`Opts::new("name", "help")`, `IntGauge::new("name", "help")`, custom
# collector `Desc::new`) and `tracing` event macros.
RUNTIME_SOURCE = re.compile(r"^(?:src|crates/[^/]+/src)/.*\.rs$")
RUNTIME_TEXT_HEAD = re.compile(
    r"(?:\btracing::)?\b(?:error|warn|info|debug|trace)!\s*\("
    r"|\b(?:Opts|HistogramOpts|Desc|IntCounter|IntGauge|Counter|Gauge|Histogram)"
    r"::new\s*\("
)
STRING_LITERAL = re.compile(r'"(?:[^"\\]|\\[\s\S])*"')
RAW_STRING_LITERAL = re.compile(r'r(#*)"[\s\S]*?"\1')
CHAR_LITERAL = re.compile(r"'(?:[^'\\\n]|\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.))'")
CFG_TEST = re.compile(r"#\[cfg\(test\)\]")

TRACKER_ID = re.compile(r"\bLAN-\d+\b")
HOME_PATH = re.compile(rb"/(?:home|Users)/(?![<$\{])[^/\s\"'<>]+")
READ_SIZE, OVERLAP, EXCERPT_SIZE = 64 * 1024, 8, 160

ARTIFACT_ROOTS = (
    Path("docs/perf/artifacts"),
    Path("docs/artifacts/soak"),
)
SEAL_NAME = "SHA256SUMS"
SEAL_ROOT = Path("docs/perf/artifacts")
SEAL_LINE = re.compile(r"([0-9a-f]{64})  (.+)")


class TrackerIdGuardError(RuntimeError):
    """The public documentation surface could not be enumerated."""


def _audit_artifact_stream(relative: str, handle: object) -> list[str]:
    failures: list[str] = []
    carry = b""
    line = 1
    reported_line = 0
    while chunk := handle.read(READ_SIZE):
        window = carry + chunk
        window_line = line - carry.count(b"\n")
        for match in HOME_PATH.finditer(window):
            number = window_line + window[: match.start()].count(b"\n")
            if match.end() <= len(carry) or number == reported_line:
                continue
            excerpt = window[match.start() : match.start() + EXCERPT_SIZE]
            failures.append(
                f"{relative}:{number} contains literal absolute home path "
                f"{excerpt.decode(errors='replace')!r}"
            )
            reported_line = number
        line += chunk.count(b"\n")
        carry = window[-OVERLAP:]
    return failures


def tracked_files() -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise TrackerIdGuardError(f"cannot list tracked files: {error}")
    if result.returncode != 0:
        detail = result.stderr.strip() or f"git ls-files exited {result.returncode}"
        raise TrackerIdGuardError(f"cannot list tracked files: {detail}")
    paths = [ROOT / name for name in result.stdout.split("\0") if name]
    if not paths:
        raise TrackerIdGuardError("cannot list tracked files: the tracked tree is empty")
    return paths


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sealed_paths(paths: list[Path], root: Path | None = None) -> set[str]:
    """Verify tracked receipt manifests and return their sealed paths."""
    root = (root or ROOT).resolve()
    tracked: dict[str, Path] = {}
    for path in paths:
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as error:
            raise TrackerIdGuardError(
                f"tracked path escapes the repository root: {path}"
            ) from error
        tracked[relative] = path

    manifests = [
        path
        for relative, path in tracked.items()
        if path.name == SEAL_NAME
        and Path(relative).is_relative_to(SEAL_ROOT)
    ]
    if not manifests:
        raise TrackerIdGuardError(
            "no tracked performance-receipt SHA256SUMS manifests were found"
        )

    sealed: set[str] = set()
    for manifest in sorted(manifests):
        if manifest.is_symlink():
            raise TrackerIdGuardError(f"seal {manifest} is a symlink")
        try:
            lines = manifest.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            raise TrackerIdGuardError(f"cannot read seal {manifest}: {error}") from error
        if not lines:
            raise TrackerIdGuardError(f"seal {manifest} is empty")

        receipt_root = manifest.parent.resolve()
        manifest_entries: set[str] = set()
        for line_number, line in enumerate(lines, start=1):
            match = SEAL_LINE.fullmatch(line)
            if match is None:
                raise TrackerIdGuardError(
                    f"{manifest}:{line_number} is not lowercase SHA-256, two spaces, "
                    "and a filename"
                )
            expected, name = match.groups()
            name_path = Path(name)
            if name_path.is_absolute() or ".." in name_path.parts:
                raise TrackerIdGuardError(
                    f"{manifest}:{line_number} entry {name!r} escapes its receipt root"
                )
            entry = manifest.parent / name_path
            try:
                resolved = entry.resolve(strict=True)
                resolved.relative_to(receipt_root)
                relative = entry.relative_to(root).as_posix()
            except (OSError, ValueError) as error:
                raise TrackerIdGuardError(
                    f"{manifest}:{line_number} entry {name!r} is missing or escapes "
                    "its receipt root"
                ) from error
            cursor = manifest.parent
            for part in name_path.parts:
                if part == ".":
                    continue
                cursor /= part
                if cursor.is_symlink():
                    raise TrackerIdGuardError(
                        f"{manifest}:{line_number} entry {name!r} is a symlink"
                    )
            if relative not in tracked:
                raise TrackerIdGuardError(
                    f"{manifest}:{line_number} entry {name!r} is not tracked"
                )
            if not resolved.is_file():
                raise TrackerIdGuardError(
                    f"{manifest}:{line_number} entry {name!r} is not a regular file"
                )
            if relative in manifest_entries:
                raise TrackerIdGuardError(
                    f"{manifest}:{line_number} duplicates entry {name!r}"
                )
            manifest_entries.add(relative)
            try:
                actual = _sha256(resolved)
            except OSError as error:
                raise TrackerIdGuardError(
                    f"cannot hash {manifest}:{line_number} entry {name!r}: {error}"
                ) from error
            if actual != expected:
                raise TrackerIdGuardError(
                    f"{manifest}:{line_number} entry {name!r} has SHA-256 {actual}, "
                    f"expected {expected}"
                )
            sealed.add(relative)
    return sealed


def discover_documents() -> dict[str, str]:
    """Map each public documentation file to its text."""
    paths = tracked_files()
    sealed = sealed_paths(paths)
    documents: dict[str, str] = {}
    for path in paths:
        relative = path.relative_to(ROOT).as_posix()
        if relative not in SCANNED_FILES and not relative.startswith(SCANNED_PREFIXES):
            continue
        if relative in sealed or path.suffix in SKIPPED_SUFFIXES:
            continue
        try:
            documents[relative] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    if not documents:
        raise TrackerIdGuardError(
            "no public documentation was discovered, so the walk is broken: "
            "the repository ships a docs/ tree and a top-level README"
        )
    return dict(sorted(documents.items()))


def audit_document(relative: str, text: str) -> list[str]:
    """Report every private tracker ID cited by `relative`."""
    failures: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for match in TRACKER_ID.finditer(line):
            failures.append(
                f"{relative}:{number} cites the private tracker ID "
                f"{match.group(0)!r}, which an external reader cannot resolve; "
                "name the thing directly, link the ADR, or cite the PR number"
            )
    return failures


def _literal_end(code: str, index: int) -> int | None:
    """Return the end of the string or char literal starting at `index`."""
    char = code[index]
    previous = code[index - 1] if index else " "
    if char == '"':
        match = STRING_LITERAL.match(code, index)
    elif char == "'":
        match = CHAR_LITERAL.match(code, index)
    elif char == "r" and (previous == "b" or not (previous.isalnum() or previous == "_")):
        match = RAW_STRING_LITERAL.match(code, index)
    else:
        match = None
    return None if match is None else match.end()


def _blank(text: str) -> str:
    return re.sub(r"[^\n]", " ", text)


def _blank_comments(text: str) -> str:
    """Blank `//`, `///`, and `/* */` comments, keeping newlines and literals."""
    out: list[str] = []
    index = 0
    while index < len(text):
        end = _literal_end(text, index)
        if end is not None:
            out.append(text[index:end])
            index = end
        elif text.startswith("//", index):
            end = text.find("\n", index)
            end = len(text) if end < 0 else end
            out.append(_blank(text[index:end]))
            index = end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = len(text) if end < 0 else end + 2
            out.append(_blank(text[index:end]))
            index = end
        else:
            out.append(text[index])
            index += 1
    return "".join(out)


def _balanced_end(code: str, index: int, open_char: str, close_char: str) -> int:
    """Return the index just past the bracket closing the one at `index`."""
    depth = 0
    while index < len(code):
        end = _literal_end(code, index)
        if end is not None:
            index = end
            continue
        if code[index] == open_char:
            depth += 1
        elif code[index] == close_char:
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(code)


def _blank_test_modules(code: str) -> str:
    """Blank every `#[cfg(test)]` block item in comment-free code."""
    while match := CFG_TEST.search(code):
        index = match.end()
        while index < len(code) and code[index] not in "{;":
            index = _literal_end(code, index) or index + 1
        if index >= len(code) or code[index] == ";":
            # A `#[cfg(test)] mod tests;` declaration or `use`: the body
            # lives in a test directory that discovery already skips.
            code = code[: match.start()] + _blank(match.group(0)) + code[match.end() :]
            continue
        end = _balanced_end(code, index, "{", "}")
        code = code[: match.start()] + _blank(code[match.start() : end]) + code[end:]
    return code


def discover_runtime_sources() -> dict[str, str]:
    """Map each runtime Rust source file to its text."""
    sources: dict[str, str] = {}
    for path in tracked_files():
        relative = path.relative_to(ROOT).as_posix()
        if not RUNTIME_SOURCE.match(relative):
            continue
        parts = Path(relative).parts
        if "tests" in parts or path.stem == "tests":
            continue
        try:
            sources[relative] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    if not sources:
        raise TrackerIdGuardError(
            "no runtime sources were discovered, so the walk is broken: "
            "the repository ships src/ and crates/*/src/ Rust trees"
        )
    return dict(sorted(sources.items()))


def audit_runtime_text(relative: str, text: str) -> list[str]:
    """Report every private tracker ID exported by metric help or log text."""
    code = _blank_test_modules(_blank_comments(text))
    failures: list[str] = []
    seen: set[tuple[int, str]] = set()
    for head in RUNTIME_TEXT_HEAD.finditer(code):
        open_paren = head.end() - 1
        close = _balanced_end(code, open_paren, "(", ")")
        for literal in STRING_LITERAL.finditer(code, open_paren, close):
            for match in TRACKER_ID.finditer(literal.group(0)):
                number = code.count("\n", 0, literal.start() + match.start()) + 1
                if (number, match.group(0)) in seen:
                    continue
                seen.add((number, match.group(0)))
                failures.append(
                    f"{relative}:{number} exports the private tracker ID "
                    f"{match.group(0)!r} in runtime text (metric help or log "
                    "message), which an operator cannot resolve; keep the "
                    "explanation and drop the ID"
                )
    return failures


def audit_artifact_home_paths(
    paths: list[Path] | None = None, root: Path | None = None
) -> list[str]:
    """Reject literal absolute home paths in tracked published artifacts."""
    root = (root or ROOT).resolve()
    artifacts: dict[Path, list[tuple[str, Path]]] = {
        artifact_root: [] for artifact_root in ARTIFACT_ROOTS
    }
    for path in paths if paths is not None else tracked_files():
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as error:
            raise TrackerIdGuardError(
                f"tracked path escapes the repository root: {path}"
            ) from error
        relative_path = Path(relative)
        for artifact_root in ARTIFACT_ROOTS:
            if relative_path.is_relative_to(artifact_root):
                artifacts[artifact_root].append((relative, path))
                break

    for artifact_root, discovered in artifacts.items():
        if not discovered:
            raise TrackerIdGuardError(
                f"no tracked artifacts were discovered under {artifact_root.as_posix()}"
            )

    failures: list[str] = []
    for discovered in artifacts.values():
        for relative, path in discovered:
            if path.is_symlink():
                raise TrackerIdGuardError(f"tracked artifact {relative} is a symlink")
            try:
                mode = path.stat().st_mode
                if not stat.S_ISREG(mode) or mode & 0o444 == 0:
                    raise OSError("not a readable regular file")
                opener = gzip.open if path.suffix == ".gz" else Path.open
                with opener(path, "rb") as handle:
                    failures.extend(_audit_artifact_stream(relative, handle))
            except (OSError, EOFError) as error:
                raise TrackerIdGuardError(
                    f"cannot read tracked artifact {relative}: {error}"
                ) from error
    return failures


def main() -> int:
    try:
        documents = discover_documents()
        sources = discover_runtime_sources()
    except TrackerIdGuardError as error:
        print(f"public tracker ID check failed: {error}", file=sys.stderr)
        return 1

    failures = [
        failure
        for relative, text in documents.items()
        for failure in audit_document(relative, text)
    ]
    failures.extend(
        failure
        for relative, text in sources.items()
        for failure in audit_runtime_text(relative, text)
    )
    try:
        failures.extend(audit_artifact_home_paths())
    except TrackerIdGuardError as error:
        print(f"public tracker ID check failed: {error}", file=sys.stderr)
        return 1
    if failures:
        for failure in failures:
            print(f"public tracker ID check failed: {failure}", file=sys.stderr)
        return 1

    print(
        f"public tracker ID check passed: {len(documents)} public documents "
        f"cite no private tracker IDs; {len(sources)} runtime sources export none"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
