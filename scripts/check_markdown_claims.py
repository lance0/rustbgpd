#!/usr/bin/env python3
"""Fail closed when tracked Markdown restates a fact the code has moved past.

Each check scans every tracked `.md` file, so it lives here rather than in a
Rust test: a Rust whole-tree scanner makes the Markdown-pinned test lane
compile and run its crate for every documentation change.

- EVPN BUM enforcement: no current document may call the kernel BUM port
  enforcement an opt-in awaiting soak (history, ADRs, and receipts excluded).
- gRPC service counts: every documented total or native service count must
  match `proto/rustbgpd.proto` plus the vendored gNMI service, and the claim
  counts are pinned so a scanner that silently stops matching fails.
- AddNeighbor payloads: exactly the known Markdown and shell sources call
  `NeighborService/AddNeighbor`, and each sends an `intent` payload with the
  expected empty-paths mask, never the removed `config` form.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE_PROTO = "proto/rustbgpd.proto"
GNMI_PROTO = "proto/github.com/openconfig/gnmi/proto/gnmi/gnmi.proto"
# Pinned claim counts: a pattern that silently stops matching fails here.
EXPECTED_CLAIMS = (4, 6)

EVPN_EXCLUDED_PREFIXES = (
    "docs/project/changelog/",
    "docs/adr/",
    "docs/soaks/",
    "docs/perf/",
    "docs/artifacts/",
    "scripts/fixtures/release-notes/",
)

ADD_NEIGHBOR = "NeighborService/AddNeighbor"
# source -> (intent marker, empty-paths mask, expected mask count)
ADD_NEIGHBOR_SOURCES = {
    "docs/reference/api.md": ("-d '{\"intent", '"paths": []', 2),
    "docs/interop.md": ("-d '{\"intent", '"paths": []', 1),
    "tests/interop/scripts/test-m4-frr.sh": ('-d "{\\"intent\\"', '\\"paths\\": []', 1),
    "tests/interop/scripts/test-m44-grpc-tier-authz.sh": (
        "add_neighbor='{\"intent",
        '"paths":[]',
        1,
    ),
}
ADD_NEIGHBOR_CONFIG_FORMS = ("-d '{\"config", '-d "{\\"config\\"', "add_neighbor='{\"config")

NUMBER_WORDS = (
    "zero one two three four five six seven eight nine ten eleven twelve thirteen "
    "fourteen fifteen sixteen seventeen eighteen nineteen twenty"
).split()


def tracked(root: Path, *patterns: str) -> dict[str, str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", *patterns],
        capture_output=True,
        check=True,
    )
    paths = sorted(path for path in result.stdout.decode().split("\0") if path)
    return {path: (root / path).read_text(encoding="utf-8") for path in paths}


def evpn_excluded(path: str) -> bool:
    return (
        path == "CHANGELOG.md"
        or path.startswith(EVPN_EXCLUDED_PREFIXES)
        or (path.startswith("tests/interop/") and path.endswith("-receipt.md"))
    )


def evpn_normalized(block: str) -> str:
    kept = (ch if ch.isalnum() or ch == "_" else " " for ch in ascii_lower(block))
    return " ".join("".join(kept).split())


def evpn_stale_class(block: str) -> str | None:
    if not ("apply_bum_enforcement" in block or ("bum" in block and "enforcement" in block)):
        return None
    classes = (
        (
            "apply_bum_enforcement_default_false",
            "apply_bum_enforcement" in block and "default false" in block,
        ),
        ("end_to_end_wired_opt_in_by_config", "end to end wired opt in by config" in block),
        ("operator_facing_opt_in", "operator facing opt in" in block),
        ("opt_in_kernel_bum_port_enforcement", "opt in kernel bum port enforcement" in block),
        (
            "production_default_awaits_soak",
            "production default enforcement awaits" in block and "soak" in block,
        ),
        ("remaining_soak_question", "remaining soak question" in block),
    )
    return next((name for name, stale in classes if stale), None)


def evpn_bum_errors(markdown: dict[str, str]) -> list[str]:
    errors = []
    for path, text in markdown.items():
        if evpn_excluded(path):
            continue
        for block in text.split("\n\n"):
            stale = evpn_stale_class(evpn_normalized(block))
            if stale:
                errors.append(f"{path}: stale EVPN BUM posture claim ({stale})")
    return errors


def proto_tokens(text: str) -> list[str]:
    """Identifiers and `{` outside comments and string literals."""
    tokens = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        i += 1
        if c == "/" and text[i : i + 1] == "/":
            end = text.find("\n", i)
            i = n if end < 0 else end + 1
        elif c == "/" and text[i : i + 1] == "*":
            end = text.find("*/", i + 1)
            i = n if end < 0 else end + 2
        elif c in "\"'":
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                i += 1
                if text[i - 1] == c:
                    break
        elif c == "{":
            tokens.append(c)
        elif c == "_" or (c.isascii() and c.isalpha()):
            start = i - 1
            while i < n and (text[i] == "_" or (text[i].isascii() and text[i].isalnum())):
                i += 1
            tokens.append(text[start:i])
    return tokens


def service_names(proto: str) -> list[str]:
    tokens = proto_tokens(proto)
    return [
        tokens[i + 1]
        for i in range(len(tokens) - 2)
        if tokens[i] == "service" and tokens[i + 2] == "{"
    ]


def ascii_lower(text: str) -> str:
    return "".join(ch.lower() if ch.isascii() else ch for ch in text)


def claim_words(block: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", ascii_lower(block))


def number(word: str) -> int | None:
    if word.isascii() and word.isdigit():
        return int(word)
    return NUMBER_WORDS.index(word) if word in NUMBER_WORDS else None


def find_patterns(words: list[str], before: list[str], after: list[str]) -> list[tuple[int, int]]:
    width = len(before) + 1 + len(after)
    found = []
    for index in range(len(words) - width + 1):
        window = words[index : index + width]
        if window[: len(before)] == before and window[len(before) + 1 :] == after:
            value = number(window[len(before)])
            if value is not None:
                found.append((index, value))
    return found


def total_claims(words: list[str]) -> list[int]:
    patterns = (
        (["grpc", "surface", "across"], ["services"]),
        (["grpc", "control", "surface", "across"], ["services"]),
        (["grpc", "server", "tonic"], ["services"]),
        (["grpc"], ["services"]),
    )
    return [value for before, after in patterns for _, value in find_patterns(words, before, after)]


def native_claims(words: list[str], is_total: bool) -> list[int]:
    patterns = (
        ["native", "rustbgpd", "v1", "services"],
        ["native", "rustbgpd", "v1", "grpc", "services"],
        ["separate", "grpc", "services"],
    )
    claims = [claim for after in patterns for claim in find_patterns(words, [], after)]
    if "grpc" in words:
        claims += find_patterns(words, [], ["service", "split"])
    if is_total:
        seen = {index for index, _ in claims}
        for index in range(len(words) - 1):
            value = number(words[index])
            if words[index + 1] == "native" and index not in seen and value is not None:
                claims.append((index, value))
    return [value for _, value in claims]


def grpc_count_errors(
    markdown: dict[str, str],
    native_proto: str,
    gnmi_proto: str,
    expected_claims: tuple[int, int] = EXPECTED_CLAIMS,
) -> list[str]:
    gnmi = service_names(gnmi_proto)
    if gnmi != ["gNMI"]:
        return [f"{GNMI_PROTO}: expected exactly the gNMI service, found {gnmi}"]
    native = len(service_names(native_proto))
    total = native + 1
    errors = []
    totals_seen = natives_seen = 0
    for path, text in markdown.items():
        for block in text.split("\n\n"):
            words = claim_words(block)
            totals = total_claims(words)
            for observed in totals:
                totals_seen += 1
                if observed != total:
                    errors.append(
                        f"{path}: observed {observed}, classification total, "
                        f"proto-derived expected {total}"
                    )
            for observed in native_claims(words, bool(totals)):
                natives_seen += 1
                if observed != native:
                    errors.append(
                        f"{path}: observed {observed}, classification native, "
                        f"proto-derived expected {native}"
                    )
    if (totals_seen, natives_seen) != expected_claims:
        errors.append(
            f"found {totals_seen} total-service and {natives_seen} native-service claims, "
            f"expected {expected_claims[0]} and {expected_claims[1]}; update EXPECTED_CLAIMS "
            "only when a document deliberately adds or drops a claim"
        )
    return errors


def add_neighbor_errors(sources: dict[str, str]) -> list[str]:
    callers = sorted(path for path, text in sources.items() if ADD_NEIGHBOR in text)
    if callers != sorted(ADD_NEIGHBOR_SOURCES):
        return [f"{ADD_NEIGHBOR} callers are {callers}, expected {sorted(ADD_NEIGHBOR_SOURCES)}"]
    errors = []
    for path, (intent, mask, masks) in ADD_NEIGHBOR_SOURCES.items():
        text = sources[path]
        if intent not in text:
            errors.append(f"{path}: AddNeighbor payload is not the intent form {intent!r}")
        if text.count(mask) != masks:
            errors.append(f"{path}: expected {masks} {mask!r} mask(s), found {text.count(mask)}")
        for form in ADD_NEIGHBOR_CONFIG_FORMS:
            if form in text:
                errors.append(f"{path}: AddNeighbor still sends the config form {form!r}")
    return errors


def check(root: Path) -> list[str]:
    markdown = tracked(root, "*.md")
    return (
        evpn_bum_errors(markdown)
        + grpc_count_errors(
            markdown,
            (root / NATIVE_PROTO).read_text(encoding="utf-8"),
            (root / GNMI_PROTO).read_text(encoding="utf-8"),
        )
        + add_neighbor_errors(tracked(root, "*.md", "*.sh"))
    )


def main() -> int:
    try:
        errors = check(ROOT)
    except (OSError, UnicodeDecodeError, subprocess.CalledProcessError) as error:
        errors = [f"cannot read tracked sources: {error!r}"]
    for error in errors:
        print(f"markdown claim check failed: {error}", file=sys.stderr)
    if not errors:
        print("markdown claim check passed")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
