#!/usr/bin/env python3
"""Fail closed when release payloads and copyable install docs diverge."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def marked(text: str, name: str, label: str) -> str:
    start = f"<!-- release-install-contract:{name}:start -->"
    end = f"<!-- release-install-contract:{name}:end -->"
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError(f"{label}: expected one {name} marker pair")
    body = text.split(start, 1)[1].split(end, 1)[0]
    if not body.strip():
        raise ValueError(f"{label}: empty {name} region")
    return body


def workflow_step(text: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^      - name: {re.escape(name)}\n(.*?)(?=^      - name: |^  [a-zA-Z0-9_-]+:|\Z)",
        text,
    )
    if not match:
        raise ValueError(f"release.yml: missing step {name!r}")
    return match.group(1)


def require(errors: list[str], label: str, text: str, tokens: tuple[str, ...]) -> None:
    for token in tokens:
        if token not in text:
            errors.append(f"{label}: missing {token!r}")


def check(root: Path) -> list[str]:
    errors: list[str] = []
    read = lambda path: (root / path).read_text(encoding="utf-8")
    try:
        release = read(".github/workflows/release.yml")
        package = workflow_step(release, "Package binaries")
        assertion = workflow_step(
            release,
            "Assert tarball has nonempty binaries, licenses, man pages, and completions",
        )
        require(
            errors,
            "release package step",
            package,
            (
                "target/${{ matrix.target }}/release/birdwatcher-adapter",
                "examples/systemd/rustbgpd.service",
                "examples/systemd/rustbgpd-dataplane.conf",
                "staging/share/systemd/",
                "rustbgpd rbgp rs-config-render birdwatcher-adapter",
            ),
        )
        require(
            errors,
            "release assertion step",
            assertion,
            (
                "birdwatcher-adapter",
                "share/systemd/rustbgpd.service",
                "share/systemd/rustbgpd-dataplane.conf",
            ),
        )

        nfpm = read("packaging/nfpm.yaml")
        native_bins = set(re.findall(r"(?m)^\s+dst: (/usr/bin/[^\s]+)\s*$", nfpm))
        expected = {"/usr/bin/rustbgpd", "/usr/bin/rbgp", "/usr/bin/rs-config-render"}
        if native_bins != expected:
            errors.append(f"packaging/nfpm.yaml: /usr/bin payload {sorted(native_bins)!r}")

        for path in ("docs/deployment.md", "docs/QUICKSTART.md"):
            doc = read(path)
            tarball = marked(doc, "tarball", path)
            require(
                errors,
                f"{path} tarball region",
                tarball,
                (
                    "share/systemd/rustbgpd.service",
                    "share/systemd/rustbgpd-dataplane.conf",
                    "rustbgpd --init-config edge --stdout",
                ),
            )
            if "examples/systemd/" in tarball:
                errors.append(f"{path}: tarball region uses source-checkout systemd paths")

        deployment = read("docs/deployment.md")
        native = marked(deployment, "native-package", "docs/deployment.md")
        sentence = re.search(r"installs the three binaries \((.*?)\) to `/usr/bin`", " ".join(native.split()))
        documented = re.findall(r"`([^`]+)`", sentence.group(1)) if sentence else []
        if documented != ["rustbgpd", "rbgp", "rs-config-render"]:
            errors.append(f"docs/deployment.md: documented native binaries {documented!r}")
        source = marked(deployment, "source-checkout", "docs/deployment.md")
        require(
            errors,
            "docs/deployment.md source-checkout region",
            source,
            ("examples/systemd/rustbgpd.service", "examples/minimal/config.toml"),
        )

        adapter = marked(
            read("examples/birdwatcher-adapter/README.md"),
            "birdwatcher-boundary",
            "birdwatcher README",
        )
        require(
            errors,
            "birdwatcher README boundary",
            adapter,
            (
                "included in release tarballs",
                "excluded from the default `cargo build`",
                "native `.deb`/`.rpm` packages",
                "container images",
            ),
        )
    except (OSError, ValueError) as error:
        errors.append(str(error))
    return errors


def main() -> int:
    errors = check(Path(__file__).resolve().parents[1])
    if errors:
        print("release install contract failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("release install contract OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
