#!/usr/bin/env python3
"""Fail closed when release payloads and copyable install docs diverge."""

from __future__ import annotations

import re
import sys
from pathlib import Path


MONITORING_PAYLOADS = (
    (
        "docs/grafana/rustbgpd-overview.json",
        "share/monitoring/rustbgpd-overview.json",
        "/usr/share/doc/rustbgpd/monitoring/rustbgpd-overview.json",
    ),
    (
        "examples/prometheus/rustbgpd-alerts.yml",
        "share/monitoring/rustbgpd-alerts.yml",
        "/usr/share/doc/rustbgpd/monitoring/rustbgpd-alerts.yml",
    ),
    (
        "examples/prometheus/rustbgpd-alerts_test.yml",
        "share/monitoring/rustbgpd-alerts_test.yml",
        "/usr/share/doc/rustbgpd/monitoring/rustbgpd-alerts_test.yml",
    ),
)


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
            "Assert tarball release payload is complete",
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
                "staging/share/monitoring",
                "docs/grafana/rustbgpd-overview.json",
                "examples/prometheus/rustbgpd-alerts.yml",
                "examples/prometheus/rustbgpd-alerts_test.yml",
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
                "share/monitoring/rustbgpd-overview.json",
                "share/monitoring/rustbgpd-alerts.yml",
                "share/monitoring/rustbgpd-alerts_test.yml",
            ),
        )

        nfpm = read("packaging/nfpm.yaml")
        native_bins = set(re.findall(r"(?m)^\s+dst: (/usr/bin/[^\s]+)\s*$", nfpm))
        expected = {"/usr/bin/rustbgpd", "/usr/bin/rbgp", "/usr/bin/rs-config-render"}
        if native_bins != expected:
            errors.append(f"packaging/nfpm.yaml: /usr/bin payload {sorted(native_bins)!r}")
        native_files = set(
            re.findall(
                r"(?m)^[ \t]+- src: ([^ \t\r\n]+)\r?\n"
                r"[ \t]+dst: ([^ \t\r\n]+)[ \t]*$",
                nfpm,
            )
        )
        expected_monitoring = {(source, native) for source, _, native in MONITORING_PAYLOADS}
        missing_monitoring = expected_monitoring - native_files
        if missing_monitoring:
            errors.append(
                "packaging/nfpm.yaml: native monitoring payloads missing exact canonical mappings "
                f"{sorted(missing_monitoring)!r}"
            )

        for source, _, _ in MONITORING_PAYLOADS:
            asset = root / source
            if not asset.is_file() or asset.stat().st_size == 0:
                errors.append(f"monitoring payload source missing or empty: {source}")

        alert_test = read("examples/prometheus/rustbgpd-alerts_test.yml")
        if not re.search(r"(?m)^rule_files:\n  - rustbgpd-alerts\.yml\s*$", alert_test):
            errors.append(
                "examples/prometheus/rustbgpd-alerts_test.yml: rule_files must resolve "
                "rustbgpd-alerts.yml beside the test payload"
            )

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

            require(
                errors,
                f"{path} monitoring discovery",
                doc,
                (
                    "share/monitoring/",
                    "/usr/share/doc/rustbgpd/monitoring/",
                    "rustbgpd-overview.json",
                    "rustbgpd-alerts.yml",
                    "rustbgpd-alerts_test.yml",
                ),
            )

        contract_workflow = read(".github/workflows/release-install-contract.yml")
        for source, _, _ in MONITORING_PAYLOADS:
            if contract_workflow.count(f"- {source}") != 2:
                errors.append(
                    ".github/workflows/release-install-contract.yml: expected pull/push "
                    f"enrollment for {source}"
                )

        deployment = read("docs/deployment.md")
        native = marked(deployment, "native-package", "docs/deployment.md")
        require(
            errors,
            "docs/deployment.md native-package region",
            native,
            ("/usr/share/doc/rustbgpd/monitoring/",),
        )
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
