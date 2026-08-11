#!/usr/bin/env python3
"""Check release artifacts through the commands that build and exercise them."""

from __future__ import annotations

import re
import sys
from pathlib import Path


BINARIES = ("rustbgpd", "rbgp", "rs-config-render", "birdwatcher-adapter")
SYSTEMD = (
    "share/systemd/rustbgpd.service",
    "share/systemd/rustbgpd-dataplane.conf",
)
MONITORING = (
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


def exact(command: str) -> str:
    return rf"^{re.escape(command)}$"


def workflow_scripts(text: str) -> tuple[str, ...]:
    steps = re.findall(r"(?ms)^      - .*?(?=^      - |^  [\w-]+:|\Z)", text)
    return tuple(
        active_script(step)
        for step in steps
        if re.search(r"(?m)^(?:      - |        )run:", step)
    )


def select_script(text: str, label: str, discriminator: str) -> str:
    matches = [
        script
        for script in workflow_scripts(text)
        if re.search(exact(discriminator), script, re.MULTILINE)
    ]
    if len(matches) != 1:
        raise ValueError(f"{label}: expected one matching run body, found {len(matches)}")
    return matches[0]


def active_script(step: str) -> str:
    block = re.search(r"(?ms)^(?:      - |        )run: \|\n(.*)\Z", step)
    if block:
        lines = block.group(1).splitlines()
    else:
        inline = re.search(r"(?m)^(?:      - |        )run: (.+)$", step)
        if not inline:
            raise ValueError("workflow step has no run command")
        lines = [inline.group(1)]
    commands = []
    pending = ""
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split(" #", 1)[0].rstrip()
        pending += (" " if pending else "") + line.removesuffix("\\").rstrip()
        if not line.endswith("\\"):
            commands.append(pending)
            pending = ""
    if pending:
        commands.append(pending)
    return "\n".join(commands)


def require_patterns(errors: list[str], label: str, text: str, patterns: tuple[str, ...]) -> None:
    missing = [pattern for pattern in patterns if not re.search(pattern, text, re.MULTILINE)]
    if missing:
        errors.append(f"{label}: missing active commands {missing!r}")


def check(root: Path) -> list[str]:
    errors: list[str] = []
    read = lambda path: (root / path).read_text(encoding="utf-8")
    try:
        release = read(".github/workflows/release.yml")
        package_tar = (
            "tar -C staging -czf dist/rustbgpd-${SUFFIX}.tar.gz rustbgpd rbgp "
            "rs-config-render birdwatcher-adapter LICENSE-MIT LICENSE-APACHE rustbgpd.schema.json share"
        )
        package = select_script(release, "tarball package commands", package_tar)
        package_patterns = tuple(rf"^cp target/\$\{{\{{ matrix\.target \}}\}}/release/{binary} staging/$" for binary in BINARIES) + (
            r"^cp examples/systemd/rustbgpd\.service examples/systemd/rustbgpd-dataplane\.conf staging/share/systemd/$",
            r"^cp docs/grafana/rustbgpd-overview\.json staging/share/monitoring/$",
            r"^cp examples/prometheus/rustbgpd-alerts\.yml examples/prometheus/rustbgpd-alerts_test\.yml staging/share/monitoring/$",
            exact(package_tar),
        )
        require_patterns(errors, "tarball package commands", package, package_patterns)

        assertion = select_script(
            release,
            "tarball payload assertions",
            'entries="$(tar -tzf "dist/rustbgpd-${SUFFIX}.tar.gz")"',
        )
        payloads = BINARIES + SYSTEMD + tuple(tar for _, tar, _ in MONITORING)
        inventory = re.search(r"(?m)^for f in (.+); do$", assertion)
        asserted = set(inventory.group(1).split()) if inventory else set()
        missing_payloads = set(payloads) - asserted
        if missing_payloads:
            errors.append(f"tarball payload assertions: missing {sorted(missing_payloads)!r}")
        tar_checks = (
            exact('if ! grep -qxF "$f" <<<"$entries"; then'),
            exact('if [ "$(tar -xOzf "dist/rustbgpd-${SUFFIX}.tar.gz" "$f" | wc -c)" -eq 0 ]; then'),
        )
        require_patterns(errors, "tarball active assertions", assertion, tar_checks)

        nfpm = read("packaging/nfpm.yaml")
        destinations = set(re.findall(r"(?m)^\s+dst: (/usr/bin/\S+)\s*$", nfpm))
        expected_bins = {f"/usr/bin/{binary}" for binary in BINARIES}
        if destinations != expected_bins:
            errors.append(f"native binary destinations: {sorted(destinations)!r}")
        mappings = set(
            re.findall(
                r"(?m)^\s+- src: (\S+)\s*\n\s+dst: (\S+)\s*$",
                nfpm,
            )
        )
        expected_monitoring = {(source, native) for source, _, native in MONITORING}
        missing_monitoring = expected_monitoring - mappings
        if missing_monitoring:
            errors.append(f"native monitoring mappings missing {sorted(missing_monitoring)!r}")
        for source, _, _ in MONITORING:
            if not (root / source).is_file() or (root / source).stat().st_size == 0:
                errors.append(f"monitoring source missing or empty: {source}")

        contract = read(".github/workflows/release-install-contract.yml")
        native = select_script(
            contract, "real native package assertions", 'dpkg-deb -x "$deb" extracted/deb'
        )
        require_patterns(
            errors,
            "real native package assertions",
            native,
            (
                r'^deb="\$\(find dist -maxdepth 1 -name \'\*\.deb\' -print -quit\)"$',
                r'^rpm="\$\(find dist -maxdepth 1 -name \'\*\.rpm\' -print -quit\)"$',
                r'^test -n "\$deb" && test -n "\$rpm"$',
                r'^dpkg-deb -x "\$deb" extracted/deb$',
                r'^rpm2cpio "\$rpm" \| cpio --quiet -id --no-absolute-filenames --directory=extracted/rpm$',
                r"^for tree in extracted/deb extracted/rpm; do$",
                r"^for exe in rustbgpd rbgp rs-config-render birdwatcher-adapter; do$",
                r'^test -x "\$tree/usr/bin/\$exe" ',
                r'^"\$tree/usr/bin/rustbgpd" --check "\$tree/etc/rustbgpd/config\.toml"$',
            ),
        )
        if "--to-stdout" in native:
            errors.append("RPM extraction must populate extracted/rpm, not stdout")

        image_command = "docker run --rm --entrypoint birdwatcher-adapter rustbgpd:release-install-contract --help"
        select_script(contract, "production image adapter assertion", image_command)
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
