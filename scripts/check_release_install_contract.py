#!/usr/bin/env python3
"""Check release artifacts through the commands that build and exercise them."""

from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path


BINARIES = ("rustbgpd", "rbgp", "rs-config-render", "birdwatcher-adapter")
LICENSES = ("LICENSE-MIT", "LICENSE-APACHE", "LICENSES.md")
SYSTEMD = (
    "share/systemd/rustbgpd.service",
    "share/systemd/rustbgpd@.service",
    "share/systemd/rustbgpd-dataplane.conf",
)
MONITORING = (
    (
        "docs/grafana/rustbgpd-overview.json",
        "share/monitoring/rustbgpd-overview.json",
        "/usr/share/doc/rustbgpd/monitoring/rustbgpd-overview.json",
    ),
    (
        "docs/grafana/rustbgpd-evpn.json",
        "share/monitoring/rustbgpd-evpn.json",
        "/usr/share/doc/rustbgpd/monitoring/rustbgpd-evpn.json",
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
SYSTEMD_UNIT = "examples/systemd/rustbgpd.service"
SYSTEMD_TEMPLATE = "examples/systemd/rustbgpd@.service"
SYSTEMD_CONTAINER_UNIT = "examples/systemd/rustbgpd-container.service"
COMPOSE_FILE = "examples/docker-compose/docker-compose.yml"
LICENSE_MAP = "LICENSES.md"
SYSTEMD_DIRECTIVES = {
    ("Unit", "StartLimitIntervalSec"): "10min",
    ("Unit", "StartLimitBurst"): "5",
    ("Service", "Type"): "notify",
    ("Service", "NotifyAccess"): "main",
    ("Service", "WatchdogSec"): "5min",
    ("Service", "TimeoutStartSec"): "10min",
    ("Service", "Restart"): "on-failure",
    ("Service", "RestartSec"): "5",
    ("Service", "TimeoutStopSec"): "32min",
}
TEMPLATE_DIRECTIVES = {
    ("Service", "ExecStart"): "/usr/local/bin/rustbgpd /var/lib/rustbgpd/%i/activation/current/config.toml",
    ("Service", "StateDirectory"): "rustbgpd/%i rustbgpd/%i/activation",
    ("Service", "StateDirectoryMode"): "0700",
    ("Service", "RuntimeDirectory"): "rustbgpd/%i",
    ("Service", "RuntimeDirectoryMode"): "0700",
    ("Service", "UMask"): "0077",
    ("Service", "NoNewPrivileges"): "yes",
    ("Service", "ProtectSystem"): "strict",
    ("Service", "ProtectHome"): "yes",
    ("Service", "ReadWritePaths"): "/var/lib/rustbgpd/%i",
    ("Service", "PrivateTmp"): "yes",
    ("Service", "AmbientCapabilities"): "CAP_NET_BIND_SERVICE",
    ("Service", "CapabilityBoundingSet"): "CAP_NET_BIND_SERVICE",
}
CONTAINER_EXEC_START = (
    "/usr/bin/docker run --name=rustbgpd --rm --network=host --user=root "
    "--cap-drop=ALL --cap-add=NET_BIND_SERVICE "
    "--stop-timeout=1920 --ulimit=nofile=65536:524288 "
    "--mount=type=bind,source=${RUSTBGPD_CONFIG_DIR},target=/etc/rustbgpd,readonly "
    "--mount=type=bind,source=${RUSTBGPD_STATE_DIR},target=/var/lib/rustbgpd "
    "${RUSTBGPD_IMAGE} rustbgpd ${RUSTBGPD_CONFIG_FILE}"
)
CONTAINER_DIRECTIVES = {
    ("Unit", "After"): ("docker.service network-online.target",),
    ("Unit", "Requires"): ("docker.service",),
    ("Unit", "Wants"): ("network-online.target",),
    ("Unit", "StartLimitIntervalSec"): ("10min",),
    ("Unit", "StartLimitBurst"): ("5",),
    ("Service", "Type"): ("simple",),
    ("Service", "User"): ("root",),
    ("Service", "Group"): ("root",),
    ("Service", "Environment"): (
        "RUSTBGPD_CONFIG_DIR=/etc/rustbgpd",
        "RUSTBGPD_STATE_DIR=/var/lib/rustbgpd",
        "RUSTBGPD_CONFIG_FILE=/etc/rustbgpd/config.toml",
    ),
    ("Service", "EnvironmentFile"): (
        "/etc/rustbgpd/rustbgpd-container.env",
    ),
    ("Service", "ExecStartPre"): (
        "/usr/bin/test x${RUSTBGPD_IMAGE} != x",
        "-/usr/bin/docker pull ${RUSTBGPD_IMAGE}",
        "-/usr/bin/docker rm --force rustbgpd",
    ),
    ("Service", "ExecStart"): (CONTAINER_EXEC_START,),
    ("Service", "ExecReload"): (
        "/usr/bin/docker kill --signal=HUP rustbgpd",
    ),
    ("Service", "ExecStop"): (
        "-/usr/bin/docker stop -t 1920 rustbgpd",
    ),
    ("Service", "ExecStopPost"): (
        "-/usr/bin/docker rm --force rustbgpd",
    ),
    ("Service", "Restart"): ("on-failure",),
    ("Service", "RestartSec"): ("5",),
    ("Service", "TimeoutStopSec"): ("33min",),
    ("Install", "WantedBy"): ("multi-user.target",),
}


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
        raise ValueError(
            f"{label}: expected one matching run body, found {len(matches)}"
        )
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


def require_patterns(
    errors: list[str], label: str, text: str, patterns: tuple[str, ...]
) -> None:
    missing = [
        pattern for pattern in patterns if not re.search(pattern, text, re.MULTILINE)
    ]
    if missing:
        errors.append(f"{label}: missing active commands {missing!r}")


def systemd_logical_lines(text: str) -> tuple[str, ...]:
    logical = []
    continued = ""
    for raw_line in text.splitlines():
        if raw_line.lstrip().startswith(("#", ";")):
            continue
        line = raw_line.rstrip()
        if continued:
            line = continued + " " + line.lstrip()
        if line.endswith("\\"):
            continued = line[:-1].rstrip()
        else:
            logical.append(line)
            continued = ""
    if continued:
        logical.append(continued)
    return tuple(logical)


def systemd_assignments(text: str) -> tuple[tuple[str | None, str, str], ...]:
    section: str | None = None
    assignments = []
    for raw_line in systemd_logical_lines(text):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if match := re.fullmatch(r"\[([^]]+)\]", line):
            section = match.group(1)
        elif "=" in line:
            key, value = line.split("=", 1)
            assignments.append((section, key.strip(), value.strip()))
    return tuple(assignments)


def systemd_status_is_70(token: str) -> bool:
    token = token.removeprefix("+")
    if token == "SOFTWARE":
        return True
    try:
        if token.lower().startswith("0b"):
            base = 2
        elif token.lower().startswith("0x"):
            base = 16
        elif len(token) > 1 and token.startswith("0"):
            base = 8
        else:
            base = 10
        return int(token, base) == 70
    except ValueError:
        return False


def check_systemd_exit_70(
    errors: list[str],
    assignments: tuple[tuple[str | None, str, str], ...],
    label: str,
) -> None:
    for _, key, value in assignments:
        if key in {"SuccessExitStatus", "RestartPreventExitStatus"} and any(
            systemd_status_is_70(token) for token in value.split()
        ):
            errors.append(
                f"{label}: {key} must not classify exit 70/SOFTWARE as non-restartable"
            )


def check_systemd_unit(errors: list[str], text: str) -> None:
    assignments = systemd_assignments(text)
    for (section, key), expected in SYSTEMD_DIRECTIVES.items():
        actual = [
            value
            for found_section, found_key, value in assignments
            if found_section == section and found_key == key
        ]
        if actual != [expected]:
            errors.append(
                f"systemd unit: [{section}] {key} must occur once with value {expected!r}, got {actual!r}"
            )
    check_systemd_exit_70(errors, assignments, "systemd unit")


def check_systemd_template(
    errors: list[str], text: str, *, packaged: bool = False
) -> None:
    assignments = systemd_assignments(text)
    expected_directives = TEMPLATE_DIRECTIVES | {
        ("Service", "ExecStart"): (
            "/usr/bin/rustbgpd /var/lib/rustbgpd/%i/activation/current/config.toml"
            if packaged
            else TEMPLATE_DIRECTIVES[("Service", "ExecStart")]
        )
    }
    for (section, key), expected in expected_directives.items():
        actual = [
            value
            for found_section, found_key, value in assignments
            if found_section == section and found_key == key
        ]
        if actual != [expected]:
            errors.append(
                f"systemd template: [{section}] {key} must occur once with value {expected!r}, got {actual!r}"
            )
    if "%I" in text:
        errors.append("systemd template: unescaped %I must not replace the exact router handle")
    check_systemd_unit(errors, text)


def check_systemd_container(errors: list[str], text: str) -> None:
    assignments = systemd_assignments(text)
    for (section, key), expected in CONTAINER_DIRECTIVES.items():
        actual = tuple(
            value
            for found_section, found_key, value in assignments
            if found_section == section and found_key == key
        )
        if actual != expected:
            errors.append(
                "systemd container unit: "
                f"[{section}] {key} must be {expected!r}, got {actual!r}"
            )
    check_systemd_exit_70(errors, assignments, "systemd container unit")
    exec_starts = (
        value
        for section, key, value in assignments
        if section == "Service" and key == "ExecStart"
    )
    if any(container_exec_start_publishes(command) for command in exec_starts):
        errors.append(
            "systemd container unit: host networking must not carry bridge publish flags"
        )


def container_exec_start_publishes(command: str) -> bool:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    if tokens[:2] != ["/usr/bin/docker", "run"]:
        return False
    try:
        image_index = tokens.index("${RUSTBGPD_IMAGE}", 2)
    except ValueError:
        return False
    for token in tokens[2:image_index]:
        if token == "-p" or (token.startswith("-p") and not token.startswith("--")):
            return True
        if token == "-P" or token.startswith("-P="):
            return True
        if token == "--publish" or token.startswith("--publish="):
            return True
        if token == "--publish-all" or token.startswith("--publish-all="):
            return True
    return False


def check_container_deployment_docs(
    errors: list[str], deployment: str, dockerfile: str
) -> None:
    required_docs = (
        "published GHCR version tags have **no leading",
        "default command is exactly",
        "net.ipv4.ip_unprivileged_port_start=0",
        "`--cap-add=NET_BIND_SERVICE` is **not sufficient**",
        "Use exactly one of these deployment paths:",
        "`--network=host` with `--user=root`",
        "--cap-drop=ALL",
        "runtime-state marker/checkpoint storage unavailable",
        "must be non-empty",
        "Runtime mutation",
        "status does not terminate the attached process",
        "`TimeoutStopSec=33min`",
        "rustbgpd --check --strict /etc/rustbgpd/config.toml",
        "docker inspect --format '{{.State.Health.Status}}' rustbgpd",
    )
    for statement in required_docs:
        if statement not in deployment:
            errors.append(
                f"container deployment docs: missing contract statement {statement!r}"
            )

    bridge_section = deployment.partition("- **Bridge networking and state**:")[2]
    bridge_section = bridge_section.partition(
        "### Host networking and privileged BGP ports"
    )[0]
    bridge_recipes = re.findall(r"(?ms)^  ```sh\n(.*?)^  ```$", bridge_section)
    bridge = next((body for body in bridge_recipes if "--network=bridge" in body), None)
    if bridge is None:
        errors.append("container deployment docs: bridge recipe missing")
    elif "--cap-add" in bridge:
        errors.append(
            "container deployment docs: bridge recipe must not credit a capability for port 179"
        )

    host_section = deployment.partition(
        "### Host networking and privileged BGP ports"
    )[2].partition("### systemd-supervised host-network container")[0]
    host_recipes = re.findall(r"(?ms)^   ```sh\n(.*?)^   ```$", host_section)
    host = next((body for body in host_recipes if "--network=host" in body), None)
    if host is None:
        errors.append("container deployment docs: host-network recipe missing")
    else:
        for flag in ("--user=root", "--cap-drop=ALL", "--cap-add=NET_BIND_SERVICE"):
            if flag not in host:
                errors.append(
                    f"container deployment docs: host-network recipe missing {flag!r}"
                )

    service_section = deployment.partition(
        "### systemd-supervised host-network container"
    )[2].partition("- **File descriptors**")[0]
    preflight = service_section.find(
        "rustbgpd --check --strict /etc/rustbgpd/config.toml"
    )
    enable = service_section.find("sudo systemctl enable --now rustbgpd-container")
    if preflight < 0 or enable < 0 or preflight > enable:
        errors.append(
            "container deployment docs: strict preflight must precede enable --now"
        )

    try:
        runtime = dockerfile.split("FROM debian:bookworm-slim AS runtime", 1)[1]
    except IndexError:
        errors.append("container image contract: production runtime stage missing")
        return
    for statement in (
        "chown rustbgpd:rustbgpd /var/lib/rustbgpd",
        "USER rustbgpd",
        "CMD rbgp --json health | grep -q '\"healthy\": true' || exit 1",
        'CMD ["rustbgpd", "/etc/rustbgpd/config.toml"]',
    ):
        if statement not in runtime:
            errors.append(
                f"container image contract: missing production statement {statement!r}"
            )


def compose_service(text: str, name: str) -> tuple[str, ...]:
    lines = text.splitlines()
    marker = f"  {name}:"
    try:
        start = lines.index(marker) + 1
    except ValueError:
        return ()
    body = []
    for line in lines[start:]:
        if (
            line.strip()
            and not line.lstrip().startswith("#")
            and len(line) - len(line.lstrip()) <= 2
        ):
            break
        body.append(line)
    return tuple(body)


def check_compose(errors: list[str], text: str) -> None:
    service = compose_service(text, "rustbgpd")
    if not service:
        errors.append("docker compose: rustbgpd service missing or empty")
        return
    grace = [
        match.group(1).strip()
        for line in service
        if (match := re.fullmatch(r"    stop_grace_period:\s*(.*?)\s*", line))
    ]
    if grace != ["32m"]:
        errors.append(
            f"docker compose: rustbgpd stop_grace_period must occur once as 32m, got {grace!r}"
        )
    if any(re.match(r"^\s+(?:restart|restart_policy):", line) for line in service):
        errors.append("docker compose: rustbgpd must not declare a restart policy")


def check(root: Path) -> list[str]:
    errors: list[str] = []
    read = lambda path: (root / path).read_text(encoding="utf-8")
    try:
        check_systemd_unit(errors, read(SYSTEMD_UNIT))
        check_systemd_template(errors, read(SYSTEMD_TEMPLATE))
        check_systemd_container(errors, read(SYSTEMD_CONTAINER_UNIT))
        check_container_deployment_docs(
            errors, read("docs/deployment.md"), read("Dockerfile")
        )
        check_compose(errors, read(COMPOSE_FILE))
        license_map = read(LICENSE_MAP)
        for clause in (
            "# Community Data License Agreement - Permissive - Version 2.0",
            "## 2. Conditions for Sharing Data",
            '5.4. "Results" means any outcome obtained by computational analysis',
        ):
            if clause not in license_map:
                errors.append(f"license map: missing CDLA clause {clause!r}")
        release = read(".github/workflows/release.yml")
        build_packages = read("scripts/build-packages.sh")
        require_patterns(
            errors,
            "native systemd staging",
            build_packages,
            (
                exact("for unit in rustbgpd.service 'rustbgpd@.service'; do"),
                r"^\s+sed 's\|\^ExecStart=/usr/local/bin/rustbgpd \|ExecStart=/usr/bin/rustbgpd \|' \\$",
                r"^grep -qxF 'ExecStart=/usr/bin/rustbgpd /var/lib/rustbgpd/%i/activation/current/config\.toml' \\$",
            ),
        )
        package_tar = (
            "tar -C staging -czf dist/rustbgpd-${SUFFIX}.tar.gz rustbgpd rbgp "
            "rs-config-render birdwatcher-adapter LICENSE-MIT LICENSE-APACHE LICENSES.md rustbgpd.schema.json share"
        )
        package = select_script(release, "tarball package commands", package_tar)
        package_patterns = tuple(
            rf"^cp target/\$\{{\{{ matrix\.target \}}\}}/release/{binary} staging/$"
            for binary in BINARIES
        ) + (
            r"^cp LICENSE-MIT LICENSE-APACHE LICENSES\.md staging/$",
            r"^cp examples/systemd/rustbgpd\.service examples/systemd/rustbgpd@\.service examples/systemd/rustbgpd-dataplane\.conf staging/share/systemd/$",
            r"^cp docs/grafana/rustbgpd-overview\.json docs/grafana/rustbgpd-evpn\.json staging/share/monitoring/$",
            r"^cp examples/prometheus/rustbgpd-alerts\.yml examples/prometheus/rustbgpd-alerts_test\.yml staging/share/monitoring/$",
            exact(package_tar),
        )
        require_patterns(errors, "tarball package commands", package, package_patterns)

        assertion = select_script(
            release,
            "tarball payload assertions",
            'entries="$(tar -tzf "dist/rustbgpd-${SUFFIX}.tar.gz")"',
        )
        payloads = BINARIES + LICENSES + SYSTEMD + tuple(tar for _, tar, _ in MONITORING)
        inventory = re.search(r"(?m)^for f in (.+); do$", assertion)
        asserted = set(inventory.group(1).split()) if inventory else set()
        missing_payloads = set(payloads) - asserted
        if missing_payloads:
            errors.append(
                f"tarball payload assertions: missing {sorted(missing_payloads)!r}"
            )
        tar_checks = (
            exact('if ! grep -qxF "$f" <<<"$entries"; then'),
            exact(
                'if [ "$(tar -xOzf "dist/rustbgpd-${SUFFIX}.tar.gz" "$f" | wc -c)" -eq 0 ]; then'
            ),
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
            errors.append(
                f"native monitoring mappings missing {sorted(missing_monitoring)!r}"
            )
        for source, _, _ in MONITORING:
            if not (root / source).is_file() or (root / source).stat().st_size == 0:
                errors.append(f"monitoring source missing or empty: {source}")
        license_mapping = (LICENSE_MAP, "/usr/share/doc/rustbgpd/LICENSES.md")
        if license_mapping not in mappings:
            errors.append(f"native license mapping missing {license_mapping!r}")
        template_mapping = (
            "${PKGROOT}/lib/systemd/system/rustbgpd@.service",
            "/lib/systemd/system/rustbgpd@.service",
        )
        if template_mapping not in mappings:
            errors.append(f"native systemd template mapping missing {template_mapping!r}")

        contract = read(".github/workflows/release-install-contract.yml")
        select_script(
            contract,
            "container systemd syntax verification",
            "systemd-analyze verify examples/systemd/rustbgpd-container.service",
        )
        native = select_script(
            contract,
            "real native package assertions",
            'dpkg-deb -x "$deb" extracted/deb',
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
                r"^for file in lib/systemd/system/rustbgpd\.service lib/systemd/system/rustbgpd@\.service usr/share/man/man1/rbgp\.1\.gz usr/share/man/man8/rustbgpd\.8\.gz usr/share/doc/rustbgpd/LICENSES\.md usr/share/doc/rustbgpd/monitoring/rustbgpd-overview\.json usr/share/doc/rustbgpd/monitoring/rustbgpd-evpn\.json usr/share/doc/rustbgpd/monitoring/rustbgpd-alerts\.yml usr/share/doc/rustbgpd/monitoring/rustbgpd-alerts_test\.yml; do$",
                r'^test -s "\$tree/\$file" ',
                r'^"\$tree/usr/bin/rustbgpd" --check "\$tree/etc/rustbgpd/config\.toml"$',
                r'^unit="\$tree/lib/systemd/system/rustbgpd\.service"$',
                r"^for directive in Type=notify NotifyAccess=main WatchdogSec=5min TimeoutStartSec=10min StartLimitIntervalSec=10min StartLimitBurst=5 Restart=on-failure RestartSec=5 TimeoutStopSec=32min; do$",
                r'^grep -qxF "\$directive" "\$unit"$',
                r'^template="\$tree/lib/systemd/system/rustbgpd@\.service"$',
                exact("grep -qxF 'ExecStart=/usr/bin/rustbgpd /var/lib/rustbgpd/%i/activation/current/config.toml' \"$template\""),
                exact("grep -qxF 'StateDirectory=rustbgpd/%i rustbgpd/%i/activation' \"$template\""),
                exact("grep -qxF 'ReadWritePaths=/var/lib/rustbgpd/%i' \"$template\""),
                r"^from scripts\.check_release_install_contract import check_systemd_template, systemd_assignments, systemd_status_is_70$",
                r"^for _, key, value in systemd_assignments\(Path\(sys\.argv\[1\]\)\.read_text\(\)\):$",
                r'^if key in \{"SuccessExitStatus", "RestartPreventExitStatus"\} and any\($',
                r"^systemd_status_is_70\(token\) for token in value\.split\(\)$",
                r'^template_errors = \[\]$',
                r'^check_systemd_template\(template_errors, Path\(sys\.argv\[2\]\)\.read_text\(\), packaged=True\)$',
                r'^if template_errors: raise SystemExit\("; "\.join\(template_errors\)\)$',
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
