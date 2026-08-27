#!/usr/bin/env python3
"""Derive crates.io-backed semver-check inputs from Cargo metadata."""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable


CRATES_IO = "https://crates.io/api/v1/crates"
USER_AGENT = "rustbgpd-semver-contract/1.0 (https://github.com/lance0/rustbgpd)"
FIRST_PUBLISH = {("rustbgpd-rpki", "0.1.0")}
SUPPORT_PATHS = (
    ".github/workflows/semver-checks.yml",
    "scripts/check_semver_publishable_crates.py",
    "scripts/test_check_semver_publishable_crates.py",
)
NORMAL_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:\+[0-9A-Za-z.-]+)?$")


class ContractError(RuntimeError):
    """The semver workflow cannot establish a fail-closed package set."""


class RegistryState(Enum):
    ABSENT = "absent"
    NORMAL_RELEASE = "normal-release"
    CLAIMED_WITHOUT_NORMAL_RELEASE = "claimed-without-normal-release"


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    directory: str


def _normal_release(payload: object, name: str) -> bool:
    if not isinstance(payload, dict):
        raise ContractError(f"crates.io returned a non-object for {name}")
    crate = payload.get("crate")
    versions = payload.get("versions")
    if not isinstance(crate, dict) or crate.get("id") != name:
        raise ContractError(f"crates.io identity mismatch for {name}")
    if not isinstance(versions, list):
        raise ContractError(f"crates.io omitted the version inventory for {name}")
    return any(
        isinstance(version, dict)
        and isinstance(version.get("num"), str)
        and NORMAL_VERSION.fullmatch(version["num"])
        and version.get("yanked") is False
        for version in versions
    )


def registry_state(name: str) -> RegistryState:
    request = urllib.request.Request(
        f"{CRATES_IO}/{name}",
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise ContractError(
                    f"crates.io returned HTTP {response.status} for {name}"
                )
            try:
                payload = json.load(response)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ContractError(f"invalid crates.io JSON for {name}") from error
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return RegistryState.ABSENT
        raise ContractError(f"crates.io returned HTTP {error.code} for {name}") from error
    except urllib.error.URLError as error:
        raise ContractError(f"cannot query crates.io for {name}: {error.reason}") from error

    if _normal_release(payload, name):
        return RegistryState.NORMAL_RELEASE
    return RegistryState.CLAIMED_WITHOUT_NORMAL_RELEASE


def _publishable(metadata: dict[str, object]) -> list[Package]:
    root = metadata.get("workspace_root")
    packages = metadata.get("packages")
    if not isinstance(root, str) or not isinstance(packages, list):
        raise ContractError("invalid cargo metadata shape")
    root_path = Path(root)
    result = []
    for package in packages:
        if not isinstance(package, dict) or package.get("publish") is not None:
            continue
        name = package.get("name")
        version = package.get("version")
        manifest = package.get("manifest_path")
        if not all(isinstance(value, str) for value in (name, version, manifest)):
            raise ContractError("publishable package metadata is incomplete")
        result.append(
            Package(
                name=name,
                version=version,
                directory=str(Path(manifest).parent.relative_to(root_path)),
            )
        )
    if not result:
        raise ContractError("no publishable crate found; did every manifest disable publish?")
    return sorted(result, key=lambda package: package.name)


def derive(
    metadata: dict[str, object],
    workflow: str,
    probe: Callable[[str], RegistryState] = registry_state,
) -> tuple[list[Package], list[Package]]:
    publishable = _publishable(metadata)
    required_paths = tuple(package.directory for package in publishable) + SUPPORT_PATHS
    missing_paths = [
        path for path in required_paths if f'- "{path}/**"' not in workflow
        and f'- "{path}"' not in workflow
    ]
    if missing_paths:
        raise ContractError(
            f"semver pull_request paths filter is missing: {missing_paths}"
        )

    checked = []
    first_publish = []
    for package in publishable:
        state = probe(package.name)
        if state is RegistryState.NORMAL_RELEASE:
            checked.append(package)
        elif (
            state is RegistryState.ABSENT
            and (package.name, package.version) in FIRST_PUBLISH
        ):
            first_publish.append(package)
        elif state is RegistryState.ABSENT:
            raise ContractError(
                f"unpublished crate is not an approved first publish: "
                f"{package.name}@{package.version}"
            )
        else:
            raise ContractError(
                f"crate name is claimed without a normal semver baseline: {package.name}"
            )
    if not checked:
        raise ContractError("no crates.io-published crate remains for semver checking")
    return checked, first_publish


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(
            f"usage: {Path(sys.argv[0]).name} METADATA_JSON SEMVER_WORKFLOW"
        )
    try:
        metadata = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        workflow = Path(sys.argv[2]).read_text(encoding="utf-8")
        checked, first_publish = derive(metadata, workflow)
    except (OSError, json.JSONDecodeError, ContractError) as error:
        print(error, file=sys.stderr)
        return 1

    print(
        "checked:",
        ", ".join(f"{p.name}@{p.version}" for p in checked),
        file=sys.stderr,
    )
    if first_publish:
        print(
            "first publish (no public semver baseline yet):",
            ", ".join(f"{p.name}@{p.version}" for p in first_publish),
            file=sys.stderr,
        )
    print("packages=" + ",".join(package.name for package in checked))
    print("first_publish=" + ",".join(package.name for package in first_publish))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
