#!/usr/bin/env python3
"""Mutation proofs for publishable-crate semver derivation."""

import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from scripts.check_semver_publishable_crates import (
    ContractError,
    RegistryState,
    derive,
    registry_state,
)


ROOT = "/repo"
WORKFLOW = """
      - "crates/wire/**"
      - "crates/fsm/**"
      - "crates/rpki/**"
      - ".github/workflows/semver-checks.yml"
      - "scripts/check_semver_publishable_crates.py"
      - "scripts/test_check_semver_publishable_crates.py"
"""


class FakeResponse:
    """Minimal context-managed response used by the registry tests."""

    def __init__(self, payload: dict[str, object]) -> None:
        self.status = 200
        self.body = io.BytesIO(json.dumps(payload).encode())

    def read(self, *args: object) -> bytes:
        return self.body.read(*args)

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


def metadata(rpki_version: str = "0.1.0") -> dict[str, object]:
    return {
        "workspace_root": ROOT,
        "packages": [
            {
                "name": "rustbgpd-wire",
                "version": "0.18.0",
                "manifest_path": f"{ROOT}/crates/wire/Cargo.toml",
                "publish": None,
            },
            {
                "name": "rustbgpd-fsm",
                "version": "0.5.0",
                "manifest_path": f"{ROOT}/crates/fsm/Cargo.toml",
                "publish": None,
            },
            {
                "name": "rustbgpd-rpki",
                "version": rpki_version,
                "manifest_path": f"{ROOT}/crates/rpki/Cargo.toml",
                "publish": None,
            },
            {
                "name": "rustbgpd",
                "version": "0.67.0",
                "manifest_path": f"{ROOT}/Cargo.toml",
                "publish": [],
            },
        ],
    }


class PublishableCrateContractTests(unittest.TestCase):
    def test_exact_rpki_first_publish_is_excluded_until_registry_visible(self) -> None:
        states = {
            "rustbgpd-wire": RegistryState.NORMAL_RELEASE,
            "rustbgpd-fsm": RegistryState.NORMAL_RELEASE,
            "rustbgpd-rpki": RegistryState.ABSENT,
        }
        checked, first = derive(metadata(), WORKFLOW, states.__getitem__)
        self.assertEqual(
            [package.name for package in checked],
            ["rustbgpd-fsm", "rustbgpd-wire"],
        )
        self.assertEqual([package.name for package in first], ["rustbgpd-rpki"])

    def test_rpki_joins_semver_set_automatically_after_publish(self) -> None:
        checked, first = derive(
            metadata(), WORKFLOW, lambda _name: RegistryState.NORMAL_RELEASE
        )
        self.assertEqual(
            [package.name for package in checked],
            ["rustbgpd-fsm", "rustbgpd-rpki", "rustbgpd-wire"],
        )
        self.assertEqual([], first)

    def test_unapproved_first_publish_version_fails(self) -> None:
        with self.assertRaisesRegex(ContractError, "not an approved first publish"):
            derive(
                metadata("0.1.1"),
                WORKFLOW,
                lambda name: RegistryState.ABSENT
                if name == "rustbgpd-rpki"
                else RegistryState.NORMAL_RELEASE,
            )

    def test_claimed_name_without_normal_release_fails(self) -> None:
        with self.assertRaisesRegex(ContractError, "claimed without a normal"):
            derive(
                metadata(),
                WORKFLOW,
                lambda name: RegistryState.CLAIMED_WITHOUT_NORMAL_RELEASE
                if name == "rustbgpd-rpki"
                else RegistryState.NORMAL_RELEASE,
            )

    def test_unexpected_unpublished_crate_fails(self) -> None:
        changed = metadata()
        changed["packages"].append(
            {
                "name": "rustbgpd-surprise",
                "version": "0.1.0",
                "manifest_path": f"{ROOT}/crates/surprise/Cargo.toml",
                "publish": None,
            }
        )
        workflow = WORKFLOW + '      - "crates/surprise/**"\n'
        with self.assertRaisesRegex(ContractError, "rustbgpd-surprise@0.1.0"):
            derive(
                changed,
                workflow,
                lambda name: RegistryState.ABSENT
                if name in {"rustbgpd-rpki", "rustbgpd-surprise"}
                else RegistryState.NORMAL_RELEASE,
            )

    def test_manifest_outside_workspace_root_fails_with_contract_error(self) -> None:
        changed = metadata()
        changed["packages"][2]["manifest_path"] = "/outside/crates/rpki/Cargo.toml"
        with self.assertRaisesRegex(
            ContractError,
            "publishable package manifest is outside workspace root: rustbgpd-rpki",
        ):
            derive(changed, WORKFLOW, lambda _name: RegistryState.NORMAL_RELEASE)

    def test_each_publishable_directory_is_required_in_trigger(self) -> None:
        with self.assertRaisesRegex(ContractError, "crates/rpki"):
            derive(
                metadata(),
                WORKFLOW.replace('      - "crates/rpki/**"\n', ""),
                lambda _name: RegistryState.NORMAL_RELEASE,
            )

    def test_helper_and_its_test_are_required_in_trigger(self) -> None:
        for path in (
            "scripts/check_semver_publishable_crates.py",
            "scripts/test_check_semver_publishable_crates.py",
        ):
            with self.subTest(path=path), self.assertRaisesRegex(ContractError, path):
                derive(
                    metadata(),
                    WORKFLOW.replace(f'      - "{path}"\n', ""),
                    lambda _name: RegistryState.NORMAL_RELEASE,
                )

    @patch("scripts.check_semver_publishable_crates.urllib.request.urlopen")
    def test_registry_normal_release_is_accepted(self, urlopen) -> None:
        urlopen.return_value = FakeResponse(
            {
                "crate": {"id": "rustbgpd-rpki"},
                "versions": [{"num": "0.1.0", "yanked": False}],
            }
        )
        self.assertIs(
            registry_state("rustbgpd-rpki"), RegistryState.NORMAL_RELEASE
        )

    @patch("scripts.check_semver_publishable_crates.urllib.request.urlopen")
    def test_registry_404_is_the_only_absent_response(self, urlopen) -> None:
        urlopen.side_effect = urllib.error.HTTPError(
            "https://crates.io", 404, "not found", {}, None
        )
        self.assertIs(registry_state("rustbgpd-rpki"), RegistryState.ABSENT)

    @patch("scripts.check_semver_publishable_crates.urllib.request.urlopen")
    def test_registry_network_failure_fails_closed(self, urlopen) -> None:
        urlopen.side_effect = urllib.error.URLError("offline")
        with self.assertRaisesRegex(ContractError, "cannot query crates.io"):
            registry_state("rustbgpd-rpki")


if __name__ == "__main__":
    unittest.main()
