#!/usr/bin/env python3
"""Pure generator checks for the optional RPKI route-server scenario."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest


GENERATOR = Path(__file__).with_name("gen-scenario.py")


class RpkiScenarioTests(unittest.TestCase):
    def generate(self, directory: Path, *, cache: str | None, dualstack: bool = False,
                 changed_peers: int | None = None, extra_env: dict[str, str] | None = None):
        env = {key: value for key, value in os.environ.items() if not key.startswith("GEN_")}
        if cache is not None:
            env["GEN_RPKI_CACHE"] = cache
        if dualstack:
            env["GEN_DUALSTACK"] = "1"
        env.update(extra_env or {})
        args = [sys.executable, str(GENERATOR), "8", str(directory), "1790"]
        if changed_peers is not None:
            args.append(str(changed_peers))
        return subprocess.run(args, env=env, capture_output=True, text=True, check=False)

    def test_absent_knob_preserves_existing_policy_and_config(self):
        with tempfile.TemporaryDirectory(prefix="rpki-gen-", dir="/tmp") as tmp:
            out = Path(tmp) / "scenario"
            result = self.generate(out, cache=None)
            self.assertEqual(result.returncode, 0, result.stderr)
            config = tomllib.loads((out / "config.toml").read_text())
            self.assertNotIn("rpki", config)
            self.assertEqual(config["policy"]["import_chain"], ["member-in"])
            self.assertEqual(len(config["neighbors"]), 8)
            for name in ("gen-a.rpol", "gen-b.rpol"):
                policy = (out / name).read_text()
                self.assertNotIn("route.rpki", policy)
                self.assertIn("    term default { accept }", policy)

    def test_cache_guards_every_member_in_both_families_and_generations(self):
        for address in ("127.0.0.1:1", "127.0.0.1:3323", "[::1]:65535"):
            with self.subTest(address=address), tempfile.TemporaryDirectory(
                prefix="rpki-gen-", dir="/tmp"
            ) as tmp:
                out = Path(tmp) / "scenario"
                result = self.generate(out, cache=address, dualstack=True, changed_peers=6)
                self.assertEqual(result.returncode, 0, result.stderr)
                config = tomllib.loads((out / "config.toml").read_text())
                self.assertEqual(config["rpki"]["cache_servers"], [{"address": address}])
                self.assertEqual(config["config_epoch"], 2)
                self.assertTrue(config["global"]["ebgp_requires_policy"])
                self.assertEqual(config["policy"]["import_chain"], ["member-in"])
                self.assertEqual(len(config["neighbors"]), 8)
                for neighbor in config["neighbors"]:
                    self.assertNotIn("import_policy_chain", neighbor)
                    self.assertEqual(neighbor["families"], ["ipv4_unicast", "ipv6_unicast"])
                for name in ("gen-a.rpol", "gen-b.rpol", "member.rpol"):
                    policy = (out / name).read_text()
                    self.assertEqual(policy.count("route.rpki == invalid { reject }"), 1)
                    self.assertLess(policy.index("term drop-blocked"),
                                    policy.index("term reject-rpki-invalid"))
                    self.assertLess(policy.index("term reject-rpki-invalid"),
                                    policy.index("term default"))
                imports = [
                    (out / name).read_text().split("policy member-in {")[1]
                    .split("policy member-out {")[0]
                    for name in ("gen-a.rpol", "gen-b.rpol")
                ]
                self.assertEqual(*imports)

    def test_invalid_addresses_fail_before_writing_files(self):
        bad = ("", "localhost:3323", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536",
               "127.0.0.1:-1", "127.0.0.1:abc", "127.0.0.999:3323", "::1:3323",
               "[::1]", "[::1]:0", "[::1]:65536", "[not-ipv6]:3323",
               "[fe80::1%eth0]:3323",
               '127.0.0.1:3323"\n[evil]')
        with tempfile.TemporaryDirectory(prefix="rpki-gen-", dir="/tmp") as tmp:
            for index, address in enumerate(bad):
                with self.subTest(address=address):
                    out = Path(tmp) / str(index)
                    result = self.generate(out, cache=address)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("GEN_RPKI_CACHE must be", result.stderr)
                    self.assertFalse(out.exists())

    def test_rpki_cache_rejected_in_policy_free_reflector_mode(self):
        with tempfile.TemporaryDirectory(prefix="rpki-gen-", dir="/tmp") as tmp:
            out = Path(tmp) / "scenario"
            result = self.generate(out, cache="127.0.0.1:3323",
                                   extra_env={"GEN_IBGP_RR_ASN": "64512"})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("incompatible", result.stderr)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
