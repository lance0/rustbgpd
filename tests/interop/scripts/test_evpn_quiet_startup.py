#!/usr/bin/env python3
"""Pin EVPN fixture pre-link IPv6 and helper multicast setup ordering."""

import json
import os
import re
import shlex
from pathlib import Path
import subprocess
import tempfile
import unittest


DIRECTORY = Path(__file__).resolve().parent
STUB = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
name = Path(sys.argv[0]).name
with open(os.environ["COMMANDS"], "a") as output:
    output.write(json.dumps([name, *sys.argv[1:]]) + "\n")
if os.environ["EXISTING"] == "1" and sys.argv[1:3] == ["link", "add"]:
    sys.exit(2)
'''


class EvpnQuietStartupTests(unittest.TestCase):
    def test_multicast_disabled_before_first_up_even_on_reexec(self):
        for helper in ("start-rustbgpd-vtep.sh", "start-rustbgpd-sa-pe.sh"):
            for existing in (False, True):
                with self.subTest(helper=helper, existing=existing):
                    source = (DIRECTORY / helper).read_text()
                    source = source.split("# Live config", 1)[0].split("# Start rustbgpd.", 1)[0]
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        for name in ("ip", "bridge"):
                            command = root / name
                            command.write_text(STUB)
                            command.chmod(0o755)
                        log = root / "commands"
                        result = subprocess.run(
                            ["sh", "-c", source, helper, "10.0.0.1", "100"],
                            env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                                 "COMMANDS": str(log), "EXISTING": str(int(existing))},
                            text=True, capture_output=True, timeout=5, check=False,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        commands = [json.loads(line) for line in log.read_text().splitlines()]
                    bridge_up = commands.index(["ip", "link", "set", "dev", "br100", "up"])
                    self.assertLess(
                        commands.index(["ip", "link", "set", "dev", "br100", "type", "bridge", "mcast_snooping", "0"]),
                        bridge_up,
                    )
                    ports = ["br100", "vxlan100"]
                    if helper == "start-rustbgpd-sa-pe.sh":
                        ports.append("eth2")
                    for port in ports:
                        quiet = commands.index(["ip", "link", "set", "dev", port, "multicast", "off"])
                        up = next(i for i, command in enumerate(commands)
                                  if command in (["ip", "link", "set", port, "up"],
                                                 ["ip", "link", "set", "dev", port, "up"]))
                        self.assertLess(quiet, up, port)


class EvpnPrelinkIpv6Tests(unittest.TestCase):
    def test_topology_disables_ipv6_before_link_creation(self):
        for milestone in ("m66-evpn-es-drain-handover", "m67-evpn-link-drain-failover"):
            with self.subTest(milestone=milestone):
                source = (DIRECTORY.parent / f"{milestone}.clab.yml").read_text()
                defaults = source.split("  defaults:\n", 1)[1].split("  nodes:\n", 1)[0]
                self.assertRegex(defaults, r"stages:\n +create-links:\n +exec:")
                self.assertIn("target: container", defaults)
                self.assertIn("phase: on-enter", defaults)
                command = re.search(r"command: (.+)", defaults).group(1)
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    for name in ("all", "default"):
                        (root / name).mkdir()
                        (root / name / "disable_ipv6").write_text("0\n")
                    command = command.replace("/proc/sys/net/ipv6/conf", str(root))
                    subprocess.run(shlex.split(command), check=True, timeout=5)
                    for name in ("all", "default"):
                        self.assertEqual((root / name / "disable_ipv6").read_text().strip(), "1")
                self.assertNotIn('echo 1 > /proc/sys/net/ipv6/conf', source.split("  nodes:\n", 1)[1])

    def test_driver_rejects_failed_hook_and_enabled_existing_interface(self):
        stub = """#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import sys
node = sys.argv[2]
command = sys.argv[-1].replace('/proc/sys/net/ipv6/conf', str(Path(os.environ['SYSCTLS']) / node))
sys.exit(subprocess.run(['sh', '-ec', command], check=False).returncode)
"""
        for milestone in ("m66-evpn-es-drain-handover", "m67-evpn-link-drain-failover"):
            source = (DIRECTORY / f"test-{milestone}.sh").read_text()
            check = source.split('# Fail closed if pre-link IPv6 setup did not take effect.\n', 1)[1]
            check = check.split('log "[phase 1] kernel topology', 1)[0]
            for enabled in (None, "all", "default", "eth2"):
                with self.subTest(milestone=milestone, enabled=enabled), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    docker = root / "docker"
                    docker.write_text(stub)
                    docker.chmod(0o755)
                    for node in ("vtep", "pe1", "pe2", "ce", "hr"):
                        for interface in ("all", "default", "eth2"):
                            directory = root / node / interface
                            directory.mkdir(parents=True)
                            (directory / "disable_ipv6").write_text(
                                "0\n" if node == "pe1" and interface == enabled else "1\n")
                    result = subprocess.run(
                        ["bash", "-c", 'set -eu; VTEP=vtep; PE1=pe1; PE2=pe2; CE=ce; HR=hr; '
                         'fail() { echo "FAIL $*"; }; ' + check + 'echo REACHED'],
                        env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}", "SYSCTLS": str(root)},
                        text=True, capture_output=True, timeout=5, check=False,
                    )
                    self.assertEqual(result.returncode, 0 if enabled is None else 1, result.stderr)
                    self.assertEqual("REACHED" in result.stdout, enabled is None)


if __name__ == "__main__":
    unittest.main()
