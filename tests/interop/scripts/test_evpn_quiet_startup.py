#!/usr/bin/env python3
"""Run EVPN helper setup with stub commands and pin multicast-before-up order."""

import json
import os
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


if __name__ == "__main__":
    unittest.main()
