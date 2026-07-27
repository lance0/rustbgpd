#!/usr/bin/env python3
"""Generate the single-peer daemon config for the RFC 7313 receipt.

Usage:
    gen-scenario.py <output-directory> [listen-port] [metrics-port]
"""

import pathlib
import sys

if not 2 <= len(sys.argv) <= 4:
    sys.exit(__doc__)

output = pathlib.Path(sys.argv[1]).resolve()
listen_port = int(sys.argv[2]) if len(sys.argv) >= 3 else 1793
metrics_port = int(sys.argv[3]) if len(sys.argv) >= 4 else 9183
output.mkdir(parents=True, exist_ok=True)

runtime = str(output)
socket = str(output / "grpc.sock")
if len(socket.encode()) > 100:
    sys.exit(f"gRPC UDS path exceeds the conservative SUN_LEN bound: {socket}")

(output / "config.toml").write_text(
    f"""# Generated Enhanced Route Refresh receipt scenario.
[global]
asn = 4200000000
router_id = "10.0.0.1"
listen_port = {listen_port}
runtime_state_dir = "{runtime}"

[global.telemetry]
log_format = "json"
prometheus_addr = "127.0.0.1:{metrics_port}"

[global.telemetry.grpc_uds]
path = "{socket}"

[security.grpc]
enforcement = "legacy"

[[neighbors]]
address = "127.1.0.1"
remote_asn = 64512
route_server_client = true
families = ["ipv4_unicast"]
hold_time = 600
max_prefixes = 100000
max_prefixes_ipv4 = 100000
""",
    encoding="utf-8",
)
print(
    f"wrote {output / 'config.toml'}; listen_port={listen_port}; "
    f"metrics_port={metrics_port}; peer=127.1.0.1"
)
