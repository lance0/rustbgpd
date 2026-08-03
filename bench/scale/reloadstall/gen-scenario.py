#!/usr/bin/env python3
"""Generate the daemon-side scenario the reloadstall harness drives.

The harness (`src/main.rs`) is only the client side: N real BGP stub
sessions that dial a *running* rustbgpd route server. This script emits the
route server it dials — a config with N route-server-client neighbors and
the two `.rpol` policy generations the harness alternates on each SIGHUP —
so the receipt in `docs/perf/reload-stall-2026-07.md` reproduces from the
repo alone.

Addressing MUST match `src/main.rs`: stub `i` binds source
`127.1.(i//200).(i%200+1)` (`stub_addr`) with ASN `64512+i` (`stub_asn`)
and BGP-id `240.1.x.y` (higher than the daemon's router-id, so the inbound
connection wins RFC 4271 §6.8 collision resolution against the daemon's
active dial to the unreachable stub port 179). The base table lives in
`20.0.0.0 .. 26.x` (`base_prefix`). In historical mode, the import-chain
reject prefix changes between two out-of-table values, so the import change is
content-real and fires Route Refresh but remains output-neutral. In explicit
`changed_peers` mode, `member-in` is byte-for-byte stable and only the selected
observers' effective export chain changes.

Both generations define the same policy names. `member-out` changes body;
`member-in` changes only in historical mode, and explicit mixed mode also
defines a content-stable `stable-out`. Only one file is loaded at a time
(copied over the live file per reload), so there is no shared-namespace
collision and the TOML chain-name references stay valid across swaps.

Usage:
    gen-scenario.py <n_peers> <out_dir> [listen_port] [changed_peers]

Emits into <out_dir>: config.toml, member.rpol (live, starts as gen-a),
gen-a.rpol (community 65400:1000), gen-b.rpol (community 65400:2000).
Marker communities deliberately avoid the RS ASN's administrator space:
rs_control_communities defaults on for the route-server-client neighbors,
and RS-administered standard communities are control forms scrubbed from
the wire (which would hide the generation markers from the observers).
The optional `changed_peers` selects the first N neighbors whose effective
export chain changes. The remaining neighbors receive a content-stable
per-neighbor `stable-out` chain, while the import chain remains content-stable
for every neighbor. Omitting it preserves the historical changed-import-plus-
export scenario. The mixed export-only receipt uses 700 peers, 600 changed
peers, 400400 total prefixes (harness arg), and port 1790.
"""
import pathlib
import sys

if len(sys.argv) < 3:
    sys.exit(__doc__)

n_peers = int(sys.argv[1])
out = pathlib.Path(sys.argv[2])
port = int(sys.argv[3]) if len(sys.argv) > 3 else 1790
changed_peers = int(sys.argv[4]) if len(sys.argv) > 4 else n_peers
if not 0 < changed_peers <= n_peers:
    sys.exit(f"changed_peers must be in 1..={n_peers}, got {changed_peers}")
mixed_export_only = len(sys.argv) > 4
out.mkdir(parents=True, exist_ok=True)
rundir = out.resolve()

# The gRPC UDS path lives under rundir and is bound with bind(2), which caps
# sun_path at ~108 bytes (SUN_LEN). A long out_dir (e.g. a deep scratchpad)
# makes the daemon fail to bind and shut down; fail here instead. Keep out_dir
# short, e.g. /tmp/rls/full.
sock = f"{rundir}/grpc.sock"
if len(sock.encode()) > 100:
    sys.exit(f"grpc.sock path too long for SUN_LEN ({len(sock)} bytes): {sock}\n"
             f"pass a shorter <out_dir> (e.g. /tmp/rls/full).")

# RFC 6996 private four-octet ASN, disjoint from every supported stub ASN.
GLOBAL_ASN = 4200000000


def stub_addr(i: int) -> str:
    return f"127.1.{i // 200}.{i % 200 + 1}"


def stub_asn(i: int) -> int:
    return 64512 + i


# (filename, import-reject prefix, export community) per generation. The mixed
# mode deliberately keeps the import body equal so its selected changed-member
# cohort is genuinely export-only.
#
# Marker communities MUST NOT be administered by GLOBAL_ASN (or 0): the
# config's route-server-client neighbors default rs_control_communities on,
# and standard communities under the RS ASN are RFC 7947 §2.3.2 control
# forms — scrubbed from the wire toward enabled members, which would blind
# the harness to its own generation evidence. 65400 may be a stub ASN; it is
# neither GLOBAL_ASN nor zero, which is the control-community distinction.
GENERATIONS = [
    ("gen-a.rpol", "192.0.2.0/24", "65400:1000"),
    (
        "gen-b.rpol",
        "192.0.2.0/24" if mixed_export_only else "198.51.100.0/24",
        "65400:2000",
    ),
]

for fname, reject_prefix, community in GENERATIONS:
    if mixed_export_only:
        policy_description = f"""# member-in is byte-for-byte stable across generations.
# Only the first {changed_peers} observers use member-out, whose community changes;
# the remaining observers use the content-stable stable-out chain."""
    else:
        policy_description = f"""# member-in rejects one out-of-table prefix ({reject_prefix} is outside the
# announced 20.0.0.0-26.x base table), so the import chain is content-real:
# reinstalled per peer, Route Refreshes fire, and routes re-enter the new chain.
# member-out tags every advertised route with the generation community."""
    stable_policy = """

policy stable-out {
    term tag { add community 65400:9000; accept }
}
""" if mixed_export_only else ""
    (out / fname).write_text(
        f"""# reload-stall policy generation - generated by gen-scenario.py.
#
{policy_description}
# The harness samples the export community to confirm the live generation.
policy member-in {{
    term drop-blocked {{ if route.prefix == {reject_prefix} {{ reject }} }}
    term default {{ accept }}
}}

policy member-out {{
    term tag {{ add community {community}; accept }}
}}
{stable_policy}
"""
    )

# The live file starts as generation A; the harness copies gen-a/gen-b over it.
(out / "member.rpol").write_text((out / "gen-a.rpol").read_text())

config = [
    "# reload-stall route-server scenario — generated by gen-scenario.py.",
    "# Stock daemon config: worker_threads unset => min(CPU, 8), matching the",
    "# receipt. Start load-gated (1-min loadavg < 2.0), --release.",
    "",
    "[global]",
    f"asn = {GLOBAL_ASN}",
    'router_id = "10.0.0.1"',  # < 240.1.x.y so the stubs win collision resolution
    f"listen_port = {port}",
    f'runtime_state_dir = "{rundir}"',
    "",
    "[global.telemetry]",
    'log_format = "json"',  # reload wall time comes from the JSON "config reload complete" line
    # /metrics + /readyz endpoint. The actor-poll histogram
    # (bgp_rib_policy_transition_actor_poll_duration_seconds, partitioned by
    # poll_kind bounded/prefix_snapshot/finalize) and the 200 ms core-readiness
    # probe are scraped here for the actor-ceiling receipt.
    'prometheus_addr = "127.0.0.1:9179"',
    "",
    "[global.telemetry.grpc_uds]",
    # The `rbgp health` control-query probe dials this owner-only socket and
    # authorizes as the implicit local-operator — no [security.grpc] needed.
    f'path = "{rundir}/grpc.sock"',
    "",
    "[policy]",
    'rpol_files = ["member.rpol"]',
    'import_chain = ["member-in"]',
    'export_chain = ["member-out"]',
    "",
]
for i in range(n_peers):
    neighbor = [
        "[[neighbors]]",
        f'address = "{stub_addr(i)}"',
        f"remote_asn = {stub_asn(i)}",
        "route_server_client = true",
        'families = ["ipv4_unicast"]',
        "hold_time = 180",
    ]
    if i >= changed_peers:
        neighbor.append('export_policy_chain = ["stable-out"]')
    config += neighbor + [""]
(out / "config.toml").write_text("\n".join(config))

print(
    f"wrote {rundir}/config.toml ({n_peers} neighbors), member.rpol, "
    f"gen-a.rpol, gen-b.rpol; listen_port={port}, changed_peers={changed_peers}, "
    f"stable_peers={n_peers - changed_peers}, grpc_uds={rundir}/grpc.sock"
)
