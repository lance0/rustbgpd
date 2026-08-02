#!/usr/bin/env python3
"""Generate the IRR-scale reload scenario for one cell of the IRR reload matrix.

Same harness (`src/main.rs`), same addressing contract as the sibling
generators (stub `i` binds 127.1.(i//200).(i%200+1), ASN 64512+i, announces
/24 slices of the 20.0.0.0-base table, last 8 stubs churn 172.16+c.j.0/24
blocks), but the policy being reloaded is an IRR-scale member policy: every
member carries an IRR-style filter list (its announced slice + its churn
block + deterministic padding prefixes drawn from 30.0.0.0-99.255.255.0),
sized log-uniformly between --min-list and --max-list entries. The whole
generation-varying policy lives in ONE file per daemon, so the harness's
frozen copy-then-reload contract drives every cell unchanged.

Cells:
  rustbgpd      SIGHUP parse-then-swap cell. The member policy is rendered by
                `rs-config-render` (the production IRR pipeline renderer) from
                a synthetic `arouteserver template-context` document built
                from the dataset; the rendered rs-hygiene + per-client .rpol
                files are concatenated (plus the generation marker export
                policy) into gen-a.rpol/gen-b.rpol and the rendered
                config.toml is patched for the loopback bench contract (see
                patch_rendered_config for the exact, asserted edits).
  rustbgpd-txn  gRPC transactional cell. The config-transaction seam rejects
                out-of-band .rpol content changes by design, so this cell
                expresses the same dataset as inline [policy.definitions]
                chain-engine statements; the swapped artifact is a full
                candidate config TOML, applied via `rbgp config plan/apply`.
  bird          BIRD 3.3.x route server; per-member prefix-set defines +
                import filters in the swapped include file, `birdc configure`.
  openbgpd      OpenBGPD 9.x route server; per-member prefix-sets +
                source-as/prefix-set allow rules in the swapped include file,
                `bgpctl reload`.

The dataset is derived only from (n_members, total_prefixes, seed, list
bounds, changed fraction) — never from the cell — so all four cells filter
the SAME member/prefix data. Path-hiding and churn-admission are recorded
emission modes, not canonical member-dataset inputs; disabling churn admission
removes the harness's 172.16-23.x blocks from emitted policies only. Generation
B replaces the first `delta` padding
prefixes of each changed member's list with fresh ones (content-real,
output-neutral: announced and churn prefixes are never touched) and swaps the
export marker community 65400:1000 -> 65400:2000, which forces the full
re-advertisement the harness timestamps for completion. Marker admin 65400 is
deliberately not the route-server ASN (65500): RS-administered standard
communities are RFC 7947 control forms scrubbed from the wire toward members.

Bogon hygiene deliberately omits 172.16.0.0/12: the harness's churn blocks
live at 172.16-23.x and must propagate for the inter-UPDATE gap baseline.

Usage:
    gen-irr-scenario.py <cell> <n_members> <total_prefixes> <out_dir>
        [--port 1790] [--seed 61] [--min-list 1000] [--max-list 40000]
        [--changed-fraction 0.1] [--render-bin PATH] [--threads 8]
        [--conf-dir DIR] [--path-hiding true|false] [--admit-churn true|false]

Emits into <out_dir> (per cell):
  rustbgpd      config.toml, member.rpol (live, = gen-a), gen-a.rpol,
                gen-b.rpol, render-{a,b}/ (rs-config-render output + receipt)
  rustbgpd-txn  config.toml (boot, = gen-a), candidate.toml (live swap file),
                gen-a.toml, gen-b.toml
  bird          bird.conf, gen.conf (live, = gen-a), gen-a.conf, gen-b.conf
  openbgpd      bgpd.conf, gen.conf (live, = gen-a), gen-a.conf, gen-b.conf
plus manifest.json (shape, seed, canonical cell-independent dataset digest,
runtime-input roster, per-member list sizes, changed members, emitted byte
sizes) in every cell.
"""

import argparse
import hashlib
import json
import math
import pathlib
import random
import subprocess
import sys

CHURNERS = 8
CHURN_BLOCK = 16
RS_ASN = 65500  # matches gen-bird/gen-obgpd; not in the stub ASN range
MARKER_ADMIN = 65400
MARKER = {"a": 1000, "b": 2000}  # must match src/main.rs COMMUNITY_GEN_A/B
# Padding prefixes are /24s drawn from 30.0.0.0-99.255.255.0: disjoint from
# the announced base table (20.x-26.x at supported shapes), the churn blocks
# (172.16-23.x) and the bogon list below.
PADDING_FIRST_OCTET = 30
PADDING_SPACE = 70 * 65536
# 172.16.0.0/12 is deliberately absent (churn range, see module docstring).
BOGONS_V4 = ["10.0.0.0/8", "192.168.0.0/16"]
MAX_AS_PATH_LEN = 32
CHURN_PREFIX_STEMS = tuple(f"172.{16 + churner}." for churner in range(CHURNERS))


def stub_addr(i: int) -> str:
    return f"127.1.{i // 200}.{i % 200 + 1}"


def stub_asn(i: int) -> int:
    return 64512 + i


def base_prefix(idx: int) -> str:
    return f"{20 + (idx >> 16)}.{(idx >> 8) & 0xFF}.{idx & 0xFF}.0/24"


def padding_prefix(idx: int) -> str:
    return f"{PADDING_FIRST_OCTET + (idx >> 16)}.{(idx >> 8) & 0xFF}.{idx & 0xFF}.0/24"


def churn_prefixes(churner: int) -> list[str]:
    return [f"172.{16 + churner}.{j}.0/24" for j in range(CHURN_BLOCK)]


class Member:
    def __init__(self, idx, asn, addr, list_a, list_b):
        self.idx = idx
        self.asn = asn
        self.addr = addr
        self.list_a = list_a
        self.list_b = list_b

    def prefixes(self, gen: str) -> list[str]:
        return self.list_a if gen == "a" else self.list_b

    @property
    def changed(self) -> bool:
        return self.list_a != self.list_b


def policy_prefixes(member: Member, gen: str, admit_churn: bool) -> list[str]:
    prefixes = member.prefixes(gen)
    if admit_churn:
        return prefixes
    return [prefix for prefix in prefixes if not prefix.startswith(CHURN_PREFIX_STEMS)]


def build_dataset(args) -> list[Member]:
    """Seeded dataset; identical for every cell (never consult args.cell)."""
    n, total = args.n_members, args.total_prefixes
    per_peer = total // n
    rng = random.Random(args.seed)
    members = []
    for i in range(n):
        target = round(
            math.exp(rng.uniform(math.log(args.min_list), math.log(args.max_list)))
        )
        fixed = [base_prefix(idx) for idx in range(i * per_peer, (i + 1) * per_peer)]
        if i >= n - CHURNERS:
            fixed += churn_prefixes(i - (n - CHURNERS))
        need = max(0, target - len(fixed))
        changed = rng.random() < args.changed_fraction and need > 0
        delta = max(1, need // 100) if changed else 0
        pool = [padding_prefix(p) for p in rng.sample(range(PADDING_SPACE), need + delta)]
        list_a = fixed + pool[:need]
        list_b = fixed + pool[delta : need + delta] if delta else list_a
        members.append(Member(i, stub_asn(i), stub_addr(i), list_a, list_b))
    return members


def check_sun_len(rundir: pathlib.Path) -> str:
    """gRPC UDS path must fit sun_path (~108 bytes); fail early like siblings."""
    sock = f"{rundir}/grpc.sock"
    if len(sock.encode()) > 100:
        sys.exit(
            f"grpc.sock path too long for SUN_LEN ({len(sock)} bytes): {sock}\n"
            f"pass a shorter <out_dir> (e.g. /tmp/irr-rs)."
        )
    return sock


def canonical_member_record(member: Member) -> bytes:
    record = {
        "idx": member.idx,
        "asn": member.asn,
        "addr": member.addr,
        "list_a": member.list_a,
        "list_b": member.list_b,
    }
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def write_manifest(out: pathlib.Path, args, members, files: list[str]) -> None:
    dataset_digest = hashlib.sha256()
    for member in members:
        dataset_digest.update(canonical_member_record(member))
    path_hiding_applicable = args.cell in ("rustbgpd", "rustbgpd-txn")
    manifest = {
        "cell": args.cell,
        "n_members": args.n_members,
        "total_prefixes": args.total_prefixes,
        "seed": args.seed,
        "min_list": args.min_list,
        "max_list": args.max_list,
        "changed_fraction": args.changed_fraction,
        "path_hiding": args.path_hiding if path_hiding_applicable else None,
        "path_hiding_requested": args.path_hiding,
        "path_hiding_applicable": path_hiding_applicable,
        "admit_churn": args.admit_churn,
        "bmp_collector": args.bmp_collector,
        "bmp_version": 3 if args.bmp_collector is not None else None,
        "bmp_view": "loc_rib" if args.bmp_collector is not None else None,
        "dataset_sha256": dataset_digest.hexdigest(),
        "list_sizes": [len(policy_prefixes(m, "a", args.admit_churn)) for m in members],
        "total_filter_entries": sum(
            len(policy_prefixes(m, "a", args.admit_churn)) for m in members
        ),
        "changed_members": [m.idx for m in members if m.changed],
        "runtime_files": files,
        "file_bytes": {f: (out / f).stat().st_size for f in files},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")


# --- rustbgpd (SIGHUP) cell -------------------------------------------------


def context_doc(
    members: list[Member], gen: str, path_hiding: bool, admit_churn: bool
) -> dict:
    """Synthetic `arouteserver template-context` single-document form.

    Modeled on tools/rs-config-render/tests/fixtures/context-small.yml (the
    top-level keys are pinned by the renderer's shape fingerprint). JSON is
    valid YAML, so the document is emitted with json.dumps. Knob intents:
    reject_invalid_as_in_as_path=false (stub ASNs are RFC 6996 private —
    the hygiene private-ASN term would reject every route), RPKI disabled
    (no RTR cache in the bench), max_prefix absent (no ceilings: announced
    slices are tiny and ceilings are not what this harness measures).
    """
    asns, irrdb, clients = {}, {}, []
    for m in members:
        bundle = f"AS{m.asn}_bundle"
        asns[f"AS{m.asn}"] = {"as_sets": [f"AS-IRRBENCH-M{m.idx}"]}
        irrdb[bundle] = {
            "asns": [m.asn],
            "prefixes": [
                {
                    "prefix": p.split("/")[0],
                    "length": int(p.split("/")[1]),
                    "exact": True,
                }
                for p in policy_prefixes(m, gen, admit_churn)
            ],
        }
        clients.append(
            {
                "id": f"AS{m.asn}_1",
                "asn": m.asn,
                "ip": m.addr,
                "description": f"member-{m.idx}",
                "cfg": {
                    "rfc8950": False,
                    "blackhole_filtering": {"announce_to_client": True},
                    "filtering": {"irrdb": {"as_set_bundle_ids": [bundle]}},
                },
            }
        )
    return {
        "ip_ver": None,
        "list_ip_vers": [4, 6],
        "live_tests": False,
        "rtt_based_functions_are_used": False,
        "perform_graceful_shutdown": False,
        "any_reject_cause_map_community_set": False,
        "asn3216_map": {},
        "arin_whois_records": {},
        "registrobr_whois_records": {},
        "rpki_roas": {},
        "reject_reasons": {"1": "Invalid AS_PATH length", "2": "Prefix is bogon"},
        "never_via_route_servers_asns": [],
        "bogons": [
            {
                "prefix": p.split("/")[0],
                "length": int(p.split("/")[1]),
                "comment": "bench bogon (172.16/12 omitted: harness churn range)",
            }
            for p in BOGONS_V4
        ],
        "cfg": {
            "rs_as": RS_ASN,
            "router_id": "10.0.0.1",
            "prepend_rs_as": False,
            "path_hiding": path_hiding,
            "passive": True,
            "gtsm": False,
            "multihop": None,
            "add_path": False,
            "rfc8950": False,
            "graceful_shutdown": {"enabled": True, "local_pref": 0},
            "blackhole_filtering": {
                "policy_ipv4": None,
                "policy_ipv6": None,
                "announce_to_client": True,
            },
            "rtt_thresholds": None,
            "communities": {
                "blackholing": {"std": None, "lrg": None, "ext": None},
                "do_not_announce_to_any": {
                    "std": f"0:{RS_ASN}",
                    "lrg": None,
                    "ext": None,
                },
                "do_not_announce_to_peers_with_rtt_lower_than": {
                    "std": None,
                    "lrg": None,
                    "ext": None,
                },
            },
            "filtering": {
                "next_hop": {"policy": "strict"},
                "ipv4_pref_len": {"min": 8, "max": 24},
                "ipv6_pref_len": {"min": 12, "max": 48},
                "global_black_list_pref": [
                    {"prefix": "192.0.2.0", "length": 24, "comment": "out-of-table"}
                ],
                "max_as_path_len": MAX_AS_PATH_LEN,
                "reject_invalid_as_in_as_path": False,
                "transit_free": {"action": "reject", "asns": [174, 3356]},
                "irrdb": {
                    "enforce_origin_in_as_set": True,
                    "enforce_prefix_in_as_set": True,
                    "allow_longer_prefixes": False,
                    "tag_as_set": True,
                },
                "rpki_bgp_origin_validation": {"enabled": False, "reject_invalid": False},
                "max_prefix": {
                    "action": None,
                    "count_rejected_routes": False,
                    "peering_db": {"enabled": False},
                    "restart_after": None,
                    "general_limit_ipv4": 0,
                    "general_limit_ipv6": 0,
                },
                "reject_policy": {"policy": "reject"},
            },
        },
        "asns": asns,
        "clients": clients,
        "irrdb_info": irrdb,
    }


def marker_policy_rpol(gen: str) -> str:
    return (
        "\n# Generation marker export policy — appended by gen-irr-scenario.py.\n"
        "# The harness samples this community off decoded UPDATEs to timestamp\n"
        "# reload completion (same mechanics as the IXP receipt matrix).\n"
        "policy irr-member-out {\n"
        f"    term tag {{ add community {MARKER_ADMIN}:{MARKER[gen]}; accept }}\n"
        "}\n"
    )


def bench_telemetry_block(rundir: pathlib.Path) -> str:
    return (
        "[global.telemetry]\n"
        'log_format = "json"\n'
        'prometheus_addr = "127.0.0.1:9179"\n'
        "\n"
        "[global.telemetry.grpc_uds]\n"
        f'path = "{rundir}/grpc.sock"\n'
        "\n"
        "[security.grpc]\n"
        "# Loopback benchmark: UDS access is gated by file perms.\n"
        'enforcement = "legacy"\n'
        "\n"
    )


def bench_bmp_block(collector: str | None) -> str:
    if collector is None:
        return ""
    return (
        "\n[bmp]\n"
        'sys_name = "rustbgpd-irr-buffer-receipt"\n'
        'sys_descr = "IRR-scale Loc-RIB dump buffer receipt"\n'
        "\n"
        "[[bmp.collectors]]\n"
        f'address = "{collector}"\n'
        "reconnect_interval = 1\n"
        'monitor = ["loc_rib"]\n'
    )


def patch_rendered_config(
    text: str,
    n: int,
    port: int,
    rundir: pathlib.Path,
    bmp_collector: str | None = None,
) -> str:
    """Adapt rs-config-render output to the loopback bench contract.

    Every edit is asserted so renderer-output drift fails loudly instead of
    producing a silently different scenario. Policy content (the rendered
    .rpol files) is never touched here — only session/telemetry plumbing:
      - listen_port + runtime_state_dir for the bench port and run dir;
      - the telemetry/security block (bench UDS path, prometheus, legacy);
      - next_hop_ownership dropped (the harness's synthetic 10.9.x.y
        NEXT_HOP is not the peer address; BIRD/OpenBGPD cells get the
        equivalent accommodation: `next hop keep` glue / `nexthop qualify
        via default`) — replaced by the sibling generators' hold_time;
      - rpol_files collapsed to the single swapped file; export chain
        pointed at the generation marker policy.
    """

    def replace_once(haystack: str, old: str, new: str) -> str:
        assert haystack.count(old) == 1, f"expected exactly one {old!r} in rendered config"
        return haystack.replace(old, new)

    text = replace_once(
        text,
        "listen_port = 179\n",
        f"listen_port = {port}\nruntime_state_dir = \"{rundir}\"\n",
    )
    tele = text.index("[global.telemetry]")
    export_anchor = text.index("# --- Export policy")
    assert tele < export_anchor
    text = text[:tele] + bench_telemetry_block(rundir) + text[export_anchor:]

    count = text.count('next_hop_ownership = "strict_peer"\n')
    assert count == n, f"expected {n} next_hop_ownership lines, found {count}"
    text = text.replace('next_hop_ownership = "strict_peer"\n', "hold_time = 180\n")

    files_start = text.index("rpol_files = [")
    files_end = text.index("]", files_start) + 1
    text = text[:files_start] + 'rpol_files = ["member.rpol"' + text[files_end - 1 :]
    text = replace_once(
        text,
        'export_chain = ["rs-transparent-export"]\n',
        'export_chain = ["irr-member-out"]\n',
    )
    assert "max_prefixes" not in text, "unexpected max-prefix ceilings in bench render"
    return text.rstrip() + "\n" + bench_bmp_block(bmp_collector)


def emit_rustbgpd(args, members: list[Member], out: pathlib.Path) -> list[str]:
    if not args.render_bin:
        sys.exit("cell rustbgpd requires --render-bin (path to rs-config-render)")
    rundir = out.resolve()
    check_sun_len(rundir)
    for gen in ("a", "b"):
        ctx = out / f"context-{gen}.json"
        ctx.write_text(
            json.dumps(context_doc(members, gen, args.path_hiding, args.admit_churn))
        )
        render_dir = out / f"render-{gen}"
        subprocess.run(
            [
                args.render_bin,
                "--context",
                str(ctx),
                "--out-dir",
                str(render_dir),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        rendered_config = (render_dir / "config.toml").read_text()
        # Concatenate the rendered policy files in the order config.toml
        # references them, then append the generation marker policy.
        parts = []
        for line in rendered_config.splitlines():
            line = line.strip()
            if line.startswith('"policy/') and line.endswith('",'):
                parts.append((render_dir / line.strip('",')).read_text())
        assert len(parts) == len(members) + 1, "rendered rpol roster mismatch"
        (out / f"gen-{gen}.rpol").write_text("".join(parts) + marker_policy_rpol(gen))
        if gen == "a":
            (out / "config.toml").write_text(
                patch_rendered_config(
                    rendered_config,
                    len(members),
                    args.port,
                    rundir,
                    args.bmp_collector,
                )
            )
    (out / "member.rpol").write_text((out / "gen-a.rpol").read_text())
    return ["config.toml", "member.rpol", "gen-a.rpol", "gen-b.rpol"]


# --- rustbgpd-txn (gRPC transactional) cell ---------------------------------


def txn_config(args, members: list[Member], gen: str, rundir: pathlib.Path) -> str:
    """Full candidate config: the same dataset as [policy.definitions] chains.

    The transaction seam refuses out-of-band .rpol content changes by
    design (docs/reload-matrix.md), so this cell carries the policy in the
    inline chain engine: per member an origin definition (AS_PATH origin
    anchor) and a prefix-list definition (one exact-match statement per
    filter entry), plus a shared hygiene definition (path-length cap +
    bogons; the AS_SET-segment regex term of rs-hygiene has no inline
    equivalent — documented in the harness README) and the generation
    marker export definition.
    """
    lines = [
        "# IRR reload-matrix transactional candidate — generated by",
        f"# gen-irr-scenario.py (generation {gen}).",
        "",
        "[global]",
        f"asn = {RS_ASN}",
        'router_id = "10.0.0.1"',
        f"listen_port = {args.port}",
        f'runtime_state_dir = "{rundir}"',
        "",
        bench_telemetry_block(rundir).rstrip(),
        "",
        "[policy]",
        'export_chain = ["irr-member-out"]',
        "",
        "[policy.definitions.irr-hygiene]",
        'default_action = "permit"',
        "[[policy.definitions.irr-hygiene.statements]]",
        'action = "deny"',
        f"match_as_path_length_ge = {MAX_AS_PATH_LEN + 1}",
    ]
    for bogon in BOGONS_V4:
        lines += [
            "[[policy.definitions.irr-hygiene.statements]]",
            'action = "deny"',
            f'prefix = "{bogon}"',
            f"ge = {bogon.split('/')[1]}",
            "le = 32",
        ]
    lines += [
        "",
        "[policy.definitions.irr-member-out]",
        'default_action = "permit"',
        "[[policy.definitions.irr-member-out.statements]]",
        'action = "permit"',
        'prefix = "0.0.0.0/0"',
        "ge = 0",
        "le = 32",
        f'set_community_add = ["{MARKER_ADMIN}:{MARKER[gen]}"]',
        "",
    ]
    for m in members:
        lines += [
            f"[policy.definitions.m{m.idx}-origin]",
            'default_action = "deny"',
            f"[[policy.definitions.m{m.idx}-origin.statements]]",
            'action = "permit"',
            f'match_as_path = "_{m.asn}$"',
            "",
            f"[policy.definitions.m{m.idx}-prefixes]",
            'default_action = "deny"',
        ]
        for p in policy_prefixes(m, gen, args.admit_churn):
            lines += [
                f"[[policy.definitions.m{m.idx}-prefixes.statements]]",
                'action = "permit"',
                f'prefix = "{p}"',
            ]
        lines.append("")
    for m in members:
        lines += [
            "[[neighbors]]",
            f'address = "{m.addr}"',
            f"remote_asn = {m.asn}",
            "route_server_client = true",
            *(["per_client_best = true"] if args.path_hiding else []),
            'families = ["ipv4_unicast"]',
            "hold_time = 180",
            f'import_policy_chain = ["irr-hygiene", "m{m.idx}-origin", "m{m.idx}-prefixes"]',
            "",
        ]
    return "\n".join(lines)


def emit_txn(args, members: list[Member], out: pathlib.Path) -> list[str]:
    rundir = out.resolve()
    check_sun_len(rundir)
    for gen in ("a", "b"):
        (out / f"gen-{gen}.toml").write_text(txn_config(args, members, gen, rundir))
    boot = (out / "gen-a.toml").read_text()
    (out / "config.toml").write_text(boot)
    (out / "candidate.toml").write_text(boot)
    return ["config.toml", "candidate.toml", "gen-a.toml", "gen-b.toml"]


# --- BIRD cell ---------------------------------------------------------------


def bird_gen_conf(members: list[Member], gen: str, admit_churn: bool) -> str:
    out = [
        "# IRR reload-matrix policy generation - generated by gen-irr-scenario.py.",
        "# Swapped over gen.conf, then `birdc configure`. One prefix-set define +",
        "# one import filter per member; the export filter tags the generation",
        "# marker community the harness tracks for completion.",
        "# 172.16/12 is absent from the bogons: harness churn range.",
        "",
        "define IRR_BOGONS = [ " + ", ".join(f"{b}+" for b in BOGONS_V4) + " ];",
        "",
        "filter member_out {",
        f"    bgp_community.add(({MARKER_ADMIN},{MARKER[gen]}));",
        "    accept;",
        "}",
        "",
    ]
    for m in members:
        prefixes = policy_prefixes(m, gen, admit_churn)
        out.append(f"define M{m.idx}_PFX = [")
        for k in range(0, len(prefixes), 8):
            row = ", ".join(prefixes[k : k + 8])
            out.append(f"    {row}{',' if k + 8 < len(prefixes) else ''}")
        out += [
            "];",
            f"filter member_in_{m.idx} {{",
            f"    if bgp_path.len > {MAX_AS_PATH_LEN} then reject;",
            "    if net ~ IRR_BOGONS then reject;",
            f"    if bgp_path.last != {m.asn} then reject;",
            f"    if ! (net ~ M{m.idx}_PFX) then reject;",
            "    accept;",
            "}",
            "",
        ]
    return "\n".join(out)


def emit_bird(args, members: list[Member], out: pathlib.Path) -> list[str]:
    conf_dir = args.conf_dir or "/etc/bird"
    for gen in ("a", "b"):
        (out / f"gen-{gen}.conf").write_text(
            bird_gen_conf(members, gen, args.admit_churn)
        )
    (out / "gen.conf").write_text((out / "gen-a.conf").read_text())
    config = [
        "# IRR reload-matrix BIRD route server - generated by gen-irr-scenario.py.",
        "# Run: docker run -d --network=host -v <out_dir>:/etc/bird bird:3.3.1 \\",
        "#          bird -f -c /etc/bird/bird.conf",
        "# Reload: overwrite gen.conf, then `birdc configure`.",
        "",
        'router id 10.0.0.1;',
        f"threads {args.threads};",
        "log stderr all;",
        "",
        "protocol device { scan time 10; }",
        "",
        "# NEXT_HOP glue (same as gen-bird-scenario.py): the stubs' synthetic",
        "# 10.9.x.y next hops resolve through device routes over lo.",
        "protocol static nh_glue {",
        "    ipv4;",
        '    route 10.9.0.0/16 via "lo";',
        '    route 127.1.0.0/16 via "lo";',
        "}",
        "",
        f'include "{conf_dir}/gen.conf";',
        "",
        "template bgp rs_member {",
        f"    local 127.0.0.1 port {args.port} as {RS_ASN};",
        "    rs client;",
        "    passive;",
        "    multihop;",
        "    hold time 180;",
        "}",
        "",
    ]
    for m in members:
        config += [
            f"protocol bgp peer{m.idx} from rs_member {{",
            f"    neighbor {m.addr} as {m.asn};",
            "    ipv4 {",
            f"        import filter member_in_{m.idx};",
            "        export filter member_out;",
            "        next hop keep;",
            "        gateway recursive;",
            "    };",
            "}",
        ]
    config.append("")
    (out / "bird.conf").write_text("\n".join(config))
    return ["bird.conf", "gen.conf", "gen-a.conf", "gen-b.conf"]


# --- OpenBGPD cell -----------------------------------------------------------


def obgpd_gen_conf(members: list[Member], gen: str, admit_churn: bool) -> str:
    out = [
        "# IRR reload-matrix policy generation - generated by gen-irr-scenario.py.",
        "# Swapped over gen.conf, then `bgpctl reload`. Prefix-sets first, then",
        "# the import ruleset (last matching rule wins; hygiene denies are",
        "# quick). The trailing match tags the generation marker community.",
        "# 172.16/12 is absent from the bogons: harness churn range.",
        "",
    ]
    for m in members:
        prefixes = policy_prefixes(m, gen, admit_churn)
        out.append(f"prefix-set ps{m.idx} {{")
        for k in range(0, len(prefixes), 8):
            out.append("\t" + " ".join(prefixes[k : k + 8]))
        out.append("}")
    out += [
        "",
        "deny from any",
        f"deny quick from any max-as-len {MAX_AS_PATH_LEN}",
    ]
    out += [f"deny quick from any prefix {b} or-longer" for b in BOGONS_V4]
    out += [
        f"allow from {m.addr} source-as {m.asn} prefix-set ps{m.idx}" for m in members
    ]
    out += [
        f"match to any set community {MARKER_ADMIN}:{MARKER[gen]}",
        "",
    ]
    return "\n".join(out)


def emit_obgpd(args, members: list[Member], out: pathlib.Path) -> list[str]:
    conf_dir = args.conf_dir or "/etc/bgpd"
    for gen in ("a", "b"):
        (out / f"gen-{gen}.conf").write_text(
            obgpd_gen_conf(members, gen, args.admit_churn)
        )
    (out / "gen.conf").write_text((out / "gen-a.conf").read_text())
    config = [
        "# IRR reload-matrix OpenBGPD route server - generated by gen-irr-scenario.py.",
        "# Run: docker run -d --network=host -v <out_dir>:/etc/bgpd openbgpd/openbgpd:9.1",
        "# Reload: overwrite gen.conf, then `bgpctl reload`.",
        "",
        f"AS {RS_ASN}",
        "router-id 10.0.0.1",
        "fib-update no",
        "transparent-as yes",
        f"listen on 127.0.0.1 port {args.port}",
        "",
        "# Synthetic 10.9.x.y next hops qualify via the host's default route",
        "# (same as gen-obgpd-scenario.py; the host MUST have a default route).",
        "nexthop qualify via default",
        "",
    ]
    for m in members:
        config += [
            f"neighbor {m.addr} {{",
            f'\tdescr "member{m.idx}"',
            f"\tremote-as {m.asn}",
            "\tpassive",
            "\tholdtime 180",
            "\tannounce IPv4 unicast",
            "}",
        ]
    config += [
        "",
        "allow to any set nexthop no-modify",
        f'include "{conf_dir}/gen.conf"',
        "",
    ]
    (out / "bgpd.conf").write_text("\n".join(config))
    return ["bgpd.conf", "gen.conf", "gen-a.conf", "gen-b.conf"]


EMITTERS = {
    "rustbgpd": emit_rustbgpd,
    "rustbgpd-txn": emit_txn,
    "bird": emit_bird,
    "openbgpd": emit_obgpd,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("cell", choices=sorted(EMITTERS))
    parser.add_argument("n_members", type=int)
    parser.add_argument("total_prefixes", type=int)
    parser.add_argument("out_dir", type=pathlib.Path)
    parser.add_argument("--port", type=int, default=1790)
    parser.add_argument("--seed", type=int, default=61)
    parser.add_argument("--min-list", type=int, default=1000)
    parser.add_argument("--max-list", type=int, default=40000)
    parser.add_argument("--changed-fraction", type=float, default=0.1)
    parser.add_argument("--render-bin", help="rs-config-render binary (rustbgpd cell)")
    parser.add_argument("--threads", type=int, default=8, help="BIRD threads knob")
    parser.add_argument("--conf-dir", help="config dir as seen by the running daemon")
    parser.add_argument(
        "--bmp-collector",
        help="optional host:port for one v3 Loc-RIB-only BMP collector",
    )
    parser.add_argument(
        "--path-hiding",
        choices=("true", "false"),
        default="true",
        help="render per-client best-path mitigation (default: true)",
    )
    parser.add_argument(
        "--admit-churn",
        choices=("true", "false"),
        default="true",
        help="include harness churn blocks in emitted import policies (default: true)",
    )
    parser.add_argument(
        "--canonical-dataset-out",
        type=pathlib.Path,
        help="test/debug output: stream the exact cell-independent digest input",
    )
    args = parser.parse_args()
    args.path_hiding = args.path_hiding == "true"
    args.admit_churn = args.admit_churn == "true"

    if args.bmp_collector is not None and args.cell != "rustbgpd":
        sys.exit("--bmp-collector is supported only by the rustbgpd cell")
    if args.n_members < CHURNERS:
        sys.exit(f"n_members must be >= {CHURNERS} (harness churner contract)")
    if args.total_prefixes % args.n_members:
        sys.exit("total_prefixes must divide evenly by n_members (harness contract)")
    if not 1 <= args.min_list <= args.max_list:
        sys.exit("need 1 <= min_list <= max_list")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    members = build_dataset(args)
    if args.canonical_dataset_out is not None:
        with args.canonical_dataset_out.open("wb") as canonical:
            for member in members:
                canonical.write(canonical_member_record(member))
    files = EMITTERS[args.cell](args, members, args.out_dir)
    write_manifest(args.out_dir, args, members, files)
    total_entries = sum(len(policy_prefixes(m, "a", args.admit_churn)) for m in members)
    swapped = files[1]  # the live swap file in every cell's roster
    print(
        f"wrote {args.out_dir.resolve()} cell={args.cell} members={args.n_members} "
        f"filter_entries={total_entries} changed_members="
        f"{sum(1 for m in members if m.changed)} "
        f"swapped_file={swapped} ({(args.out_dir / swapped).stat().st_size} bytes)"
    )


if __name__ == "__main__":
    main()
