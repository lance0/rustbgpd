#!/usr/bin/env python3
"""Reduce one M123 phase snapshot to RFC 9785 facts and compare expectations.

    m123_dont_preempt_oracle.py DIR EXPECT_JSON   check one phase, write facts.json
    m123_dont_preempt_oracle.py replay ROOT       re-check every phase under ROOT

A phase directory holds rbgp `evpn es list -j` and `evpn --route-type 4 -j`
(ListEvpnRoutes), SR Linux ES and BGP RIB state, and the CE bond report.
Type 4 DF Election values are decoded from the raw extended community on the
rustbgpd side and from SR Linux's own rendering on the SR Linux side, so each
PE's view of the other is its own decoding of the wire.
"""

from datetime import datetime
import json
from pathlib import Path
import re
import sys

ESI = "00:01:23:00:00:00:00:00:00:01"
RUST = "10.0.123.1"
SRL = "192.0.2.2"
HIGHEST_PREFERENCE = 2
ROLE_STAMP_JITTER = 1.0
SRL_DF = re.compile(r"df-election::DF-Type:(\w+)/DP:([01])/DF-Preference:(\d+)/AC:[01]")


def read(directory, name):
    return json.loads((directory / name).read_text())


def df_extcomm(values):
    """RFC 8584 / RFC 9785 DF Election extcomm (0x06/0x06) as [pref, dp]."""
    found = []
    for value in values:
        raw = int(value).to_bytes(8, "big")
        if raw[:2] == b"\x06\x06":
            alg = raw[2] & 0x1F
            if alg != HIGHEST_PREFERENCE:
                found.append(f"alg{alg}")
            else:
                found.append([int.from_bytes(raw[6:8], "big"), bool(raw[3] & 0x80)])
    return found[0] if len(found) == 1 else (found or None)


def rust_facts(directory):
    segments = [s for s in read(directory, "rust-es.json")["segments"] if s["esi"] == ESI]
    if not segments:
        # The daemon is stopped: the driver records an empty listing.
        return dict.fromkeys(
            (
                "rust_role",
                "rust_admin",
                "rust_advertised",
                "rust_recovery_pending",
                "rust_drained",
                "rust_own_type4",
                "rust_decoded_srl",
            )
        )
    segment = segments[0]
    roles = [m.get("df_role", "") for m in segment["members"]]
    routes = [
        r for r in read(directory, "rust-type4.json") if r["route_type"] == 4 and r["esi"] == ESI
    ]

    def type4(origin):
        rows = [r for r in routes if r["ip"] == origin]
        return (
            df_extcomm(rows[0]["extended_communities"])
            if len(rows) == 1
            else (None if not rows else "duplicate")
        )

    return {
        "rust_role": roles[0] if len(roles) == 1 else roles,
        "rust_admin": [segment["df_preference"], segment["df_dont_preempt"]],
        "rust_advertised": [
            segment["advertised_df_preference"],
            segment["advertised_df_dont_preempt"],
        ],
        "rust_recovery_pending": segment["df_recovery_pending"],
        "rust_drained": segment["drained"],
        "rust_own_type4": type4(RUST),
        "rust_decoded_srl": type4(SRL),
    }


def srl_facts(directory):
    es = read(directory, "srl-es.json")
    alg = es["df-election"]["algorithm"]["preference-alg"]
    candidates, changed = {}, None
    for instance in es.get("association", {}).get("network-instance", []):
        for bgp in instance.get("bgp-instance", []):
            changed = bgp.get("designated-forwarder-role-last-change", "").split(" ")[0] or None
            rows = bgp.get("computed-designated-forwarder-candidates", {})
            for row in rows.get("designated-forwarder-candidate", []):
                candidates[row["address"]] = row["designated-forwarder"]
    rib = read(directory, "srl-rib.json")
    attrs = {a["index"]: a for a in rib.get("attr-sets", {}).get("attr-set", [])}
    routes = [
        r
        for afi in rib.get("afi-safi", [])
        for r in afi.get("evpn", {}).get("local-rib", {}).get("ethernet-segment-route", [])
        if r["esi"] == ESI
    ]

    def type4(origin):
        rows = [r for r in routes if r["originating-router"] == origin]
        if len(rows) != 1:
            return None if not rows else "duplicate"
        communities = attrs[rows[0]["attr-id"]].get("communities", {}).get("ext-community", [])
        found = [m for m in map(SRL_DF.fullmatch, communities) if m]
        if len(found) != 1:
            return "duplicate" if found else None
        kind, dp, pref = found[0].groups()
        return [int(pref), dp == "1"] if kind == "Preference" else kind

    return {
        "srl_oper_state": es["oper-state"],
        "srl_admin": [alg["preference-value"], alg["capabilities"]["non-revertive"]],
        "srl_oper": [alg["oper-preference-value"], alg["oper-do-not-prempt"]],
        "srl_df": candidates,
        "srl_role_change": changed,
        "srl_decoded_rust": type4(RUST),
        "srl_own_type4": type4(SRL),
    }


def ce_facts(directory):
    """Up ports in the CE bond's active aggregator, collecting and distributing."""
    text = (directory / "ce-bond.txt").read_text()
    active = re.search(
        r"Active Aggregator Info:\s*\n\s*Aggregator ID: (\d+)\s*\n\s*Number of ports: (\d+)", text
    )
    ports = 0
    for section in text.split("Slave Interface: ")[1:]:
        aggregator = re.search(r"\nAggregator ID: (\d+)", section)
        actor = re.search(r"details actor lacp pdu:.*?port state: (\d+)", section, re.S)
        # A carrier-down slave keeps its last actor state, so MII must be up.
        if (
            active
            and aggregator
            and actor
            and aggregator[1] == active[1]
            and section.splitlines()[1] == "MII Status: up"
            and int(actor[1]) & 0x30 == 0x30
        ):
            ports += 1
    return {"ce_bundled_ports": ports}


def facts(directory):
    return rust_facts(directory) | srl_facts(directory) | ce_facts(directory)


def epoch(stamp):
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def check(directory, expected):
    """Exact equality per fact, plus two checks on SR Linux's DF role-change
    stamp, its only record of a transient role flip between snapshots.

    `srl_role_settled_for: N` needs the stamp at least N seconds older than
    the snapshot: SR Linux rewrites it a few seconds after a role change
    without changing the role. `srl_role_changed_after: TIME` needs the stamp
    to record a change caused by the action at TIME: SR Linux can report the
    new role before it updates the stamp. `srl_role_unchanged_since: STAMP`
    accepts that earlier stamp within ROLE_STAMP_JITTER seconds, since SR
    Linux re-renders an unchanged stamp a few milliseconds apart."""
    observed = facts(directory)
    (directory / "facts.json").write_text(json.dumps(observed, indent=2, sort_keys=True) + "\n")
    expected = dict(expected)
    pinned = "srl_role_unchanged_since" in expected
    since = expected.pop("srl_role_unchanged_since", None)
    settle = expected.pop("srl_role_settled_for", None)
    after = expected.pop("srl_role_changed_after", None)
    unknown = set(expected) - set(observed)
    if unknown:
        raise KeyError(f"unknown expectation keys {sorted(unknown)}")
    problems = [
        f"{key}: expected {want!r}, observed {observed[key]!r}"
        for key, want in sorted(expected.items())
        if observed[key] != want
    ]
    stamp = observed["srl_role_change"]
    if pinned and (
        since is None or stamp is None or abs(epoch(stamp) - epoch(since)) > ROLE_STAMP_JITTER
    ):
        problems.append(f"srl_role_change: expected unchanged since {since}, observed {stamp}")
    if settle is not None:
        taken = (directory / "taken-at").read_text().strip()
        if stamp is None or epoch(taken) - epoch(stamp) < settle:
            problems.append(f"srl_role_change: {stamp} not settled for {settle}s at {taken}")
    if after is not None and (stamp is None or epoch(stamp) < epoch(after) - ROLE_STAMP_JITTER):
        problems.append(f"srl_role_change: {stamp} predates the action at {after}")
    return problems


def main(argv):
    if len(argv) == 3 and argv[1] == "replay":
        phases = sorted(p.parent for p in Path(argv[2]).rglob("expect.json"))
        if not phases:
            print(f"no phases under {argv[2]}", file=sys.stderr)
            return 1
        failed = 0
        for phase in phases:
            for problem in check(phase, read(phase, "expect.json")):
                print(f"{phase.name}: {problem}", file=sys.stderr)
                failed = 1
        return failed
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    directory = Path(argv[1])
    expected = json.loads(argv[2])
    (directory / "expect.json").write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n")
    problems = check(directory, expected)
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
