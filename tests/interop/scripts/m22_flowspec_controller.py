#!/usr/bin/env python3
"""Bounded dual-AFI controller lifecycle proof against M22's FRR observer."""

import argparse
import copy
import ipaddress
import json
from pathlib import Path
import struct
import subprocess
import time


DENY = (65001 << 16) | 666
REWRITE = (65001 << 16) | 100
REWRITE_RT = (2 << 48) | (65001 << 32) | 100
TAG = (65001 << 16) | 10
FAMILIES = ("IPV4", "IPV6")


def rule(family, index, rate=1000):
    prefix = f"198.18.{index}.0/24" if family == "IPV4" else f"2001:db8:{index:x}::/64"
    prefix = str(ipaddress.ip_network(prefix))
    return {
        "afiSafi": f"ADDRESS_FAMILY_{family}_FLOWSPEC",
        "components": [{"type": 1, "prefix": prefix}, {"type": 3, "value": "=6"},
                       {"type": 5, "value": "=80"}],
        "actions": [{"trafficRate": {"rate": rate}}],
        "communities": [TAG, DENY] if index == 0 else [TAG],
    }


def identity(row):
    return tuple((c["type"], c.get("prefix", ""), c.get("value", "").replace("==", "="), c.get("offset", 0))
                 for c in row["components"])


def normalized(row):
    """Compare the full promised rule payload, allowing protobuf default omission."""
    rate = row["actions"][0]["trafficRate"].get("rate", 0)
    assert len(row["actions"]) == 1, row
    return (identity(row), row["afiSafi"], rate, tuple(sorted(row.get("communities", []))))


def assert_routes(actual, expected, sources=None):
    assert len(actual) == len(expected), (len(actual), len(expected))
    got = {identity(row): row for row in actual}
    assert len(got) == len(actual), "duplicate identities in returned view"
    assert set(got) == {identity(row) for row in expected}, "wrong rule identities"
    for row in expected:
        observed = got[identity(row)]
        assert normalized(observed) == normalized(row), (observed, row)
        if sources is not None:
            assert observed["peerAddress"] == sources.get(identity(row), "0.0.0.0"), observed
        # The decoded action and raw extended community must describe the same payload.
        bits = struct.unpack("!I", struct.pack("!f", row["actions"][0]["trafficRate"]["rate"]))[0]
        communities = [0x8006000000000000 | bits] + row.get("extendedCommunities", [])
        assert sorted(int(v) for v in observed.get("extendedCommunities", [])) == sorted(communities), observed


def frr_routes(document):
    """Require one usable FRR path per exact FlowSpec NLRI, not a count/text hit."""
    routes = document["routes"]
    assert document["totalRoutes"] == len(routes), document
    result = {}
    for nlri, paths in routes.items():
        assert len(paths) == 1 and paths[0].get("valid") and paths[0].get("bestpath"), (nlri, paths)
        result[nlri] = paths[0]
    return result


def frr_details(text):
    # FRR 10.7.1 emits one JSON array per NLRI for "flowspec detail json".
    # Parse the complete sequence; never extract a nearby rate with text grep.
    decoder = json.JSONDecoder()
    routes = {}
    while text.strip():
        text = text.lstrip()
        parts, end = decoder.raw_decode(text)
        text = text[end:]
        row = parts[0]
        prefix = row["to"].removesuffix("/off 0")
        assert prefix not in routes, ("duplicate FRR rule", prefix)
        routes[prefix] = dict(row, ecomlist=parts[1]["ecomlist"])
    return routes


def assert_frr(snapshot, expected):
    routes = frr_routes(snapshot["frr"])
    details = snapshot["frr_details"]
    assert len(routes) == len(expected), (len(routes), len(expected))
    assert set(details) == {row["components"][0]["prefix"] for row in expected}, details
    for row in expected:
        prefix = row["components"][0]["prefix"]
        matches = [path for path in routes.values() if path["to"].removesuffix("/off 0") == prefix]
        assert len(matches) == 1, (prefix, routes)
        for observed in (matches[0], details[prefix]):
            assert observed["proto"].replace(" ", "") == "=6", observed
            assert observed["dstp"].replace(" ", "") == "=80", observed
        rate = row["actions"][0]["trafficRate"]["rate"]
        ecom = details[prefix]["ecomlist"]
        action = f"FS:rate {rate:.6f}"
        assert action in ecom and ecom.replace(action, "").strip() == "65001:100", ecom


class Lab:
    def __init__(self, args):
        self.args = args
        self.output = Path(args.output)
        self.output.mkdir(parents=True)
        self.token = Path("tests/fixtures/grpc-test-only-operator.token").read_text().strip()
        self.results = []
        self.baseline = None

    @staticmethod
    def command(args, **kwargs):
        return subprocess.run(args, check=True, text=True, capture_output=True, timeout=15, **kwargs).stdout

    def rpc(self, method, payload=None, source=False, error=None):
        target = self.args.source_grpc if source else self.args.grpc
        command = ["grpcurl", "-max-time", "10", "-plaintext", "-import-path", ".", "-proto",
                   "proto/rustbgpd.proto", "-H", f"authorization: Bearer {self.token}",
                   "-d", "@", target, f"rustbgpd.v1.{method}"]
        result = subprocess.run(command, input=json.dumps(payload or {}), text=True,
                                capture_output=True, timeout=15)
        if error:
            assert result.returncode and f"Code: {error}" in result.stderr, result
            return None
        assert result.returncode == 0, (method, result.stderr)
        return json.loads(result.stdout)

    def frr(self, command):
        return json.loads(self.command(["docker", "exec", self.args.frr, "vtysh", "-c", command]))

    def sessions(self):
        summary = self.frr("show bgp neighbors 10.0.0.1 json")["10.0.0.1"]
        assert summary["bgpState"] == "Established", summary
        source = self.rpc("NeighborService/GetNeighborState", {"address": "10.0.1.2"})
        assert source["state"] == "SESSION_STATE_ESTABLISHED", source
        return (summary["connectionsDropped"], source.get("flapCount", "0"))

    def wait(self, label, check, seconds=30):
        deadline = time.monotonic() + seconds
        last = None
        while True:
            try:
                value = check()
                self.results.append(label)
                print(f"PASS {label}", flush=True)
                return value
            except (AssertionError, subprocess.SubprocessError, KeyError) as error:
                last = str(error)
            if time.monotonic() >= deadline:
                raise AssertionError(f"{label} did not converge within {seconds}s: {last}")
            time.sleep(0.5)

    def add(self, payload, outcome, source=False):
        result = self.rpc("InjectionService/AddFlowSpec", payload, source)
        assert result["outcome"] == f"FLOW_SPEC_INJECT_OUTCOME_{outcome}", result

    def delete(self, payload, outcome="DELETED", source=False, allow_missing=False, error=None):
        request = {key: payload[key] for key in ("afiSafi", "components")}
        request["allowMissing"] = allow_missing
        result = self.rpc("InjectionService/DeleteFlowSpec", request, source, error)
        if error is None:
            assert result["outcome"] == f"FLOW_SPEC_DELETE_OUTCOME_{outcome}", result

    def snapshot(self, family):
        request = {"afiSafi": f"ADDRESS_FAMILY_{family}_FLOWSPEC"}
        return {
            "local": self.rpc("RibService/ListFlowSpecRoutes", dict(request, receivedPeerAddress="0.0.0.0")),
            "selected": self.rpc("RibService/ListFlowSpecRoutes", request),
            "advertised": self.rpc("RibService/ListFlowSpecRoutes", dict(request, advertisedPeerAddress="10.0.0.2")),
            "frr": self.frr(f"show bgp {family.lower()} flowspec json"),
            "frr_details": frr_details(self.command(["docker", "exec", self.args.frr, "vtysh", "-c",
                                                      f"show bgp {family.lower()} flowspec detail json"])),
        }

    def views(self, label, intended, replacements=None):
        replacements = replacements or {}
        snapshots = {}
        for family in FAMILIES:
            snapshot = self.snapshot(family)
            snapshots[family] = snapshot
            self.output.joinpath(f"{label}-{family}.json").write_text(json.dumps(snapshot, indent=2) + "\n")
            local = snapshot["local"]
            advertised = snapshot["advertised"]
            assert local.get("receivedView") is True, local
            assert advertised.get("advertisedView") is True, advertised
            assert not local.get("routes") and not advertised.get("receivedRoutes"), snapshot
            rows = local.get("receivedRoutes", [])
            assert_routes([row["route"] for row in rows], intended[family], {})
            for row in rows:
                key = identity(row["route"])
                assert row.get("selected", False) == (key not in replacements), row
                assert row["validation"] == "FLOW_SPEC_VALIDATION_STATUS_DISABLED", row
                assert not row.get("pending", False) and not row.get("pathId", 0), row
            selected = {identity(row): row for row in intended[family]}
            selected.update({key: row for key, row in replacements.items()
                             if row["afiSafi"] == f"ADDRESS_FAMILY_{family}_FLOWSPEC"})
            selected = list(selected.values())
            sources = {key: "10.0.1.2" for key in replacements}
            assert_routes(snapshot["selected"].get("routes", []), selected, sources)
            exported = copy.deepcopy([row for row in selected if DENY not in row.get("communities", [])])
            for row in exported:
                row["communities"] = row.get("communities", []) + [REWRITE]
                row["extendedCommunities"] = [REWRITE_RT]
            assert_routes(advertised.get("routes", []), exported, sources)
            assert_frr(snapshot, exported)
        drops = self.sessions()
        self.output.joinpath(f"{label}-sessions.json").write_text(json.dumps({"baseline": self.baseline, "observed": drops}) + "\n")
        if self.baseline is not None:
            assert drops == self.baseline, ("unexpected session drop", self.baseline, drops)
        return snapshots

    def restart(self):
        previous = self.baseline
        self.command(["docker", "exec", self.args.daemon, "sh", "-c",
                      'for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = rustbgpd ] || continue; kill -TERM "${p##*/}"; done'])
        def stopped():
            result = subprocess.run(["docker", "exec", self.args.daemon, "sh", "-c",
                                     'grep -q rustbgpd /proc/*/comm 2>/dev/null'], timeout=10)
            assert result.returncode == 1, result.returncode
        self.wait("daemon stopped", stopped)
        self.command(["docker", "exec", "-d", self.args.daemon, "sh", "-c",
                      "/usr/local/bin/rustbgpd /tmp/controller.toml >> /tmp/controller.log 2>&1"])
        self.wait("restarted daemon health", lambda: self.rpc("ControlService/GetHealth"))
        self.baseline = self.wait("restart sessions restored", self.sessions, 90)
        assert self.baseline[0] == previous[0] + 1, (previous, self.baseline)

    def run(self):
        self.baseline = self.wait("initial sessions established", self.sessions, 90)
        self.wait("initial-empty", lambda: self.views("initial-empty", {family: [] for family in FAMILIES}))
        intended = {family: [rule(family, index) for index in range(50)] for family in FAMILIES}
        for rows in intended.values():
            for payload in rows:
                self.add(payload, "CREATED")
        self.wait("created", lambda: self.views("created", intended))
        for rows in intended.values():
            for payload in rows:
                self.add(payload, "UNCHANGED")
        self.wait("unchanged", lambda: self.views("unchanged", intended))
        for rows in intended.values():
            for payload in rows:
                payload["actions"][0]["trafficRate"]["rate"] = 2000
                self.add(payload, "REPLACED")
        self.wait("replaced", lambda: self.views("replaced", intended))

        masked = {identity(rows[1]): rule(family, 1, 3000) for family, rows in intended.items()}
        for payload in masked.values():
            self.add(payload, "CREATED", source=True)
        self.wait("masked-local-intent", lambda: self.views("masked-local-intent", intended, masked))
        for rows in intended.values():
            rows[1]["actions"][0]["trafficRate"]["rate"] = 4000
            self.add(rows[1], "REPLACED")
            self.add(rows[1], "UNCHANGED")
        self.wait("masked-replaced", lambda: self.views("masked-replaced", intended, masked))
        removed = {family: rows.pop(1) for family, rows in intended.items()}
        for payload in removed.values():
            self.delete(payload)
            self.delete(payload, error="NotFound")
            self.delete(payload, "NOT_PRESENT", allow_missing=True)
        self.wait("delete-keeps-received-winner", lambda: self.views("delete-keeps-received-winner", intended, masked))
        for family, payload in removed.items():
            self.add(payload, "CREATED")
            intended[family].insert(1, payload)
        self.wait("masked-recreated", lambda: self.views("masked-recreated", intended, masked))
        for payload in masked.values():
            self.delete(payload, source=True)
        self.wait("local-selection-restored", lambda: self.views("local-selection-restored", intended))

        previous = self.baseline
        self.rpc("NeighborService/DisableNeighbor", {"address": "10.0.0.2"})
        def disconnected():
            state = self.frr("show bgp neighbors 10.0.0.1 json")["10.0.0.1"]["bgpState"]
            assert state != "Established", state
        self.wait("peer deliberately disconnected", disconnected)
        self.rpc("NeighborService/EnableNeighbor", {"address": "10.0.0.2"})
        self.baseline = self.wait("peer reconnected", self.sessions, 90)
        assert self.baseline == (previous[0] + 1, previous[1]), (previous, self.baseline)
        self.wait("reconnect-replay", lambda: self.views("reconnect-replay", intended))

        self.restart()
        self.wait("restart-empty", lambda: self.views("restart-empty", {family: [] for family in FAMILIES}))
        for rows in intended.values():
            for payload in rows:
                self.add(payload, "CREATED")
        self.wait("restart-reconciled", lambda: self.views("restart-reconciled", intended))
        for rows in intended.values():
            for payload in rows:
                self.delete(payload)
            self.delete(rows[0], error="NotFound")
            self.delete(rows[0], "NOT_PRESENT", allow_missing=True)
        self.wait("deleted", lambda: self.views("deleted", {family: [] for family in FAMILIES}))
        receipt = {"result": "pass", "rules": 100, "rules_per_afi": 50,
                   "families": list(FAMILIES), "checks": self.results,
                   "scope": "bounded functional controller qualification; no performance or dataplane claim"}
        self.output.joinpath("result.json").write_text(json.dumps(receipt, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("grpc", "source-grpc", "daemon", "frr", "output"):
        parser.add_argument(f"--{name}", required=True)
    Lab(parser.parse_args()).run()


if __name__ == "__main__":
    main()
