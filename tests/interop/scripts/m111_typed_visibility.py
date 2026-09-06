#!/usr/bin/env python3
"""Compare M111 typed VPN snapshots with the wire oracle and FRR allocation.

Run after m111_capture_oracle.py has produced wire.json. Retain the initial
count-1 RR snapshots as baseline-vpnv4-rr.json and baseline-vpnv6-rr.json
before the driver overwrites the VPNv4 snapshot during its survivor check.
This verifier supplements the packet oracle; it does not decode the capture.
"""

from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path

from m105_capture_oracle import need

STRUCTURE_FIELDS = (
    "locator_block_length", "locator_node_length", "function_length",
    "argument_length", "transposition_length", "transposition_offset",
)
FAMILIES = {"vpnv4": "l3vpn_ipv4_unicast", "vpnv6": "l3vpn_ipv6_unicast"}


def route(snapshot: list[dict], family: str, wire: dict, allocated: dict) -> dict:
    need(len(snapshot) == 1, f"{family}: expected exactly one typed route")
    row = snapshot[0]
    nlri = bytes.fromhex(wire["nlri_hex"])
    next_hop = bytes.fromhex(wire["next_hop_hex"])
    need(len(nlri) >= 12 and len(next_hop) in (24, 48), "short wire route")
    label = int.from_bytes(nlri[1:4], "big") >> 4
    expected = {
        "afi_safi": FAMILIES[family], "route_distinguisher": wire["rd"],
        "route_distinguisher_bytes": nlri[4:12].hex(), "prefix": wire["prefix"],
        "labels": [label], "next_hop": str(ipaddress.IPv6Address(next_hop[8:24])),
        "peer_address": "2001:db8:111:10::2",
    }
    for field, value in expected.items():
        need(row.get(field) == value, f"{family}: typed {field} differs from wire")
    need(not row.get("stale") and not row.get("llgr_stale") and not row.get("path_id"),
         f"{family}: stale or unexpected Add-Path route")
    view = row.get("prefix_sid")
    need(isinstance(view, dict), f"{family}: typed Prefix-SID absent")
    need(view.get("raw_value") == wire["prefix_sid_hex"], f"{family}: raw Prefix-SID differs")
    # FRR's short source attribute has optional-transitive flags, without Partial.
    need(view.get("flags") == 0xC0 and not view.get("decode_error"),
         f"{family}: Prefix-SID flags or decode error differs")
    structure = dict(zip(STRUCTURE_FIELDS, wire["structure"], strict=True))
    need(wire["structure"] == [40, 24, 16, 0, 16, 64], "wire SID Structure differs")
    need(wire["endpoint_behavior"] == {"vpnv4": 19, "vpnv6": 18}[family],
         f"{family}: wire endpoint behavior differs")
    expected_services = [{"tlv_type": 5, "sids": [{
        "sid_value": wire["advertised_sid"], "endpoint_behavior": wire["endpoint_behavior"],
        "flags": 0, "structures": [structure],
    }]}]
    need(view.get("services") == expected_services, f"{family}: typed service differs from wire")
    # Reconstruct from the operator's advertised SID and 20-bit label, rather
    # than treating the advertised locator as the complete allocated SID.
    sid = view["services"][0]["sids"][0]
    bits = sid["structures"][0]
    length, offset = bits["transposition_length"], bits["transposition_offset"]
    function = row["labels"][0] >> (20 - length)
    reconstructed = str(ipaddress.IPv6Address(
        int(ipaddress.IPv6Address(sid["sid_value"])) | (function << (128 - offset - length))
    ))
    need(function == wire["transposed_function"] and reconstructed == wire["service_sid"],
         f"{family}: typed service SID reconstruction differs")
    allocation = allocated.get(reconstructed, {})
    need(allocation.get("sid") == reconstructed
         and allocation.get("behavior") == {"vpnv4": "End.DT4", "vpnv6": "End.DT6"}[family]
         and allocation.get("locator") == "srv6-proof"
         and allocation.get("context", {}).get("vrfName") == "vrf111"
         and allocation.get("context", {}).get("table") == 111
         and any(client.get("protocol") == "bgp" for client in allocation.get("clients", [])),
         f"{family}: reconstructed typed SID differs from FRR allocation")
    return {"prefix": row["prefix"], "advertised_sid": sid["sid_value"],
            "service_sid": reconstructed, "label": label, "endpoint_behavior": sid["endpoint_behavior"]}


def verify(directory: Path) -> dict:
    def read(name: str):
        return json.loads((directory / name).read_text(encoding="utf-8"))

    wire, allocated = read("wire.json"), read("frr-sids.json")
    need(wire.get("schema") == "m111-wire/1" and set(wire["families"]) == set(FAMILIES),
         "wire receipt schema or family set differs")
    result = {}
    for family in FAMILIES:
        evidence = wire["families"][family]
        baseline = route(read(f"baseline-{family}-rr.json"), family, evidence, allocated)
        retained = route(read(f"{family}-count-1-rr.json"), family, evidence, allocated)
        need(baseline == retained, f"{family}: retained typed route differs from baseline")
        need(read(f"{family}-count-0-rr.json") == [], f"{family}: withdrawn typed route remains")
        result[family] = baseline
    return {"schema": "m111-typed-visibility/1", "families": result,
            "vpnv4_survives_vpnv6_withdrawal": True, "both_withdrawn": True}


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError(f"usage: {sys.argv[0]} ARTIFACT_DIRECTORY")
        print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True, separators=(",", ":")))
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        print(f"M111 typed visibility failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
