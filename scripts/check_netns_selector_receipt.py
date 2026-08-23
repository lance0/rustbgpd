#!/usr/bin/env python3
"""Validate and publish the executed kernel-netns selector inventory."""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

BASE = (
    "fdb_nhg", "fib_runtime", "bfd_runtime", "dataplane_vlan_fdb",
    "macip_vlan_attribution", "svd_fdb_vni", "managed_bridge",
    "managed_vxlan", "managed_svd_vxlan", "managed_vlan_upper",
    "managed_ready", "link_carrier", "ac_gate", "nexthop_raw",
    "foreign_state_l2", "foreign_state_nhid",
)
VRF = (
    "l3_multipath", "managed_ip_vrf_ready", "l3_all_active_writer",
    "foreign_state_l3", "l3_route_event",
)


def finalize(receipt: Path, output: Path, summary: Path, vrf_available: bool) -> list[str]:
    seen = receipt.read_text().splitlines() if receipt.is_file() else []
    counts = collections.Counter(seen)
    expected = BASE + VRF if vrf_available else BASE
    errors: list[str] = []
    errors += [f"missing selector: {item}" for item in expected if counts[item] == 0]
    errors += [f"duplicate selector: {item}" for item, count in counts.items() if count > 1]
    errors += [f"unexpected selector: {item}" for item in counts if item not in expected]
    executed = [item for item in expected if counts[item] == 1]
    omitted = [] if vrf_available else [
        {"selector": item, "reason": "vrf_unavailable"} for item in VRF
    ]
    payload = {
        "errors": sorted(errors),
        "executed_selectors": executed,
        "omitted_selectors": omitted,
        "schema_version": 1,
        "vrf_available": vrf_available,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    status = "PASS" if not errors else "FAIL"
    summary.write_text(
        f"### Netns selector receipt: {status}\n\n"
        f"Executed **{len(executed)}** selectors; published **{len(omitted)}** VRF omissions.\n"
    )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--vrf-available", choices=("true", "false"), required=True)
    args = parser.parse_args()
    errors = finalize(
        args.receipt, args.output, args.summary, args.vrf_available == "true"
    )
    for error in errors:
        print(error)
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
