#!/usr/bin/env python3
import difflib
import json
import os
from pathlib import Path
import sys

EXPECTED = {
    "status": 200,
    "protocols": 200,
    "protocol": 200,
    "symbols": 200,
    "protocol_routes": 200,
    "table_routes": 200,
    "export_routes": 200,
    "protocol_count": 200,
    "table_count": 200,
    "export_count": 200,
    "lookup_protocol": 200,
    "lookup_table": 200,
    "lookup_export": 200,
    "wildcard": 200,
    "bad_prefix": 400,
    "over_limit": 403,
    "missing_protocol": 404,
    "bird_failure": 503,
}
UNSUPPORTED = {
    "defined-only-rejected-route-reason-emission",
    "full-ixp-manager-ui-filter-policy-engine",
    "full-table-snapshot",
    "direct-runtime-protocol-alias-reconfiguration",
}
RUNTIME_SUPPORTED = {
    "exact-protocol-route",
    "exact-export-route",
    "filtered-prefix-wildcard",
    "less-specific-longest-prefix-match",
    "atomic-all-candidate-prefix-snapshot",
    "file-backed-runtime-protocol-alias-reconfiguration",
    "active-rejected-route-reason-inventory",
}
ADAPTER_API_VERSION = {"kind": "product-identity", "prefix": "rustbgpd "}
FILTERED_PREFIX_QUERY = {"global_admin": 65001, "function": 1101}
FILTERED_RETENTION_METADATA = {
    "fields": ["enabled", "capacity", "evictions_since_reset", "may_be_incomplete"],
    "unknown_evictions": None,
    "bounded_store_exempts_generic_max": True,
    "api_max_routes": "retention_capacity",
    "store_eviction_status": 200,
    "store_eviction_retained_rows_preserved": True,
}
REJECT_REASONS = {
    "display": {
        str(reason_id): meaning
        for reason_id, meaning in enumerate([
            "PREFIX LENGTH TOO LONG", "PREFIX LENGTH TOO SHORT", "BOGON",
            "BOGON ASN", "AS PATH TOO LONG", "AS PATH TOO SHORT",
            "FIRST AS NOT PEER AS", "NEXT HOP NOT PEER IP",
            "IRRDB PREFIX FILTERED", "IRRDB ORIGIN AS FILTERED",
            "PREFIX NOT IN ORIGIN AS", "RPKI UNKNOWN", "RPKI INVALID",
            "TRANSIT FREE ASN", "TOO MANY COMMUNITIES",
        ], 1)
    },
    "active_ids": [1, 3, 5, 6, 7, 8, 9, 10, 13, 14],
    "defined_only_ids": [2, 4, 11, 12, 15],
    "fallback_id": 0,
}
MANUAL_CONFIG_EXPORT = {
    "schema": "rustbgpd.ixp-manager.router-config/v2",
    "ixp_manager_version": "7.4.0",
    "router_handle": "b2-rs1-lan1-ipv4",
    "strict_receipt_required": True,
    "birdwatcher_protocol_aliases": {
        "candidate_path": "birdwatcher-protocol-aliases.conf",
        "current_path": "<runtime-state-dir>/activation/current/birdwatcher-protocol-aliases.conf",
        "line": "pb_{vlan_interface_id:04}_as{asn}={peer_address}@master{protocol}",
        "tables": {"4": "master4", "6": "master6"},
        "cap": 4096,
    },
    "own_as_large_community_scrub": {
        "syntax": "remove large-community <router-asn>:*:*",
        "global_export_chain_position": "last",
        "client_override_export_chain_position": "last",
        "foreign_global_admins": "preserved",
    },
    "ui_filters": {
        "advertise_actions": [
            "AS_IS", "NO_ADVERTISE", "PREPEND_ONCE", "PREPEND_TWICE",
            "PREPEND_THRICE",
        ],
        "receive_actions": [
            "AS_IS", "NO_ADVERTISE", "PREPEND_ONCE", "PREPEND_TWICE",
            "PREPEND_THRICE",
        ],
        "global_receive_prepend": "path-first-with-optional-received-prefix",
        "peer_receive_prepend": "literal-peer-asn",
        "overlapping_receive_prepend": True,
        "compiled_receive_cell_cap": 4096,
        "per_client_cap": 256,
        "total_cap": 4096,
    },
}
FULL_UI_FILTERS = [
    {
        "id": 31, "customer_id": 2, "peer": None,
        "received_prefix": None, "advertised_prefix": None, "protocol": 4,
        "action_advertise": "NO_ADVERTISE", "action_receive": "NO_ADVERTISE",
        "order_by": 2,
    },
    {
        "id": 33, "customer_id": 2,
        "peer": {"customer_id": 4, "asn": 112},
        "received_prefix": "192.175.48.0/24",
        "advertised_prefix": "77.72.72.0/21", "protocol": 4,
        "action_advertise": "PREPEND_TWICE",
        "action_receive": "PREPEND_TWICE", "order_by": 4,
    },
    {
        "id": 35, "customer_id": 2, "peer": None,
        "received_prefix": None, "advertised_prefix": None, "protocol": None,
        "action_advertise": "AS_IS", "action_receive": "AS_IS", "order_by": 6,
    },
]
SUPPORTED_UI_FILTERS = [
    {
        "id": 32, "customer_id": 2, "peer": None,
        "received_prefix": None, "advertised_prefix": None,
        "protocol": 4, "action_advertise": "AS_IS",
        "action_receive": "PREPEND_ONCE", "order_by": 3,
    },
    FULL_UI_FILTERS[1],
    FULL_UI_FILTERS[2],
]


def fail(message: str) -> None:
    raise SystemExit(message)


root = Path(__file__).resolve().parent
capture = Path(sys.argv[1])
manifest = json.loads((root / "contract.json").read_text())
if manifest.get("runtime_compatibility") is not False:
    fail("contract oracle must not promote a runtime compatibility claim")
if set(manifest.get("unsupported", [])) != UNSUPPORTED:
    fail("unsupported compatibility matrix drifted")
if set(manifest.get("runtime_supported", [])) != RUNTIME_SUPPORTED:
    fail("supported runtime matrix drifted")
if manifest.get("adapter_api_version") != ADAPTER_API_VERSION:
    fail("adapter api.version must remain an honest product identity")
if manifest.get("filtered_prefix_query") != FILTERED_PREFIX_QUERY:
    fail("filtered-prefix namespace drifted")
if manifest.get("filtered_retention_metadata") != FILTERED_RETENTION_METADATA:
    fail("filtered retention completeness contract drifted")
if manifest.get("reject_reasons") != REJECT_REASONS:
    fail("pinned reject-reason display or active partition drifted")
if manifest.get("manual_config_export") != MANUAL_CONFIG_EXPORT:
    fail("strict manual v2 export contract drifted")
consumer_source = (root / "config-consumer.php").read_text()
for required in [
    "$router->template = 'api/v4/router/server/bird2/standard';",
    "whereIn('id', [32, 33])->update(['enabled' => 1]);",
    "substr_count($birdCandidate, $prepend) - substr_count($birdBaseline, $prepend) !== 3",
    "substr_count($birdCandidate, $peerGuard) - substr_count($birdBaseline, $peerGuard) !== 1",
    "$globalPosition >= $specificPosition",
    "$birdBaseline,",
    "$birdCandidate,",
]:
    if required not in consumer_source:
        fail(f"pinned in-memory BIRD path-first proof drifted: {required}")
if manifest.get("protocol_aliases") != {
    "member-v4": "pb_as64496",
    "member-v4-reloaded": "pb_reloaded_as64496",
}:
    fail("explicit protocol alias matrix drifted")
if manifest.get("routing_tables") != ["master4"]:
    fail("live routing-table identity drifted")

if len(sys.argv) == 3:
    config_capture = Path(sys.argv[2])
    full = json.loads((config_capture / "config-ui-filter.json").read_text())
    supported = json.loads(
        (config_capture / "ixp-manager-v7.4-rustbgpd.json").read_text()
    )
    for name, document, filters in [
        ("full", full, FULL_UI_FILTERS),
        ("row-31-disabled", supported, SUPPORTED_UI_FILTERS),
    ]:
        if document.get("schema") != MANUAL_CONFIG_EXPORT["schema"]:
            fail(f"{name} UI-filter capture schema drifted")
        if document.get("ui_filters") != filters:
            fail(f"{name} UI-filter capture row objects drifted")
        if document.get("complete", {}).get("ui_filter_count") != len(filters):
            fail(f"{name} UI-filter capture completion count drifted")
        if document.get("unsupported", {}).get("active_ui_filters") != []:
            fail(f"{name} UI-filter capture retained a v1 refusal marker")

responses = {}
for name, expected_status in EXPECTED.items():
    body_path = capture / f"{name}.body"
    meta_path = capture / f"{name}.meta"
    if not body_path.is_file() or not meta_path.is_file():
        fail(f"required case silently skipped: {name}")
    metadata = meta_path.read_text().splitlines()
    if len(metadata) != 2:
        fail(f"{name}: incomplete HTTP metadata capture")
    status = int(metadata[0])
    content_type = metadata[1]
    if status != expected_status:
        fail(f"{name}: expected HTTP {expected_status}, got {status}")
    expected_content_type = "application/json"
    if content_type != expected_content_type:
        fail(f"{name}: expected Content-Type {expected_content_type!r}, got {content_type!r}")
    body = body_path.read_text()
    if status == 200:
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as error:
            fail(f"{name}: HTTP 200 body is not JSON: {error}; body={body[:160]!r}")
        api = parsed.get("api", {})
        leaked = {"env", "cache_disabled", "ip_whitelisted"} & set(api)
        if leaked:
            fail(f"{name}: production response leaked debug-only API keys: {sorted(leaked)}")
    responses[name] = {"status": status, "content_type": content_type, "body": body}

actual = json.dumps(
    {
        "provenance": {
            "birdseye_commit": manifest["birdseye_commit"],
            "license": "MIT",
            "source": "https://github.com/inex/birdseye",
            "synthetic_data": "RFC 5737 and RFC 5398 documentation values",
        },
        "responses": responses,
    },
    indent=2,
    sort_keys=True,
) + "\n"
fixture = root / "fixtures" / "birdseye-contract.json"
if os.getenv("CAPTURE_FIXTURES") == "1":
    output = Path(os.environ["CAPTURE_OUTPUT"])
    output.mkdir(parents=True, exist_ok=True)
    (output / fixture.name).write_text(actual)
    sys.exit(0)

expected = fixture.read_text()
if actual != expected:
    sys.stderr.writelines(difflib.unified_diff(
        expected.splitlines(True), actual.splitlines(True),
        fromfile=str(fixture), tofile="live-birdseye-capture",
    ))
    fail("pinned Bird's Eye contract drifted")
