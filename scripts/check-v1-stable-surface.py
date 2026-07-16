#!/usr/bin/env python3
"""Fail closed when the pinned RS/RR v1 stable-surface inventory drifts."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import re
import subprocess
import sys
from pathlib import Path

if sys.version_info < (3, 11):
    print(
        "v1 stable-surface check failed: Python 3.11 or newer is required "
        "for the standard-library tomllib module",
        file=sys.stderr,
    )
    raise SystemExit(1)

import tomllib


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "docs/v1-stable-surface.json"
SCHEMA_PATH = ROOT / "docs/rustbgpd.schema.json"
GRPC_INVENTORY_PATH = ROOT / "docs/grpc-method-inventory.json"
WORKSPACE_MANIFEST_PATH = ROOT / "Cargo.toml"
JSON_TYPES = {"array", "boolean", "null", "number", "object", "string"}
V1_UPGRADE_HISTORY_ORIGIN = (0, 50, 0)
EXPECTED_EFFECTIVE_DEFAULT_PATHS = (
    "Global.cluster_id",
    "Global.dynamic_neighbor_limit",
    "Neighbor.disable_ipv4_unicast",
    "Neighbor.families",
    "Neighbor.gr_restart_time",
    "Neighbor.gr_stale_routes_time",
    "Neighbor.graceful_restart",
    "Neighbor.hold_time",
    "Neighbor.llgr_stale_time",
    "Neighbor.send_hold_time",
)
EXPECTED_EFFECTIVE_DEFAULT_ASSERTION_PATHS = tuple(
    path for path in EXPECTED_EFFECTIVE_DEFAULT_PATHS if path != "Neighbor.families"
)
EXPECTED_SCHEMA_REPRESENTATION_DEFAULTS = {
    "Global.dynamic_neighbor_limit": None,
    "Neighbor.families": [],
}
EXPECTED_EFFECTIVE_FAMILY_CASES = (
    '"bare_ipv4",bare.transport_config.peer.families,&[(Afi::Ipv4,Safi::Unicast)]',
    '"bare_ipv6",bare_ipv6.transport_config.peer.families,'
    '&[(Afi::Ipv4,Safi::Unicast),(Afi::Ipv6,Safi::Unicast)]',
    '"group_overrides_address_default",inherited.transport_config.peer.families,'
    '&[(Afi::Ipv6,Safi::Unicast)]',
    '"neighbor_overrides_group",overridden.transport_config.peer.families,'
    '&[(Afi::Ipv4,Safi::Unicast)]',
)
EFFECTIVE_DEFAULT_ASSERTION_MACRO = "assert_v1_effective_default"
EFFECTIVE_DEFAULT_ASSERTION_RE = re.compile(
    rf'\b{EFFECTIVE_DEFAULT_ASSERTION_MACRO}!\(\s*"([^"\\]+)"\s*,\s*'
    r"([a-z][a-z0-9_]*)\s*,\s*(None|true|false|\d+|\(\d+\s*,\s*\d+\))\s*\);"
)
EFFECTIVE_FAMILY_ASSERTION_MACRO = "assert_v1_family_case"
EFFECTIVE_FAMILY_ASSERTION_RE = re.compile(
    rf"\b{EFFECTIVE_FAMILY_ASSERTION_MACRO}!\((.*?)\);", re.DOTALL
)


def fail(message: str) -> None:
    print(f"v1 stable-surface check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot load {path.relative_to(ROOT)}: {error}")


def require_sorted_unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        fail(f"{label} contains duplicates")
    if values != sorted(values):
        fail(f"{label} must be sorted for reviewable diffs")


def schema_definition(schema: dict, name: str) -> dict:
    if name == "Config":
        return schema
    try:
        return schema["$defs"][name]
    except KeyError:
        fail(f"config definition {name!r} no longer exists in the JSON Schema")


def strip_descriptions(value):
    if isinstance(value, dict):
        return {
            key: strip_descriptions(child)
            for key, child in value.items()
            if key != "description"
        }
    if isinstance(value, list):
        return [strip_descriptions(child) for child in value]
    return value


def stable_config_object_shape(definition_schema: dict, fields: list[str]) -> dict:
    """Return the compatibility-relevant shape for selected stable fields."""
    properties = definition_schema.get("properties", {})
    return {
        "additionalProperties": strip_descriptions(
            definition_schema.get("additionalProperties", True)
        ),
        "properties": {
            field: strip_descriptions(properties[field]) for field in fields
        },
        "required": sorted(definition_schema.get("required", [])),
    }


def schema_digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def check_stable_config_object_shape_regressions() -> None:
    fields = ["address", "remote_asn"]
    neighbor = {
        "additionalProperties": False,
        "properties": {
            "address": {"description": "ignored prose", "type": "string"},
            "remote_asn": {"minimum": 0, "type": "integer"},
            "optional_sibling": {"type": "boolean"},
        },
        "required": ["remote_asn", "address"],
    }
    baseline = schema_digest(stable_config_object_shape(neighbor, fields))

    required_changed = {**neighbor, "required": ["address"]}
    if schema_digest(stable_config_object_shape(required_changed, fields)) == baseline:
        fail("internal config-shape regression did not detect required-field drift")

    unknown_fields_allowed = {**neighbor, "additionalProperties": True}
    if schema_digest(stable_config_object_shape(unknown_fields_allowed, fields)) == baseline:
        fail("internal config-shape regression did not detect unknown-field policy drift")

    additive_sibling = {
        **neighbor,
        "properties": {
            **neighbor["properties"],
            "another_optional_sibling": {"default": False, "type": "boolean"},
        },
    }
    if schema_digest(stable_config_object_shape(additive_sibling, fields)) != baseline:
        fail("internal config-shape regression rejected an additive optional sibling")

    required_reordered = {**neighbor, "required": ["address", "remote_asn"]}
    if schema_digest(stable_config_object_shape(required_reordered, fields)) != baseline:
        fail("internal config-shape regression treated required ordering as semantic")


def check_effective_default_assertion_block(test_region: str, test: str) -> None:
    if not re.search(
        rf"""
        macro_rules!\s+{EFFECTIVE_DEFAULT_ASSERTION_MACRO}\s*\{{\s*
        \(\s*\$path:literal\s*,\s*\$actual:expr\s*,\s*\$expected:expr\s*\)\s*=>\s*\{{\s*
        assert_eq!\(\s*\$actual\s*,\s*\$expected\s*,.*?\);\s*
        \}}\s*;\s*
        \}}
        """,
        test_region,
        flags=re.DOTALL | re.VERBOSE,
    ):
        fail(
            f"effective-default validation test {test!r} has no runtime-vs-expected "
            "assertion macro"
        )
    assertions = EFFECTIVE_DEFAULT_ASSERTION_RE.findall(test_region)
    if [path for path, _, _ in assertions] != list(
        EXPECTED_EFFECTIVE_DEFAULT_ASSERTION_PATHS
    ):
        fail(
            f"effective-default validation test {test!r} must assert exactly the "
            "nine scalar scoped full paths in sorted order"
        )
    for path, actual, _ in assertions:
        field = path.partition(".")[2]
        runtime_field = (
            "effective_dynamic_neighbor_limit"
            if path == "Global.dynamic_neighbor_limit"
            else field
        )
        extraction = (
            rf"\blet\s+{re.escape(actual)}\s*=\s*"
            rf"[^;]*\b{re.escape(runtime_field)}\b[^;]*;"
        )
        if actual != field or not re.search(extraction, test_region):
            fail(
                f"effective-default validation test {test!r} assertion for {path!r} "
                "is not bound to that runtime field"
            )

    if not re.search(
        rf"""
        macro_rules!\s+{EFFECTIVE_FAMILY_ASSERTION_MACRO}\s*\{{\s*
        \(\s*\$case:literal\s*,\s*\$actual:expr\s*,\s*\$expected:expr\s*\)\s*=>\s*\{{\s*
        assert_eq!\(\s*\$actual\.as_slice\(\)\s*,\s*\$expected\s*,.*?\);\s*
        \}}\s*;\s*
        \}}
        """,
        test_region,
        flags=re.DOTALL | re.VERBOSE,
    ):
        fail(
            f"effective-default validation test {test!r} has no typed "
            "runtime-vs-expected family assertion macro"
        )
    family_cases = tuple(
        re.sub(r"\s+", "", invocation)
        for invocation in EFFECTIVE_FAMILY_ASSERTION_RE.findall(test_region)
    )
    if family_cases != EXPECTED_EFFECTIVE_FAMILY_CASES:
        fail(
            f"effective-default validation test {test!r} must assert exactly the "
            "four typed family-resolution cases"
        )


def check_dynamic_neighbor_limit_linkage(
    config_source: str, peer_manager_source: str
) -> None:
    if not re.search(
        r"pub\(crate\)\s+fn\s+effective_dynamic_neighbor_limit\s*\(\s*&self\s*\)"
        r"\s*->\s*u32\s*\{\s*self\.global\s*\.dynamic_neighbor_limit\s*"
        r"\.unwrap_or\(DEFAULT_DYNAMIC_NEIGHBOR_LIMIT\)\s*\}",
        config_source,
        flags=re.DOTALL,
    ):
        fail(
            "Config::effective_dynamic_neighbor_limit must resolve the shared "
            "DEFAULT_DYNAMIC_NEIGHBOR_LIMIT"
        )
    if not re.search(
        r"dynamic_neighbor_limit:\s*current_config"
        r"\.effective_dynamic_neighbor_limit\(\)",
        peer_manager_source,
    ):
        fail(
            "PeerManager must consume Config::effective_dynamic_neighbor_limit"
        )


def check_effective_defaults(
    inventory: dict, schema: dict, stable_paths: set[str]
) -> None:
    effective = inventory["config"].get("effective_defaults")
    if not isinstance(effective, dict):
        fail("config.effective_defaults must be an object")
    required_keys = {
        "paths",
        "schema_representation_defaults",
        "validation_source",
        "validation_test",
    }
    if set(effective) != required_keys:
        fail(
            "config.effective_defaults must contain exactly paths, "
            "schema_representation_defaults, validation_source, and validation_test"
        )

    paths = effective["paths"]
    if not isinstance(paths, list) or not paths or not all(
        isinstance(path, str) and path for path in paths
    ):
        fail("config.effective_defaults.paths must be a non-empty string list")
    require_sorted_unique(paths, "config.effective_defaults.paths")
    if paths != list(EXPECTED_EFFECTIVE_DEFAULT_PATHS):
        fail("config.effective_defaults.paths must match the exact ten-path scoped set")
    schema_defaults = effective["schema_representation_defaults"]
    if schema_defaults != EXPECTED_SCHEMA_REPRESENTATION_DEFAULTS:
        fail(
            "config.effective_defaults.schema_representation_defaults must match "
            "the exact two-path representation map"
        )
    for path in paths:
        definition, separator, field = path.partition(".")
        if not separator or "." in field or path not in stable_paths:
            fail(f"effective default path {path!r} is not a stable config field")
        property_schema = schema_definition(schema, definition)["properties"][field]
        if path in schema_defaults:
            if property_schema.get("default", object()) != schema_defaults[path]:
                fail(
                    f"schema representation default for {path!r} drifted from the "
                    "pinned non-effective value"
                )
        elif "default" in property_schema:
            fail(
                f"contextual effective default {path!r} must not claim a static JSON Schema default"
            )
        description = property_schema.get("description")
        if not isinstance(description, str) or not description.strip():
            fail(f"contextual effective default {path!r} has no schema description")

    source_name = effective["validation_source"]
    test = effective["validation_test"]
    if not isinstance(source_name, str) or not source_name:
        fail("config.effective_defaults.validation_source must be a source path")
    if not isinstance(test, str) or not test:
        fail("config.effective_defaults.validation_test must be a test name")
    source_path = ROOT / safe_relative_path(
        source_name, "effective-default validation source"
    )
    try:
        source = source_path.read_text()
    except OSError as error:
        fail(f"cannot read effective-default validation source {source_name}: {error}")
    test_region = named_rust_test_region(source, test)
    if test_region is None:
        fail(f"effective-default validation test {test!r} is not a live named test")
    check_effective_default_assertion_block(test_region, test)
    expect_checker_failure(
        lambda: check_effective_default_assertion_block(
            EFFECTIVE_DEFAULT_ASSERTION_RE.sub("", test_region), test
        ),
        "must assert exactly the nine scalar scoped full paths",
        "missing effective-default runtime assertion block",
    )
    for broken_macro, label in (
        (
            test_region.replace("$actual, $expected", "$expected, $expected"),
            "vacuous macro",
        ),
        (
            re.sub(
                r"assert_eq!\(\s*\$actual\s*,\s*\$expected\s*,.*?\);",
                "",
                test_region,
                count=1,
                flags=re.DOTALL,
            ),
            "no-op macro",
        ),
    ):
        expect_checker_failure(
            lambda broken_macro=broken_macro: check_effective_default_assertion_block(
                broken_macro, test
            ),
            "no runtime-vs-expected assertion macro",
            label,
        )
    expect_checker_failure(
        lambda: check_effective_default_assertion_block(
            EFFECTIVE_FAMILY_ASSERTION_RE.sub("", test_region), test
        ),
        "must assert exactly the four typed family-resolution cases",
        "missing effective-family runtime rows",
    )
    expect_checker_failure(
        lambda: check_effective_default_assertion_block(
            test_region.replace("$actual.as_slice()", "$expected", 1), test
        ),
        "no typed runtime-vs-expected family assertion macro",
        "vacuous effective-family macro",
    )
    for linkage in ("parse_strict(", "resolve_neighbor("):
        if linkage not in test_region:
            fail(
                f"effective-default validation test {test!r} does not exercise {linkage[:-1]}"
            )

    config_source = (ROOT / "src/config/mod.rs").read_text()
    peer_manager_source = (ROOT / "src/peer_manager/mod.rs").read_text()
    check_dynamic_neighbor_limit_linkage(config_source, peer_manager_source)
    expect_checker_failure(
        lambda: check_dynamic_neighbor_limit_linkage(
            config_source,
            peer_manager_source.replace(
                "current_config.effective_dynamic_neighbor_limit()",
                "current_config.global.dynamic_neighbor_limit.unwrap_or(100)",
                1,
            ),
        ),
        "PeerManager must consume Config::effective_dynamic_neighbor_limit",
        "bypassed dynamic-neighbor-limit accessor",
    )


def check_config(inventory: dict, schema: dict) -> None:
    stable_entries = inventory["config"]["stable_fields"]
    definitions: set[str] = set()
    stable_paths: set[str] = set()
    for entry in stable_entries:
        definition = entry["definition"]
        if definition in definitions:
            fail(f"stable config definition {definition!r} appears twice")
        definitions.add(definition)
        fields = entry["fields"]
        require_sorted_unique(fields, f"config.{definition}.fields")
        properties = schema_definition(schema, definition).get("properties", {})
        for field in fields:
            if field not in properties:
                fail(f"stable config field {definition}.{field} disappeared")
            stable_paths.add(f"{definition}.{field}")
        pinned_schema = stable_config_object_shape(
            schema_definition(schema, definition), fields
        )
        digest = schema_digest(pinned_schema)
        if digest != entry["schema_sha256"]:
            fail(
                f"stable config schema changed for {definition} ({digest}); review selected "
                "properties, required fields, unknown-field policy, and compatibility before "
                "updating the inventory"
            )

    stable_types = inventory["config"]["stable_types"]
    type_names = [entry["definition"] for entry in stable_types]
    require_sorted_unique(type_names, "config.stable_types")
    for entry in stable_types:
        definition = entry["definition"]
        value = strip_descriptions(schema_definition(schema, definition))
        digest = schema_digest(value)
        if digest != entry["schema_sha256"]:
            fail(
                f"stable config type changed for {definition} ({digest}); review enum values, "
                "constraints, and compatibility before updating the inventory"
            )

    classified_definitions = definitions | set(type_names)
    for entry in stable_entries:
        definition = entry["definition"]
        properties = schema_definition(schema, definition).get("properties", {})
        selected = {field: properties[field] for field in entry["fields"]}
        references = set(re.findall(r"#/\$defs/(\w+)", json.dumps(selected)))
        missing_references = sorted(references - classified_definitions)
        if missing_references:
            fail(
                f"stable config fields in {definition} reference unpinned types: "
                f"{', '.join(missing_references)}"
            )

    unstable = inventory["config"]["explicitly_unstable_roots"]
    unstable_paths = [entry["path"] for entry in unstable]
    require_sorted_unique(unstable_paths, "config.explicitly_unstable_roots")
    for entry in unstable:
        path = entry["path"]
        definition, separator, field = path.partition(".")
        if not separator or field not in schema_definition(schema, definition).get("properties", {}):
            fail(f"explicitly unstable config path {path!r} does not exist")
        if path in stable_paths:
            fail(f"config path {path!r} is both stable and unstable")

    config_properties = set(schema.get("properties", {}))
    classified_roots = {
        path.removeprefix("Config.")
        for path in stable_paths | set(unstable_paths)
        if path.startswith("Config.")
    }
    missing = sorted(config_properties - classified_roots)
    if missing:
        fail(f"top-level config roots are unclassified: {', '.join(missing)}")
    check_effective_defaults(inventory, schema, stable_paths)


RPC_RE = re.compile(
    r"rpc\s+(\w+)\s*\(\s*(stream\s+)?([\w.]+)\s*\)\s*"
    r"returns\s*\(\s*(stream\s+)?([\w.]+)\s*\)"
)
SERVICE_RE = re.compile(r"^service\s+(\w+)\s*\{(.*?)^\}", re.MULTILINE | re.DOTALL)


def parse_services(proto: str) -> dict[str, list[tuple[str, str, str, bool, bool]]]:
    services: dict[str, list[tuple[str, str, str, bool, bool]]] = {}
    for service_match in SERVICE_RE.finditer(proto):
        rows = []
        for rpc_match in RPC_RE.finditer(service_match.group(2)):
            rows.append(
                (
                    rpc_match.group(1),
                    rpc_match.group(3),
                    rpc_match.group(5),
                    rpc_match.group(2) is not None,
                    rpc_match.group(4) is not None,
                )
            )
        services[service_match.group(1)] = rows
    return services


def strip_proto_comments(proto: str) -> str:
    proto = re.sub(r"/\*.*?\*/", "", proto, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", proto)


def parse_proto_definitions(proto: str) -> dict[str, str]:
    """Return normalized top-level message/enum declarations by name."""
    definitions: dict[str, str] = {}
    declaration = re.compile(r"(?m)^(message|enum)\s+(\w+)\s*\{")
    for match in declaration.finditer(proto):
        depth = 1
        cursor = match.end()
        while cursor < len(proto) and depth:
            if proto[cursor] == "{":
                depth += 1
            elif proto[cursor] == "}":
                depth -= 1
            cursor += 1
        if depth:
            fail(f"unterminated protobuf {match.group(1)} {match.group(2)}")
        definitions[match.group(2)] = re.sub(r"\s+", " ", proto[match.start() : cursor]).strip()
    return definitions


def message_graph_digest(
    rows: list[tuple[str, str, str, bool, bool]], definitions: dict[str, str]
) -> str:
    pending = [type_name.rsplit(".", 1)[-1] for row in rows for type_name in row[1:3]]
    selected: set[str] = set()
    while pending:
        name = pending.pop()
        if name in selected or name not in definitions:
            continue
        selected.add(name)
        body = definitions[name]
        for candidate in definitions:
            if candidate not in selected and re.search(rf"\b{re.escape(candidate)}\b", body):
                pending.append(candidate)
    canonical = "\n".join(f"{name}:{definitions[name]}" for name in sorted(selected))
    return hashlib.sha256(canonical.encode()).hexdigest()


def signature_digest(rows: list[tuple[str, str, str, bool, bool]]) -> str:
    canonical = "\n".join(
        f"{method}:{request}:{response}:{str(client_streaming).lower()}:{str(server_streaming).lower()}"
        for method, request, response, client_streaming, server_streaming in rows
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def check_method_sets(inventory: dict, services: dict, definitions: dict[str, str]) -> set[str]:
    stable_paths: set[str] = set()
    for class_name in ("stable_method_sets", "scoped_rr_only_method_sets"):
        for entry in inventory["grpc"][class_name]:
            service = entry["service"]
            if service not in services:
                fail(f"gRPC service {service!r} disappeared")
            methods = entry["methods"]
            if len(methods) != len(set(methods)):
                fail(f"gRPC method set {service} contains duplicates")
            wanted = set(methods)
            rows = [row for row in services[service] if row[0] in wanted]
            found = {row[0] for row in rows}
            missing = sorted(wanted - found)
            if missing:
                fail(f"stable gRPC methods disappeared from {service}: {', '.join(missing)}")
            digest = signature_digest(rows)
            if digest != entry["signature_sha256"]:
                fail(
                    f"stable gRPC signature changed for {service} ({digest}); review request/response "
                    "messages, streaming modes, and compatibility before updating the inventory"
                )
            graph_digest = message_graph_digest(rows, definitions)
            if graph_digest != entry["message_graph_sha256"]:
                fail(
                    f"stable protobuf message graph changed for {service} ({graph_digest}); "
                    "review field numbers/types/enums and additive compatibility before updating the inventory"
                )
            for method in methods:
                path = f"/rustbgpd.v1.{service}/{method}"
                if path in stable_paths:
                    fail(f"gRPC method {path} is classified twice")
                stable_paths.add(path)
    return stable_paths


def check_grpc(inventory: dict) -> None:
    proto_path = ROOT / inventory["grpc"]["proto"]
    try:
        proto = strip_proto_comments(proto_path.read_text())
    except OSError as error:
        fail(f"cannot read {proto_path.relative_to(ROOT)}: {error}")
    services = parse_services(proto)
    definitions = parse_proto_definitions(proto)
    stable_paths = check_method_sets(inventory, services, definitions)
    unstable_fields = inventory["grpc"]["explicitly_unstable_message_fields"]
    require_sorted_unique(unstable_fields, "grpc.explicitly_unstable_message_fields")
    for path in unstable_fields:
        message, separator, field = path.partition(".")
        if not separator or message not in definitions:
            fail(f"explicitly unstable protobuf field {path!r} has no message")
        if field != "*" and not re.search(
            rf"\b{re.escape(field)}\b\s*=\s*\d+", definitions[message]
        ):
            fail(f"explicitly unstable protobuf field {path!r} disappeared")
    outside = inventory["grpc"]["explicitly_outside_v1"]
    if len(outside) != len(set(outside)):
        fail("grpc.explicitly_outside_v1 contains duplicates")
    outside_native: set[tuple[str, str]] = set()
    for surface in outside:
        if surface == "gnmi.gNMI":
            continue
        service, separator, method = surface.partition(".")
        if service not in services:
            fail(f"outside-v1 gRPC service {service!r} disappeared")
        if separator:
            available = {row[0] for row in services[service]}
            if method not in available:
                fail(f"outside-v1 gRPC method {surface!r} disappeared")
            stable_path = f"/rustbgpd.v1.{service}/{method}"
            if stable_path in stable_paths:
                fail(f"gRPC method {surface!r} is both inventoried and outside v1")
            outside_native.add((service, method))
        else:
            outside_native.update((service, row[0]) for row in services[service])
    stable_native = {
        (path.split(".", 2)[2].split("/", 1)[0], path.rsplit("/", 1)[1])
        for path in stable_paths
    }
    all_native = {(service, row[0]) for service, rows in services.items() for row in rows}
    unclassified = sorted(all_native - stable_native - outside_native)
    if unclassified:
        fail(f"native gRPC methods are unclassified: {unclassified}")
    authz_paths = {entry["path"] for entry in load_json(GRPC_INVENTORY_PATH)["methods"]}
    missing_authz = sorted(stable_paths - authz_paths)
    if missing_authz:
        fail(f"stable gRPC methods disappeared from authorization inventory: {missing_authz}")


def semantic_toml_sha256(path: Path) -> str:
    with path.open("rb") as source:
        value = tomllib.load(source)
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        fail(f"cannot read {path.relative_to(ROOT)}: {error}")


def safe_relative_path(value: str, label: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        fail(f"unsafe {label} path {value!r}")
    return path


def workspace_release() -> tuple[str, tuple[int, int, int]]:
    try:
        manifest = tomllib.loads(WORKSPACE_MANIFEST_PATH.read_text())
        raw = manifest["workspace"]["package"]["version"]
    except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        fail(f"cannot read workspace package version: {error}")
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", raw)
    if not match:
        fail(f"workspace package version {raw!r} is not MAJOR.MINOR.PATCH")
    version = tuple(map(int, match.groups()))
    return f"v{raw}", version


def require_git_tag(tag: str) -> None:
    result = subprocess.run(
        ["git", "cat-file", "-e", f"refs/tags/{tag}^{{commit}}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        fail(f"required release tag {tag!r} is unavailable; fetch tags before validating")


def tagged_file(tag: str, path: str) -> bytes | None:
    result = subprocess.run(
        ["git", "show", f"refs/tags/{tag}:{path}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    return result.stdout if result.returncode == 0 else None


ReleaseVersion = tuple[int, int, int]
ReleaseTransition = tuple[ReleaseVersion, ReleaseVersion]


def parse_release_tag(tag: str) -> ReleaseVersion:
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", tag)
    if not match:
        fail(f"upgrade exercise release must be a full vMAJOR.MINOR.PATCH tag: {tag!r}")
    return tuple(map(int, match.groups()))


def release_line(version: ReleaseVersion) -> ReleaseVersion:
    return (version[0], version[1], 0)


def release_line_chain_error(
    transitions: list[ReleaseTransition], baseline_version: ReleaseVersion
) -> str | None:
    if not transitions:
        return "at least one consecutive-release upgrade exercise is required"
    if transitions[0][0] != V1_UPGRADE_HISTORY_ORIGIN:
        return "upgrade exercise history must retain the canonical v0.50.0 origin"

    targets = [target for _, target in transitions]
    if targets != sorted(targets) or len(targets) != len(set(targets)):
        return "upgrade exercises must be ordered by unique target release"

    for index, (source, target) in enumerate(transitions):
        if source[2] != 0 or target[2] != 0:
            return "upgrade exercise endpoints must be release-line anchors with patch zero"
        same_major_next_minor = target[0] == source[0] and target[1] == source[1] + 1
        next_major = target[0] == source[0] + 1 and target[1] == 0
        if not (same_major_next_minor or next_major):
            return "upgrade exercise is not between consecutive release lines"
        if index == 0 and next_major:
            return "major-boundary exercise must retain its preceding release-line receipt"
        if index and source != transitions[index - 1][1]:
            return "upgrade exercises must form one contiguous release-line chain"

    expected_target = release_line(baseline_version)
    if transitions[-1][1] != expected_target:
        return (
            "latest upgrade exercise must end at the workspace release-line anchor "
            f"v{expected_target[0]}.{expected_target[1]}.{expected_target[2]}"
        )
    return None


def check_release_line_selftests() -> None:
    v0_49 = (0, 49, 0)
    v0_50 = (0, 50, 0)
    v0_51 = (0, 51, 0)
    v0_52 = (0, 52, 0)
    v1_0 = (1, 0, 0)
    cases = [
        ("patch baseline", [(v0_50, v0_51)], (0, 51, 1), True),
        (
            "major baseline",
            [(v0_50, v0_51), (v0_51, v1_0)],
            (1, 0, 0),
            True,
        ),
        (
            "major patch baseline",
            [(v0_50, v0_51), (v0_51, v1_0)],
            (1, 0, 1),
            True,
        ),
        ("lone major transition", [(v0_50, v1_0)], (1, 0, 0), False),
        ("nonzero exercise patch", [(v0_50, (0, 51, 1))], (0, 51, 1), False),
        ("skipped minor", [(v0_49, v0_51)], (0, 51, 0), False),
        (
            "unordered chain",
            [(v0_51, v0_52), (v0_50, v0_51)],
            (0, 51, 0),
            False,
        ),
        (
            "duplicate target",
            [(v0_50, v0_51), (v0_50, v0_51)],
            (0, 51, 0),
            False,
        ),
        (
            "disconnected chain",
            [(v0_49, v0_50), (v0_51, v0_52)],
            (0, 52, 0),
            False,
        ),
        (
            "rewritten history origin",
            [(v0_49, v0_50), (v0_50, v1_0)],
            (1, 0, 0),
            False,
        ),
        ("stale target", [(v0_50, v0_51)], (0, 52, 1), False),
    ]
    for label, transitions, baseline_version, expected_valid in cases:
        valid = release_line_chain_error(transitions, baseline_version) is None
        if valid != expected_valid:
            fail(f"internal release-line regression self-test failed: {label}")


def check_upgrade_exercises(inventory: dict) -> None:
    baseline, baseline_version = workspace_release()
    if inventory.get("baseline_release") != baseline:
        fail(
            f"baseline_release must match the workspace package version: expected {baseline}, "
            f"found {inventory.get('baseline_release')!r}"
        )
    exercises = inventory["upgrade_exercises"]
    if not exercises:
        fail("at least one consecutive-release upgrade exercise is required")
    transitions: list[ReleaseTransition] = []
    validation_tests = [exercise["validation_test"] for exercise in exercises]
    if len(validation_tests) != len(set(validation_tests)):
        fail("upgrade exercises must use unique validation_test ids")
    for exercise in exercises:
        from_version = parse_release_tag(exercise["from_release"])
        to_version = parse_release_tag(exercise["to_release"])
        transitions.append((from_version, to_version))
        if exercise.get("result") not in {
            "accepted_without_config_migration",
            "accepted_with_documented_migration",
        }:
            fail(f"upgrade exercise has no recognized accepted result: {exercise.get('result')!r}")
        require_git_tag(exercise["from_release"])
        if exercise["to_release"] != baseline:
            require_git_tag(exercise["to_release"])

        fixture_relative = safe_relative_path(
            exercise["fixture_directory"], "upgrade fixture directory"
        )
        fixture_directory = ROOT / fixture_relative
        source_directory = safe_relative_path(
            exercise["source_directory"], "upgrade source directory"
        )
        files = exercise["files"]
        file_names = [entry["path"] for entry in files]
        require_sorted_unique(file_names, "upgrade_exercise.files")
        if "config.toml" not in file_names:
            fail("upgrade exercise must archive config.toml")
        actual_files = []
        for path in fixture_directory.rglob("*"):
            relative_path = str(path.relative_to(fixture_directory))
            if path.is_symlink():
                fail(f"upgrade fixture {relative_path!r} must not be a symlink")
            if path.is_dir():
                continue
            if not path.is_file():
                fail(f"upgrade fixture {relative_path!r} must be a regular file")
            actual_files.append(relative_path)
        actual_files.sort()
        if actual_files != file_names:
            fail(
                f"upgrade fixture directory must contain exactly the inventoried files: "
                f"expected {file_names}, found {actual_files}"
            )
        for entry in files:
            relative = safe_relative_path(entry["path"], "upgrade fixture")
            fixture = fixture_directory / relative
            if fixture.is_symlink() or not fixture.is_file():
                fail(f"upgrade fixture {fixture.relative_to(ROOT)} must be a regular file")
            digest = file_sha256(fixture)
            if digest != entry["sha256"]:
                fail(
                    f"immutable upgrade fixture {fixture.relative_to(ROOT)} changed "
                    f"({digest}); archive a new release fixture instead"
                )
            tag_path = str(source_directory / relative)
            tagged = tagged_file(exercise["from_release"], tag_path)
            if tagged is None:
                fail(f"required tag path {exercise['from_release']}:{tag_path} is unavailable")
            tagged_digest = hashlib.sha256(tagged).hexdigest()
            if tagged_digest != entry["sha256"]:
                fail(
                    f"archived fixture {fixture.relative_to(ROOT)} does not match "
                    f"{exercise['from_release']}:{tag_path}"
                )
            if exercise["to_release"] != baseline and tagged_file(
                exercise["to_release"], tag_path
            ) is None:
                fail(f"required tag path {exercise['to_release']}:{tag_path} is unavailable")

        config_fixture = fixture_directory / "config.toml"
        digest = semantic_toml_sha256(config_fixture)
        expected = exercise["semantic_toml_sha256"]
        if digest != expected:
            fail(
                f"upgrade fixture {config_fixture.relative_to(ROOT)} changed semantically; run and record a new "
                "consecutive-release migration exercise before updating the digest"
            )

        validation_source = ROOT / safe_relative_path(
            exercise["validation_source"], "upgrade validation source"
        )
        try:
            validation_text = validation_source.read_text()
        except OSError as error:
            fail(f"cannot read upgrade validation source {exercise['validation_source']}: {error}")
        validation_test = exercise["validation_test"].rsplit("::", 1)[-1]
        test_region = named_rust_test_region(validation_text, validation_test)
        if test_region is None:
            fail(
                f"upgrade validation test {exercise['validation_test']!r} disappeared from "
                f"{exercise['validation_source']}"
            )
        if exercise["fixture_directory"] not in test_region:
            fail(
                f"upgrade validation test {exercise['validation_test']!r} does not reference "
                f"the immutable fixture directory"
            )

    if error := release_line_chain_error(transitions, baseline_version):
        fail(error)


def check_json_type_spec(type_spec, label: str) -> None:
    if isinstance(type_spec, str):
        types = [type_spec]
    elif isinstance(type_spec, list):
        types = type_spec
        require_sorted_unique(types, label)
    else:
        fail(f"{label} must be a JSON type or sorted type union")
    if not types:
        fail(f"{label} type union cannot be empty")
    invalid = sorted({value for value in types if value not in JSON_TYPES})
    if invalid:
        fail(f"{label} contains invalid JSON types: {invalid}")


def check_json_type_map(type_map: dict, label: str, *, required: bool) -> None:
    if not isinstance(type_map, dict) or (required and not type_map):
        qualifier = "at least one" if required else "zero or more"
        fail(f"{label} must pin {qualifier} JSON field/type entries")
    require_sorted_unique(list(type_map), label)
    for field, type_spec in type_map.items():
        check_json_type_spec(type_spec, f"{label}.{field}")


def check_json_shape(shape: dict, label: str) -> None:
    required = shape.get("required_json_types")
    optional = shape.get("optional_json_types", {})
    check_json_type_map(required, f"{label}.required_json_types", required=True)
    check_json_type_map(optional, f"{label}.optional_json_types", required=False)
    overlap = sorted(set(required) & set(optional))
    if overlap:
        fail(f"{label} fields are both required and optional: {overlap}")


def strip_rust_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", source)


def named_rust_test_region(source: str, name: str) -> str | None:
    source = strip_rust_comments(source)
    match = re.search(rf"\b(?:async\s+)?fn\s+{re.escape(name)}\s*\(", source)
    if not match:
        return None
    attributes_match = re.search(
        r"((?:\s*#\[[^\]]*\])+\s*)$", source[: match.start()], flags=re.DOTALL
    )
    attributes = attributes_match.group(1) if attributes_match else ""
    attribute_bodies = [body.strip() for body in re.findall(r"#\[(.*?)\]", attributes, re.DOTALL)]
    if not any(
        re.fullmatch(r"(?:tokio::)?test(?:\s*\(.*\))?", body, flags=re.DOTALL)
        for body in attribute_bodies
    ):
        return None
    for body in attribute_bodies:
        is_cfg_attr = re.match(r"cfg_attr\b", body) is not None
        if re.match(r"ignore\b", body) or (is_cfg_attr and re.search(r"\bignore\b", body)):
            fail(f"inventory-linked contract test {name!r} must not be ignored")
        if re.match(r"should_panic\b", body) or (
            is_cfg_attr and re.search(r"\bshould_panic\b", body)
        ):
            fail(f"inventory-linked contract test {name!r} must not use should_panic")
    body_start = source.find("{", match.end())
    if body_start < 0:
        return None
    depth = 1
    cursor = body_start + 1
    while cursor < len(source) and depth:
        if source[cursor] == "{":
            depth += 1
        elif source[cursor] == "}":
            depth -= 1
        cursor += 1
    if depth:
        return None
    return source[match.start() : cursor]


def check_contract_command_paths(
    contract: dict, label: str, stable_command_paths: set[str]
) -> None:
    command_paths = contract.get("command_paths")
    if not isinstance(command_paths, list) or not command_paths:
        fail(f"{label}.command_paths must link at least one stable CLI command path")
    canonical = [" ".join(path.split()) for path in command_paths]
    require_sorted_unique(canonical, f"{label}.command_paths")
    if command_paths != canonical:
        fail(f"{label}.command_paths must use canonical single-space separators")
    missing = sorted(set(command_paths) - stable_command_paths)
    if missing:
        fail(f"{label}.command_paths reference unpinned CLI paths: {missing}")


def check_contract_producer_tests(contract: dict, label: str) -> None:
    golden_paths = {golden["path"] for golden in contract.get("golden_files", [])}
    producer_tests = contract.get("producer_tests", [])
    if not golden_paths and producer_tests:
        fail(f"{label}.producer_tests cannot exist without pinned golden files")
    if golden_paths and not producer_tests:
        fail(f"{label} pins golden files without producer-test linkage")

    producer_ids = [producer["id"] for producer in producer_tests]
    require_sorted_unique(producer_ids, f"{label}.producer_tests")
    linked_goldens: list[str] = []
    for producer in producer_tests:
        producer_label = f"{label}.producer_tests.{producer['id']}"
        golden = producer.get("golden")
        if golden not in golden_paths:
            fail(f"{producer_label} references an unpinned golden file")
        linked_goldens.append(golden)

        source_path = ROOT / safe_relative_path(
            producer["source"], "JSON contract producer-test source"
        )
        try:
            source = source_path.read_text()
        except OSError as error:
            fail(f"cannot read producer-test source {producer['source']}: {error}")
        test = producer.get("test")
        test_region = named_rust_test_region(source, test) if test else None
        if not test_region:
            fail(f"{producer_label} has no live named producer test")
        test_linkage = producer.get("test_linkage")
        if not test_linkage or test_linkage not in test_region:
            fail(f"{producer_label} test is not linked to its producer")
        golden_linkage = producer.get("golden_linkage")
        if not golden_linkage or golden_linkage not in test_region:
            fail(f"{producer_label} test is not linked to its pinned golden")

    if len(linked_goldens) != len(set(linked_goldens)):
        fail(f"{label}.producer_tests link a golden file more than once")
    missing_producers = sorted(golden_paths - set(linked_goldens))
    if missing_producers:
        fail(f"{label}.golden_files have no producer test: {missing_producers}")


def check_json_contract(
    contract: dict,
    label: str,
    *,
    require_id_literal: bool,
    stable_command_paths: set[str] | None = None,
) -> None:
    if contract.get("evolution") not in {
        "additive_fields_only",
        "additive_fields_only_except_explicitly_experimental_fields",
        "closed_schema_version_bump_required",
    }:
        fail(f"{label} has no recognized evolution policy")
    source_path = ROOT / safe_relative_path(contract["source"], "JSON contract source")
    try:
        source = source_path.read_text()
    except OSError as error:
        fail(f"cannot read JSON contract source {contract['source']}: {error}")
    if require_id_literal and contract["id"] not in source:
        fail(f"JSON contract {contract['id']!r} disappeared from {contract['source']}")
    test = contract.get("test")
    test_region = named_rust_test_region(source, test) if test else None
    if not test_region:
        fail(f"JSON contract {contract['id']!r} has no live named contract test")
    linkage = contract.get("test_linkage")
    if not linkage or linkage not in test_region:
        fail(f"JSON contract {contract['id']!r} test is not linked to its inventory floor")
    evidence_test = contract.get("evidence_test")
    if evidence_test and named_rust_test_region(source, evidence_test) is None:
        fail(f"JSON contract {contract['id']!r} has no live named evidence test")
    if not contract.get("executable_type_floor"):
        fail(f"JSON contract {contract['id']!r} type floor is not marked executable")
    if "required_json_types" not in source or "optional_json_types" not in source:
        fail(f"JSON contract {contract['id']!r} test source does not consume its type floor")
    golden_files = contract.get("golden_files", [])
    golden_paths = [golden["path"] for golden in golden_files]
    require_sorted_unique(golden_paths, f"{label}.golden_files")
    for golden in golden_files:
        golden_path = ROOT / safe_relative_path(golden["path"], "JSON contract golden")
        if golden_path.is_symlink() or not golden_path.is_file():
            fail(f"JSON contract golden {golden['path']} must be a regular file")
        if file_sha256(golden_path) != golden["sha256"]:
            fail(f"JSON contract golden {golden['path']} changed without an inventory update")
    check_contract_producer_tests(contract, label)
    if stable_command_paths is not None:
        check_contract_command_paths(contract, label, stable_command_paths)
    if "required_json_types" in contract:
        check_json_shape(contract, label)
    elif "record_json_contracts" in contract:
        records = contract["record_json_contracts"]
        require_sorted_unique(list(records), f"{label}.record_json_contracts")
        if not records:
            fail(f"{label} must pin at least one record shape")
        for record, shape in records.items():
            check_json_shape(shape, f"{label}.{record}")
    else:
        fail(f"{label} has no required JSON field/type metadata")
    nested = contract.get("nested_json_contracts", [])
    nested_paths = [shape["path"] for shape in nested]
    require_sorted_unique(nested_paths, f"{label}.nested_json_contracts")
    for shape in nested:
        check_json_shape(shape, f"{label}.{shape['path']}")
    experimental = contract.get("explicitly_experimental_json_fields", [])
    require_sorted_unique(experimental, f"{label}.explicitly_experimental_json_fields")
    classified = set(contract.get("required_json_types", {})) | set(
        contract.get("optional_json_types", {})
    )
    overlap = sorted(classified & set(experimental))
    if overlap:
        fail(f"{label} fields are both contract-pinned and explicitly experimental: {overlap}")
    for field in experimental:
        if field not in source:
            fail(f"{label} experimental JSON field {field!r} disappeared from its source")


def check_cli(inventory: dict) -> None:
    if inventory["cli"].get("stability_scope") != "command_path_and_name_only":
        fail("CLI stability scope must remain command path/name only")
    stable_paths = inventory["cli"]["stable_command_paths"]
    scoped_paths = inventory["cli"]["scoped_rr_only_command_paths"]
    stable_canonical = [" ".join(path.split()) for path in stable_paths]
    scoped_canonical = [" ".join(path.split()) for path in scoped_paths]
    require_sorted_unique(stable_canonical, "cli.stable_command_paths")
    require_sorted_unique(scoped_canonical, "cli.scoped_rr_only_command_paths")
    if stable_paths != stable_canonical or scoped_paths != scoped_canonical:
        fail("CLI command paths must use canonical single-space separators")
    overlap = sorted(set(stable_canonical) & set(scoped_canonical))
    if overlap:
        fail(f"CLI paths are both stable and scoped RR-only: {overlap}")
    versioned = inventory["cli"]["versioned_json_contracts"]
    versioned_ids = [contract["id"] for contract in versioned]
    require_sorted_unique(versioned_ids, "cli.versioned_json_contracts")
    for contract in versioned:
        check_json_contract(
            contract,
            f"cli.versioned_json_contracts.{contract['id']}",
            require_id_literal=True,
            stable_command_paths=set(stable_canonical),
        )
    pinned = inventory["cli"]["test_pinned_json_contracts"]
    pinned_ids = [contract["id"] for contract in pinned]
    require_sorted_unique(pinned_ids, "cli.test_pinned_json_contracts")
    for contract in pinned:
        check_json_contract(
            contract,
            f"cli.test_pinned_json_contracts.{contract['id']}",
            require_id_literal=False,
        )


def expect_checker_failure(action, expected: str, label: str) -> None:
    stderr = io.StringIO()
    failed = False
    with contextlib.redirect_stderr(stderr):
        try:
            action()
        except SystemExit:
            failed = True
    if not failed:
        fail(f"checker self-test {label!r} unexpectedly passed")
    actual = stderr.getvalue()
    if expected not in actual:
        fail(
            f"checker self-test {label!r} failed for the wrong reason; "
            f"expected stderr containing {expected!r}, got {actual!r}"
        )


def check_cli_checker_selftests(inventory: dict) -> None:
    versioned = {
        contract["id"]: contract for contract in inventory["cli"]["versioned_json_contracts"]
    }
    ribsnap = versioned["rbgp-ribsnap/1"]

    expect_checker_failure(
        lambda: check_contract_command_paths(
            versioned["rbgp-ribdiff/1"],
            "selftest.ribdiff",
            set(inventory["cli"]["stable_command_paths"]) - {"diff advertised"},
        ),
        "reference unpinned CLI paths",
        "missing command path classification",
    )

    missing_golden = copy.deepcopy(ribsnap)
    missing_golden["golden_files"] = missing_golden["golden_files"][1:]
    expect_checker_failure(
        lambda: check_contract_producer_tests(missing_golden, "selftest.ribsnap"),
        "references an unpinned golden file",
        "missing golden linkage",
    )

    missing_producer_linkage = copy.deepcopy(ribsnap)
    missing_producer_linkage["producer_tests"][0]["test_linkage"] = (
        "producer_linkage_that_does_not_exist"
    )
    expect_checker_failure(
        lambda: check_contract_producer_tests(
            missing_producer_linkage, "selftest.ribsnap"
        ),
        "test is not linked to its producer",
        "missing producer linkage",
    )


def check_named_rust_test_region_selftests() -> None:
    cases = [
        ('#[test]\n#[ignore = "reason"]', "must not be ignored", "ignore with reason"),
        (
            "#[test]\n#[cfg_attr(test, ignore)]",
            "must not be ignored",
            "cfg_attr ignore",
        ),
        (
            '#[test]\n#[cfg_attr(not(test), ignore = "reason")]',
            "must not be ignored",
            "conditional ignore with reason",
        ),
        ("#[test]\n#[should_panic]", "must not use should_panic", "should_panic"),
        (
            '#[test]\n#[should_panic(expected = "boom")]',
            "must not use should_panic",
            "should_panic with expected message",
        ),
        (
            "#[test]\n#[cfg_attr(test, should_panic)]",
            "must not use should_panic",
            "cfg_attr should_panic",
        ),
    ]
    for attributes, expected, label in cases:
        source = f"{attributes}\nfn contract_probe() {{}}"
        expect_checker_failure(
            lambda source=source: named_rust_test_region(source, "contract_probe"),
            expected,
            label,
        )


def check_policy(inventory: dict) -> None:
    roles = inventory["roles"]
    role_ids = [role["id"] for role in roles]
    if len(role_ids) != len(set(role_ids)):
        fail("role matrix contains duplicate ids")
    classifications = {role["classification"] for role in roles}
    required = {"stable", "scoped_rr_only", "alpha", "experimental"}
    if not required <= classifications:
        fail(f"role matrix must include classifications: {sorted(required)}")
    public_contract_path = ROOT / "docs/v1-stable-contract.md"
    try:
        public_contract = public_contract_path.read_text()
    except OSError as error:
        fail(f"cannot read {public_contract_path.relative_to(ROOT)}: {error}")
    for role_id in role_ids:
        if f"`{role_id}`" not in public_contract:
            fail(f"public role matrix is missing machine role id {role_id!r}")
    compatibility = inventory["compatibility"]
    for key in ("protobuf", "config", "rpol", "metrics", "events", "migration_support"):
        if not compatibility.get(key):
            fail(f"compatibility policy {key!r} is missing")
    window = compatibility["deprecation_window"]
    if window["minimum_minor_releases"] < 2 or window["minimum_days"] < 90:
        fail("v1 deprecation window cannot be shortened below two minors and 90 days")


def main() -> None:
    check_release_line_selftests()
    check_stable_config_object_shape_regressions()
    check_named_rust_test_region_selftests()
    inventory = load_json(INVENTORY_PATH)
    if inventory.get("schema_version") != 1 or inventory.get("contract") != "rustbgpd-rs-rr-v1":
        fail("unexpected inventory schema or contract id")
    check_policy(inventory)
    check_config(inventory, load_json(SCHEMA_PATH))
    check_grpc(inventory)
    check_cli_checker_selftests(inventory)
    check_cli(inventory)
    check_upgrade_exercises(inventory)
    print("v1 stable-surface inventory: OK")


if __name__ == "__main__":
    main()
