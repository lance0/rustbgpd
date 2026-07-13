#!/usr/bin/env python3
"""Fail closed when the pinned RS/RR v1 stable-surface inventory drifts."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "docs/v1-stable-surface.json"
SCHEMA_PATH = ROOT / "docs/rustbgpd.schema.json"
GRPC_INVENTORY_PATH = ROOT / "docs/grpc-method-inventory.json"


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
        pinned_schema = {field: strip_descriptions(properties[field]) for field in fields}
        digest = hashlib.sha256(
            json.dumps(pinned_schema, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if digest != entry["schema_sha256"]:
            fail(
                f"stable config schema changed for {definition} ({digest}); review types, defaults, "
                "constraints, and compatibility before updating the inventory"
            )

    stable_types = inventory["config"]["stable_types"]
    type_names = [entry["definition"] for entry in stable_types]
    require_sorted_unique(type_names, "config.stable_types")
    for entry in stable_types:
        definition = entry["definition"]
        value = strip_descriptions(schema_definition(schema, definition))
        digest = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
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
    proto = strip_proto_comments(proto_path.read_text())
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


def tagged_file(tag: str, path: str) -> bytes | None:
    result = subprocess.run(
        ["git", "show", f"{tag}:{path}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    return result.stdout if result.returncode == 0 else None


def check_upgrade_exercises(inventory: dict) -> None:
    exercises = inventory["upgrade_exercises"]
    if not exercises:
        fail("at least one consecutive-release upgrade exercise is required")
    for exercise in exercises:
        from_match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", exercise["from_release"])
        to_match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", exercise["to_release"])
        if not from_match or not to_match:
            fail("upgrade exercise releases must be full vMAJOR.MINOR.PATCH tags")
        from_version = tuple(map(int, from_match.groups()))
        to_version = tuple(map(int, to_match.groups()))
        if not (
            to_version[0] == from_version[0]
            and to_version[1] == from_version[1] + 1
            and from_version[2] == 0
            and to_version[2] == 0
        ):
            fail(
                f"upgrade exercise is not between consecutive minor releases: "
                f"{exercise['from_release']} -> {exercise['to_release']}"
            )
        fixture = ROOT / exercise["fixture"]
        digest = semantic_toml_sha256(fixture)
        expected = exercise["semantic_toml_sha256"]
        if digest != expected:
            fail(
                f"upgrade fixture {exercise['fixture']} changed semantically; run and record a new "
                "consecutive-release migration exercise before updating the digest"
            )
        for release_key in ("from_release", "to_release"):
            release = exercise[release_key]
            tagged = tagged_file(release, exercise["fixture"])
            if tagged is None:
                continue
            tagged_value = tomllib.loads(tagged.decode())
            tagged_digest = hashlib.sha256(
                json.dumps(tagged_value, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if tagged_digest != expected:
                fail(f"recorded upgrade fixture does not match {release}:{exercise['fixture']}")


def check_cli(inventory: dict) -> None:
    stable_paths = inventory["cli"]["stable_command_paths"]
    scoped_paths = inventory["cli"]["scoped_rr_only_command_paths"]
    require_sorted_unique(stable_paths, "cli.stable_command_paths")
    require_sorted_unique(scoped_paths, "cli.scoped_rr_only_command_paths")
    overlap = sorted(set(stable_paths) & set(scoped_paths))
    if overlap:
        fail(f"CLI paths are both stable and scoped RR-only: {overlap}")
    for contract in inventory["cli"]["versioned_json_contracts"]:
        source = ROOT / contract["source"]
        if contract["id"] not in source.read_text():
            fail(f"JSON contract {contract['id']!r} disappeared from {contract['source']}")
    pinned = inventory["cli"]["test_pinned_json_contracts"]
    pinned_ids = [contract["id"] for contract in pinned]
    require_sorted_unique(pinned_ids, "cli.test_pinned_json_contracts")
    for contract in pinned:
        source = (ROOT / contract["source"]).read_text()
        if contract["test"] not in source:
            fail(
                f"JSON contract test {contract['test']!r} disappeared from {contract['source']}"
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
    public_contract = (ROOT / "docs/v1-stable-contract.md").read_text()
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
    inventory = load_json(INVENTORY_PATH)
    if inventory.get("schema_version") != 1 or inventory.get("contract") != "rustbgpd-rs-rr-v1":
        fail("unexpected inventory schema or contract id")
    check_policy(inventory)
    check_config(inventory, load_json(SCHEMA_PATH))
    check_grpc(inventory)
    check_cli(inventory)
    check_upgrade_exercises(inventory)
    print("v1 stable-surface inventory: OK")


if __name__ == "__main__":
    main()
