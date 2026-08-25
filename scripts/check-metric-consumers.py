#!/usr/bin/env python3
"""Require every emitted Prometheus family to have a shipped consumer."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
TELEMETRY = "crates/telemetry/src/metrics.rs"
SETTLEMENT = "crates/api/src/runtime_config_settlement.rs"
DASHBOARD = ROOT / "docs/grafana/rustbgpd-overview.json"
ALERT_RULES = ROOT / "examples/prometheus/rustbgpd-alerts.yml"
CARGO_LOCK = ROOT / "Cargo.lock"

# Decision records, evidence receipts, and point-in-time status documents remain
# part of the public-document spelling check, but they are historical evidence:
# a metric mention there must not keep an otherwise unused family certified.
# CHANGELOG.md and ROADMAP.md are already outside the shared public-document
# discovery surface, so they cannot certify a metric and do not belong here.
HISTORICAL_DOCUMENTS = frozenset(
    {
        "docs/OPERATIONAL_PROOF.md",
        "docs/RECEIPTS.md",
        "docs/evpn-alpha-soak.md",
        "docs/milestones.md",
        "docs/upstream-findings.md",
    }
)
HISTORICAL_DOCUMENT_PREFIXES = (
    "docs/adr/",
    "docs/artifacts/",
    "docs/perf/",
    "docs/soaks/",
)

EMITTER_FILES = frozenset({TELEMETRY, SETTLEMENT})
CUSTOM_COLLECTORS = frozenset(
    {
        (TELEMETRY, "JemallocCollector"),
        (TELEMETRY, "SessionNotificationDepthCollector"),
        (SETTLEMENT, "RuntimeConfigSettlementCollector"),
    }
)
CUSTOM_COLLECTOR_PREFIXES = {
    (TELEMETRY, "JemallocCollector"): "jemalloc_",
    (TELEMETRY, "SessionNotificationDepthCollector"): "bgp_session_notification_",
    (SETTLEMENT, "RuntimeConfigSettlementCollector"): "bgp_runtime_config_settlement_",
}
SPECIAL_REGISTRATIONS = {
    TELEMETRY: (
        "prometheus::process_collector::ProcessCollector::for_self()",
        "jemalloc_stats::JemallocCollector::new()",
        "SessionNotificationDepthCollector::new(Arc::clone(&session_notification_outstanding_value),Arc::clone(&session_notification_outstanding_high_watermark_value),)",
    ),
    SETTLEMENT: (
        "RuntimeConfigSettlementCollector::new(Arc::clone(&self.registry,))",
    ),
}
PROCESS_COLLECTOR_VERSION = "0.14.0"
PROCESS_FAMILIES = frozenset(
    {
        "process_cpu_seconds_total",
        "process_open_fds",
        "process_max_fds",
        "process_virtual_memory_bytes",
        "process_resident_memory_bytes",
        "process_start_time_seconds",
        "process_threads",
    }
)

# These generic process families intentionally remain raw diagnostics. The
# restart signal has a shipped alert, while these six are useful for ad-hoc
# host/process correlation without prescribing deployment-specific thresholds.
ALLOWLIST = {
    "process_cpu_seconds_total": "generic raw process CPU diagnostic",
    "process_open_fds": "generic raw process file-descriptor diagnostic",
    "process_max_fds": "generic raw process file-descriptor ceiling",
    "process_virtual_memory_bytes": "generic raw process virtual-memory diagnostic",
    "process_resident_memory_bytes": "generic raw process resident-memory diagnostic",
    "process_threads": "generic raw process thread-count diagnostic",
}

METRIC_CONSTRUCTOR = re.compile(
    r"\b(?:Int)?(?:Counter|Gauge)(?:Vec)?::(?:new|with_opts)\s*\("
    r"|\bHistogram(?:Vec)?::(?:new|with_opts)\s*\("
)
RAW_EMITTER_HINT = re.compile(
    r"(?:Int)?(?:Counter|Gauge)(?:Vec)?::(?:new|with_opts)"
    r"|Histogram(?:Vec)?::(?:new|with_opts)"
    r"|impl\s+Collector\s+for|ProcessCollector::for_self"
    r"|\.register\s*\(\s*Box::new"
)
STATIC_DEFINITION = re.compile(
    r"let\s+(\w+)\s*=\s*"
    r"((?:Int)?(?:Counter|Gauge)(?:Vec)?|HistogramVec)::new\(\s*"
    r"(?:(?:Opts|HistogramOpts)::new\(\s*)?__RUST_STRING_(\d+)__",
    re.DOTALL,
)
CUSTOM_COLLECTOR = re.compile(r"\bimpl\s+Collector\s+for\s+(\w+)")
REGISTER_START = re.compile(r"\.register\s*\(\s*Box::new\s*\(")
VARIABLE_REGISTRATION = re.compile(r"(\w+)\.clone\(\)")
METRIC_TOKEN = re.compile(r"(?<![$\w:])([A-Za-z_:][A-Za-z0-9_:]*)(?![\w:])")
RULE_METRIC_PREFIX = re.compile(
    r"^(?:bfd|bgp|bmp|evpn|gnmi|jemalloc|mrt|process)_"
)
EXTERNAL_RULE_INPUTS = frozenset({"up"})
BLOCK_SCALARS = frozenset({">", ">-", ">+", "|", "|-", "|+"})
INLINE_CODE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")


def load_helper(filename: str, module_name: str) -> ModuleType:
    path = ROOT / "scripts" / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load checker helper {path.relative_to(ROOT)}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DASHBOARD_CHECK = load_helper("check-grafana-dashboard.py", "dashboard_contract")
PUBLIC_DOCS_CHECK = load_helper("check_public_tracker_ids.py", "public_docs_contract")


def production_source(source: str) -> str:
    """Drop the conventional trailing Rust test module from source discovery."""
    return re.split(
        r"\n#\[cfg\(test\)\]\s*\nmod\s+tests\s*\{", source, maxsplit=1
    )[0]


def static_metric_definitions(source: str) -> dict[str, tuple[str, str]]:
    """Return statically named metric constructors keyed by local variable."""
    source = production_source(source)
    syntax, strings = DASHBOARD_CHECK.rust_lex(source)
    definitions: dict[str, tuple[str, str]] = {}
    names: set[str] = set()
    for variable, constructor, string_index in STATIC_DEFINITION.findall(syntax):
        name = strings[int(string_index)]
        if variable in definitions:
            raise ValueError(f"duplicate metric constructor variable {variable}")
        if name in names:
            raise ValueError(f"duplicate metric family definition {name}")
        definitions[variable] = (
            name,
            "histogram" if constructor == "HistogramVec" else "ordinary",
        )
        names.add(name)

    constructor_count = len(METRIC_CONSTRUCTOR.findall(syntax))
    if constructor_count != len(definitions):
        raise ValueError(
            "metric constructor inventory is not fully static: "
            f"found {constructor_count} constructor calls but "
            f"{len(definitions)} literal definitions"
        )
    return definitions


def braced_body(syntax: str, pattern: str, description: str) -> str:
    """Return the single balanced brace body following a matched declaration."""
    matches = list(re.finditer(pattern, syntax))
    if len(matches) != 1:
        raise ValueError(f"expected one {description}, found {len(matches)}")
    opening = syntax.find("{", matches[0].start(), matches[0].end())
    depth = 1
    index = opening + 1
    while index < len(syntax) and depth:
        if syntax[index] == "{":
            depth += 1
        elif syntax[index] == "}":
            depth -= 1
        index += 1
    if depth:
        raise ValueError(f"unterminated {description}")
    return syntax[opening + 1 : index - 1]


def registry_registration_expressions(source: str) -> list[str]:
    """Return every Box::new payload registered in production source."""
    syntax, _ = DASHBOARD_CHECK.rust_lex(production_source(source))
    expressions: list[str] = []
    for match in REGISTER_START.finditer(syntax):
        depth = 1
        index = match.end()
        while index < len(syntax) and depth:
            if syntax[index] == "(":
                depth += 1
            elif syntax[index] == ")":
                depth -= 1
            index += 1
        if depth:
            raise ValueError("unterminated registry Box::new registration")
        if re.match(r"\s*,?\s*\)", syntax[index:]) is None:
            raise ValueError("unsupported registry registration after Box::new payload")
        expression = syntax[match.end() : index - 1].strip()
        expressions.append(expression.removesuffix(",").rstrip())

    registration_count = len(re.findall(r"\.register\s*\(", syntax))
    if registration_count != len(expressions):
        raise ValueError(
            "registry registration is not a supported Box::new expression: "
            f"found {registration_count} registrations but parsed {len(expressions)}"
        )
    return expressions


def custom_collector_metric_inventory(
    source: str, collector: str, metric_prefix: str
) -> tuple[dict[str, str], set[str]]:
    """Map every collected custom-collector field to one literal definition."""
    source = production_source(source)
    syntax, _ = DASHBOARD_CHECK.rust_lex(source)
    definitions = static_metric_definitions(source)
    inherent = braced_body(
        syntax,
        rf"\bimpl\s+{re.escape(collector)}\s*\{{",
        f"inherent impl for {collector}",
    )
    collector_impl = braced_body(
        syntax,
        rf"\bimpl\s+Collector\s+for\s+{re.escape(collector)}\s*\{{",
        f"Collector impl for {collector}",
    )
    collect_body = braced_body(
        collector_impl,
        r"\bfn\s+collect\s*\(\s*&self\s*\)\s*->\s*Vec\s*<\s*MetricFamily\s*>\s*\{",
        f"collect method for {collector}",
    )
    if "MetricFamily" in collect_body:
        raise ValueError(
            f"{collector} collect method constructs MetricFamily values directly"
        )
    unexpected_returns = [
        expression
        for expression in re.findall(r"\breturn\s+([^;]+);", collect_body)
        if re.sub(r"\s+", "", expression) != "Vec::new()"
    ]
    if unexpected_returns:
        raise ValueError(
            f"{collector} returns families outside mapped field collection"
        )
    initial_families = re.findall(
        r"\blet\s+mut\s+families\s*=\s*self\.(\w+)\.collect\(\)\s*;",
        collect_body,
    )
    extended_families = re.findall(
        r"\bfamilies\.extend\(\s*self\.(\w+)\.collect\(\)\s*\)\s*;",
        collect_body,
    )
    if len(initial_families) != 1:
        raise ValueError(
            f"{collector} must initialize families from exactly one mapped field"
        )
    collected_field_sequence = [*initial_families, *extended_families]
    collected_fields = set(collected_field_sequence)
    if len(collected_fields) != len(collected_field_sequence):
        raise ValueError(f"{collector} collects a metric field more than once")
    if len(re.findall(r"\bfamilies\b", collect_body)) != len(collected_fields) + 1:
        raise ValueError(
            f"{collector} assembles families outside mapped field collection"
        )
    if re.search(r"\bfamilies\s*$", collect_body.strip()) is None:
        raise ValueError(f"{collector} does not return its mapped families")
    unexpected_collects = set(
        re.findall(r"self\.(\w+)\.collect\(\)", collect_body)
    ) - collected_fields
    if unexpected_collects:
        raise ValueError(
            f"{collector} has unsupported collected fields: {sorted(unexpected_collects)}"
        )
    if not collected_fields:
        raise ValueError(f"{collector} has no collected metric fields")

    field_variables: dict[str, set[str]] = {}
    for body in re.findall(r"(?<!-> )\bSelf\s*\{([^{}]*)\}", inherent):
        for entry in body.split(","):
            parts = [part.strip() for part in entry.split(":", 1)]
            if not parts or not parts[0]:
                continue
            field, variable = parts[0], parts[-1]
            field_variables.setdefault(field, set()).add(variable)

    emitted: dict[str, str] = {}
    emitted_variables: set[str] = set()
    for field in sorted(collected_fields):
        variables = field_variables.get(field, set())
        if len(variables) != 1:
            raise ValueError(
                f"{collector} collected field {field} has no unique constructor mapping"
            )
        variable = next(iter(variables))
        if variable not in definitions:
            raise ValueError(
                f"{collector} collected field {field} does not map to a literal metric definition"
            )
        name, kind = definitions[variable]
        if not name.startswith(metric_prefix):
            raise ValueError(
                f"{collector} field {field} emits unexpected metric family {name}"
            )
        emitted[name] = kind
        emitted_variables.add(variable)

    custom_variables = {
        variable
        for variable, (name, _) in definitions.items()
        if name.startswith(metric_prefix)
    }
    missing = sorted(custom_variables - emitted_variables)
    if missing:
        raise ValueError(
            f"{collector} literal metric definitions are not collected: {missing}"
        )
    return emitted, emitted_variables


def registered_metric_variables(
    relative: str, source: str, definitions: dict[str, tuple[str, str]]
) -> set[str]:
    """Require every registry payload to be a literal metric or pinned collector."""
    variables: list[str] = []
    specials: list[str] = []
    for expression in registry_registration_expressions(source):
        compact = re.sub(r"\s+", "", expression)
        variable = VARIABLE_REGISTRATION.fullmatch(compact)
        if variable is not None:
            name = variable.group(1)
            if name not in definitions:
                raise ValueError(
                    f"registered variable {name} has no parsed literal metric definition"
                )
            variables.append(name)
        else:
            specials.append(compact)

    expected_specials = Counter(SPECIAL_REGISTRATIONS[relative])
    actual_specials = Counter(specials)
    if actual_specials != expected_specials:
        raise ValueError(
            f"special collector registrations changed: expected {expected_specials}, "
            f"got {actual_specials}"
        )
    duplicates = sorted(name for name, count in Counter(variables).items() if count != 1)
    if duplicates:
        raise ValueError(f"metric variables registered more than once: {duplicates}")
    return set(variables)


def session_notification_depth_inventory(source: str) -> tuple[dict[str, str], set[str]]:
    """Validate the two fresh local gauges emitted by the atomic depth collector."""
    source = production_source(source)
    syntax, _ = DASHBOARD_CHECK.rust_lex(source)
    collector_impl = braced_body(
        syntax,
        r"\bimpl\s+Collector\s+for\s+SessionNotificationDepthCollector\s*\{",
        "Collector impl for SessionNotificationDepthCollector",
    )
    collect_body = braced_body(
        collector_impl,
        r"\bfn\s+collect\s*\(\s*&self\s*\)\s*->\s*Vec\s*<\s*MetricFamily\s*>\s*\{",
        "collect method for SessionNotificationDepthCollector",
    )
    definitions = static_metric_definitions(source)
    emitted = {
        variable: definition
        for variable, definition in definitions.items()
        if definition[0].startswith("bgp_session_notification_")
    }
    expected = {
        "current_gauge": ("bgp_session_notification_outstanding", "ordinary"),
        "high_watermark_gauge": (
            "bgp_session_notification_outstanding_high_watermark",
            "ordinary",
        ),
    }
    if emitted != expected:
        raise ValueError(
            "SessionNotificationDepthCollector must construct exactly two uniquely "
            f"named local gauges: expected {expected}, got {emitted}"
        )
    if collect_body.count("IntGauge::new(") != 2:
        raise ValueError(
            "SessionNotificationDepthCollector must construct exactly two local IntGauge encoders"
        )
    initial = "let mut families = current_gauge.collect();"
    extension = "families.extend(high_watermark_gauge.collect());"
    if collect_body.count(initial) != 1 or collect_body.count(extension) != 1:
        raise ValueError(
            "SessionNotificationDepthCollector must assemble each local gauge exactly once"
        )
    if re.search(r"\bfamilies\s*$", collect_body.strip()) is None:
        raise ValueError(
            "SessionNotificationDepthCollector must return its assembled families"
        )
    return {name: kind for name, kind in emitted.values()}, set(emitted)


def candidate_emitter_sources(root: Path = ROOT) -> dict[str, str]:
    """Discover tracked production Rust files that can define metric families."""
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.rs"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or f"git ls-files exited {result.returncode}"
        raise ValueError(f"cannot discover Rust metric emitters: {detail}")

    sources: dict[str, str] = {}
    for relative in (name for name in result.stdout.split("\0") if name):
        path = root / relative
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise ValueError(f"cannot read tracked Rust source {relative}: {error}") from error
        production = production_source(source)
        # Avoid feeding unrelated Rust syntax to the deliberately small lexer.
        # Any supported or unclassified emitter still carries one of these
        # constructor/collector tokens in code before lexical masking.
        if RAW_EMITTER_HINT.search(production) is None:
            continue
        syntax, _ = DASHBOARD_CHECK.rust_lex(production)
        if (
            METRIC_CONSTRUCTOR.search(syntax)
            or CUSTOM_COLLECTOR.search(syntax)
            or "ProcessCollector::for_self" in syntax
            or REGISTER_START.search(syntax)
        ):
            sources[relative] = production
    if not sources:
        raise ValueError("no production metric emitter sources discovered")
    return sources


def validate_emitter_roster(sources: dict[str, str]) -> None:
    actual_files = set(sources)
    if actual_files != EMITTER_FILES:
        raise ValueError(
            "metric emitter source roster changed: "
            f"expected {sorted(EMITTER_FILES)}, got {sorted(actual_files)}"
        )

    actual_collectors = {
        (relative, collector)
        for relative, source in sources.items()
        for collector in CUSTOM_COLLECTOR.findall(
            DASHBOARD_CHECK.rust_lex(production_source(source))[0]
        )
    }
    if actual_collectors != CUSTOM_COLLECTORS:
        raise ValueError(
            "custom metric collector roster changed: "
            f"expected {sorted(CUSTOM_COLLECTORS)}, got {sorted(actual_collectors)}"
        )


def settlement_metric_inventory(source: str) -> dict[str, str]:
    """Inventory scrape-time families wired through the settlement collector."""
    source = production_source(source)
    definitions = static_metric_definitions(source)
    registered = registered_metric_variables(SETTLEMENT, source, definitions)
    if registered:
        raise ValueError(
            f"runtime settlement unexpectedly registers direct metric variables: {registered}"
        )
    emitted, _ = custom_collector_metric_inventory(
        source,
        "RuntimeConfigSettlementCollector",
        CUSTOM_COLLECTOR_PREFIXES[(SETTLEMENT, "RuntimeConfigSettlementCollector")],
    )
    return emitted


def process_dependency_version(lock_text: str) -> str:
    lock = tomllib.loads(lock_text)
    versions = sorted(
        package.get("version", "")
        for package in lock.get("package", [])
        if package.get("name") == "prometheus"
    )
    if versions != [PROCESS_COLLECTOR_VERSION]:
        raise ValueError(
            "Prometheus dependency version changed; revalidate ProcessCollector families: "
            f"expected {[PROCESS_COLLECTOR_VERSION]}, got {versions}"
        )
    return versions[0]


def workspace_metric_inventory(
    sources: dict[str, str] | None = None, lock_text: str | None = None
) -> dict[str, str]:
    sources = sources or candidate_emitter_sources()
    validate_emitter_roster(sources)
    for relative, source in sources.items():
        try:
            static_metric_definitions(source)
        except ValueError as error:
            raise ValueError(f"{relative}: {error}") from error

    telemetry_definitions = static_metric_definitions(sources[TELEMETRY])
    registered = registered_metric_variables(
        TELEMETRY, sources[TELEMETRY], telemetry_definitions
    )
    jemalloc, jemalloc_variables = custom_collector_metric_inventory(
        sources[TELEMETRY],
        "JemallocCollector",
        CUSTOM_COLLECTOR_PREFIXES[(TELEMETRY, "JemallocCollector")],
    )
    session_depth, session_depth_variables = session_notification_depth_inventory(
        sources[TELEMETRY]
    )
    expected_registered = (
        set(telemetry_definitions) - jemalloc_variables - session_depth_variables
    )
    if registered != expected_registered:
        missing = sorted(
            telemetry_definitions[variable][0]
            for variable in expected_registered - registered
        )
        extra = sorted(
            telemetry_definitions[variable][0]
            for variable in registered - expected_registered
        )
        raise ValueError(
            "telemetry registration does not match its definitions: "
            f"unregistered={missing}, undefined={extra}"
        )
    telemetry = {
        telemetry_definitions[variable][0]: telemetry_definitions[variable][1]
        for variable in registered
    }
    telemetry.update(jemalloc)
    telemetry.update(session_depth)

    settlement = settlement_metric_inventory(sources[SETTLEMENT])
    overlap = sorted(set(telemetry) & set(settlement))
    if overlap:
        raise ValueError(f"duplicate workspace metric families: {overlap}")

    process_dependency_version(lock_text or CARGO_LOCK.read_text(encoding="utf-8"))

    inventory = {**telemetry, **settlement}
    for name in PROCESS_FAMILIES:
        if name in inventory:
            raise ValueError(f"process family duplicates workspace family {name}")
        inventory[name] = "ordinary"
    if len(inventory) != 196:
        raise ValueError(f"emitted metric roster changed: expected 196, got {len(inventory)}")
    return dict(sorted(inventory.items()))


def normalize_metric(name: str, inventory: dict[str, str]) -> str | None:
    if name in inventory:
        return name
    for suffix in ("_bucket", "_count", "_sum"):
        if name.endswith(suffix):
            base = name.removesuffix(suffix)
            if inventory.get(base) == "histogram":
                return base
    return None


def rule_expressions(text: str) -> list[tuple[int, str]]:
    """Extract only YAML rule expression scalars without needing PyYAML."""
    lines = text.splitlines()
    expressions: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)expr:\s*(.*)$", lines[index])
        if match is None:
            index += 1
            continue
        line_number = index + 1
        indentation = len(match.group(1))
        remainder = match.group(2).strip()
        index += 1
        if not remainder:
            raise ValueError(f"empty YAML expr scalar at line {line_number}")
        reject_yaml_expr_references(remainder, line_number)
        if remainder.startswith((">", "|")) and remainder not in BLOCK_SCALARS:
            raise ValueError(
                f"unsupported YAML expr block header at line {line_number}: {remainder}"
            )
        if remainder not in BLOCK_SCALARS:
            continuation: list[str] = []
            while index < len(lines):
                line = lines[index]
                current_indent = len(line) - len(line.lstrip())
                if line.strip() and current_indent <= indentation:
                    break
                continuation.append(line.strip())
                index += 1
            scalar = "\n".join([remainder, *continuation])
            decoded = decode_yaml_scalar(scalar, line_number)
            require_nonempty_yaml_expression(decoded, line_number)
            expressions.append((line_number, decoded))
            continue
        body: list[str] = []
        while index < len(lines):
            line = lines[index]
            current_indent = len(line) - len(line.lstrip())
            if line.strip() and current_indent <= indentation:
                break
            body.append(line)
            index += 1
        scalar = "\n".join(body)
        require_nonempty_yaml_expression(scalar, line_number)
        expressions.append((line_number, scalar))
    if not expressions:
        raise ValueError("no Prometheus rule expressions discovered")
    return expressions


def reject_yaml_expr_references(value: str, line_number: int) -> None:
    """Reject dependency-free parser ambiguities around YAML anchors and aliases."""
    syntax = strip_yaml_inline_comment(value)
    syntax = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\'\'|[^\'])*\'', '""', syntax)
    if re.match(r"\s*!", syntax):
        raise ValueError(f"unsupported YAML expr tag at line {line_number}")
    if re.match(r"\s*[&*][A-Za-z0-9_-]+(?:\s|$)", syntax):
        raise ValueError(f"unsupported YAML expr anchor or alias at line {line_number}")


def decode_yaml_scalar(value: str, line_number: int) -> str:
    """Decode the quoted scalar forms accepted by this dependency-free parser."""
    if not value.startswith(("\"", "'")):
        return value
    match = re.fullmatch(
        r'("(?:\\.|[^"\\])*"|\'(?:\'\'|[^\'])*\')\s*(?:#.*)?', value
    )
    if match is None:
        raise ValueError(f"unsupported quoted YAML expr scalar at line {line_number}")
    scalar = match.group(1)
    if scalar.startswith("'"):
        return scalar[1:-1].replace("''", "'")
    try:
        decoded = json.loads(scalar)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"unsupported double-quoted YAML expr scalar at line {line_number}: {error.msg}"
        ) from error
    if not isinstance(decoded, str):
        raise ValueError(f"non-string YAML expr scalar at line {line_number}")
    return decoded


def strip_yaml_inline_comment(value: str) -> str:
    """Remove a YAML/PromQL comment marker only when it is outside quotes."""
    single_quoted = double_quoted = escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\" and double_quoted:
            escaped = True
            continue
        if character == "\"" and not single_quoted:
            double_quoted = not double_quoted
            continue
        if character == "'" and not double_quoted:
            single_quoted = not single_quoted
            continue
        if (
            character == "#"
            and not single_quoted
            and not double_quoted
            and (index == 0 or value[index - 1].isspace())
        ):
            return value[:index].rstrip()
    return value


def require_nonempty_yaml_expression(value: str, line_number: int) -> None:
    """Reject scalars that are empty after decoding and removing comments."""
    visible = "\n".join(
        strip_yaml_inline_comment(line) for line in value.splitlines()
    ).strip()
    if not visible:
        raise ValueError(f"empty YAML expr scalar at line {line_number}")


def rule_metric_references(
    text: str, inventory: dict[str, str]
) -> dict[str, list[str]]:
    references: dict[str, list[str]] = {}
    unresolved: list[str] = []
    for line_number, expression in rule_expressions(text):
        expression = "\n".join(
            strip_yaml_inline_comment(line) for line in expression.splitlines()
        )
        syntax = re.sub(r'"(?:\\.|[^"\\])*"', '""', expression)
        syntax = "\n".join(
            line for line in syntax.splitlines() if not line.lstrip().startswith("#")
        )
        for token in METRIC_TOKEN.findall(syntax):
            name = normalize_metric(token, inventory)
            if name is not None:
                references.setdefault(name, []).append(f"line {line_number}")
            elif token not in EXTERNAL_RULE_INPUTS and RULE_METRIC_PREFIX.match(token):
                unresolved.append(f"{token} (line {line_number})")
    if unresolved:
        raise ValueError("unregistered Prometheus rule metrics: " + "; ".join(unresolved))
    if not references:
        raise ValueError("no emitted metric references discovered in Prometheus rules")
    return references


def public_document_references(
    documents: dict[str, str], inventory: dict[str, str]
) -> dict[str, list[str]]:
    references: dict[str, list[str]] = {}
    markdown = {
        relative: text
        for relative, text in documents.items()
        if Path(relative).suffix == ".md"
    }
    if not markdown:
        raise ValueError("no public Markdown documents discovered")
    metric_spellings = {
        spelling: name
        for name, kind in inventory.items()
        for spelling in (
            (name, f"{name}_bucket", f"{name}_count", f"{name}_sum")
            if kind == "histogram"
            else (name,)
        )
    }
    near_misses: list[str] = []
    for relative, text in markdown.items():
        for token in set(METRIC_TOKEN.findall(text)):
            name = normalize_metric(token, inventory)
            if name is not None:
                references.setdefault(name, []).append(relative)
        metric_context = "\n".join(
            [
                *INLINE_CODE.findall(text),
                *(line for line in text.splitlines() if "|" in line),
                *markdown_fenced_code(text),
            ]
        )
        for token in set(METRIC_TOKEN.findall(metric_context)):
            if normalize_metric(token, inventory) is not None:
                continue
            matches = sorted(
                spelling
                for spelling in metric_spellings
                if one_documentation_edit_apart(token, spelling)
            )
            if matches:
                near_misses.append(f"{token} ({relative}; near {matches[0]})")
    if near_misses:
        raise ValueError(
            "near-miss emitted metric names in public docs: " + "; ".join(near_misses)
        )
    return references


def document_evidence_class(relative: str) -> str:
    """Classify a public Markdown path as normative or historical evidence."""
    if relative in HISTORICAL_DOCUMENTS or relative.startswith(
        HISTORICAL_DOCUMENT_PREFIXES
    ):
        return "historical"
    return "normative"


def normative_document_references(
    references: dict[str, list[str]],
) -> set[str]:
    """Return metric names backed by current operator-facing guidance."""
    return {
        name
        for name, documents in references.items()
        if any(
            document_evidence_class(relative) == "normative"
            for relative in documents
        )
    }


def markdown_fenced_code(text: str) -> list[str]:
    """Return fenced Markdown bodies without widening typo checks to prose."""
    bodies: list[str] = []
    opening_character = ""
    opening_length = 0
    body: list[str] = []
    for line in text.splitlines():
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if not opening_character:
            if marker is not None:
                opening_character = marker.group(1)[0]
                opening_length = len(marker.group(1))
                body = []
            continue
        closing = re.fullmatch(
            rf" {{0,3}}{re.escape(opening_character)}{{{opening_length},}}\s*", line
        )
        if closing is not None:
            bodies.append("\n".join(body))
            opening_character = ""
            opening_length = 0
            body = []
        else:
            body.append(line)
    if opening_character:
        bodies.append("\n".join(body))
    return bodies


def one_documentation_edit_apart(left: str, right: str) -> bool:
    """Return whether one insertion, deletion, substitution, or swap separates tokens."""
    if left == right or abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        mismatches = [
            index for index, pair in enumerate(zip(left, right)) if pair[0] != pair[1]
        ]
        if len(mismatches) == 1:
            return True
        return (
            len(mismatches) == 2
            and mismatches[1] == mismatches[0] + 1
            and left[mismatches[0]] == right[mismatches[1]]
            and left[mismatches[1]] == right[mismatches[0]]
        )
    if len(left) > len(right):
        left, right = right, left
    left_index = right_index = differences = 0
    while left_index < len(left) and right_index < len(right):
        if left[left_index] == right[right_index]:
            left_index += 1
            right_index += 1
        else:
            differences += 1
            right_index += 1
            if differences > 1:
                return False
    return True


def validate_coverage(
    inventory: dict[str, str],
    consumers: set[str],
    allowlist: dict[str, str] = ALLOWLIST,
) -> None:
    empty_reasons = sorted(name for name, reason in allowlist.items() if not reason.strip())
    unknown = sorted(set(allowlist) - set(inventory))
    stale = sorted(set(allowlist) & consumers)
    missing = sorted(set(inventory) - consumers - set(allowlist))
    failures: list[str] = []
    if empty_reasons:
        failures.append(f"allowlist entries without reasons: {empty_reasons}")
    if unknown:
        failures.append(f"allowlist entries are not emitted: {unknown}")
    if stale:
        failures.append(f"allowlist entries now have shipped consumers: {stale}")
    if missing:
        failures.append(f"emitted metric families lack shipped consumers: {missing}")
    if failures:
        raise ValueError("; ".join(failures))


def main() -> int:
    try:
        inventory = workspace_metric_inventory()
        dashboard = json.loads(DASHBOARD.read_text(encoding="utf-8"))
        dashboard_raw = DASHBOARD_CHECK.dashboard_metric_references(dashboard)
        DASHBOARD_CHECK.check_metric_linkage(dashboard_raw, inventory)
        dashboard_refs = {
            normalized
            for name in dashboard_raw
            if (normalized := normalize_metric(name, inventory)) is not None
        }
        rule_refs = set(
            rule_metric_references(
                ALERT_RULES.read_text(encoding="utf-8"), inventory
            )
        )
        documents = PUBLIC_DOCS_CHECK.discover_documents()
        public_doc_refs = public_document_references(documents, inventory)
        doc_refs = normative_document_references(public_doc_refs)
        consumers = dashboard_refs | rule_refs | doc_refs
        validate_coverage(inventory, consumers)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"metric consumer check failed: {error}", file=sys.stderr)
        return 1

    print(
        "metric consumer check passed: "
        f"{len(inventory)} emitted families; "
        f"{len(dashboard_refs)} dashboard, {len(rule_refs)} rules, "
        f"{len(doc_refs)} normative-doc families; {len(consumers)} consumed, "
        f"{len(ALLOWLIST)} justified raw diagnostics"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
