"""Daemon evidence shared by the two flagship soak analyzers (stdlib only)."""

import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

# print_startup_banner emits these lines to stderr even with JSON logging.
# Only the flagship shapes are accepted, once, as a complete contiguous block.
BANNER = re.compile(
    r"  rustbgpd \d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)? \| AS \d+ \| router-id [0-9.]+\n"
    r"  \|- \d+ peers \(\d+ [ei]BGP(?:, \d+ [ei]BGP)?\)"
    r"(?: in \d+ peer groups?)?\n"
    r"(?:  \|- \d+ named polic(?:y|ies)(?:, \d+ neighbor sets?)?\n)?"
    r"  \|- grpc: (?:unix:///[^\s]+|tcp://[^\s]+)"
    r"(?: \(read-only\))?(?: \(token auth\))?\n"
    r"  \|- metrics: http://[^\s]+/metrics\n"
)


def unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"invalid JSON constant {value}")


def analyze_daemon_log(run_dir):
    """Fail closed; retain counts and bounded diagnostics, not multi-GB logs."""
    warnings = Counter()
    records = errors = defects = 0
    examples = []
    banner = []
    banner_seen = False

    def defect(message):
        nonlocal defects
        defects += 1
        if len(examples) < 20:
            examples.append(message)

    try:
        with (Path(run_dir) / "rustbgpd.log").open(encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                if not line.endswith("\n"):
                    defect(f"line {number}: unterminated record")
                if banner:
                    if line == "\n":
                        if not BANNER.fullmatch("".join(banner)):
                            defect(f"line {number}: invalid startup banner")
                        banner = []
                        continue
                    if len(banner) < 6 and line.startswith("  "):
                        banner.append(line)
                        continue
                    defect(f"line {number}: incomplete startup banner")
                    banner = []
                if line == "\n":
                    continue
                if not banner_seen and line.startswith("  rustbgpd "):
                    banner_seen = True
                    banner = [line]
                    continue
                try:
                    record = json.loads(line, object_pairs_hook=unique_members,
                                        parse_constant=reject_constant)
                    if not isinstance(record, dict):
                        raise ValueError("record is not an object")
                    level = record.get("level")
                    fields = record.get("fields")
                    if (level not in ("TRACE", "DEBUG", "INFO", "WARN", "ERROR")
                            or not isinstance(fields, dict)
                            or not isinstance(fields.get("message"), str)
                            or not fields["message"]
                            or not isinstance(record.get("target"), str)
                            or not record["target"]):
                        raise ValueError("invalid level, fields.message, or target")
                    stamp = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
                    if stamp.tzinfo is None:
                        raise ValueError("timestamp has no timezone")
                except (ValueError, TypeError, KeyError, AttributeError) as exc:
                    defect(f"line {number}: invalid daemon record: {exc}")
                    continue
                records += 1
                if level == "WARN":
                    warnings[fields["message"]] += 1
                elif level == "ERROR":
                    # No scenario-justified ERROR exceptions have been established.
                    errors += 1
                    if len(examples) < 20:
                        examples.append(f"line {number}: {record['target']}: {fields}")
    except (OSError, UnicodeError) as exc:
        defect(f"cannot read rustbgpd.log: {exc}")
    if banner:
        defect("incomplete startup banner at end of file")
    if not records:
        defect("no daemon JSON records")
    return {
        "value": {"records": records, "errors": errors, "defects": defects,
                  "warnings_by_message": dict(sorted(warnings.items())),
                  "examples": examples},
        "pass": records > 0 and errors == 0 and defects == 0,
    }
