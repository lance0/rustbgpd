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
    "complete-rejected-route-reason-inventory",
    "less-specific-longest-prefix-match",
    "atomic-all-candidate-table-snapshot",
    "runtime-protocol-alias-configuration",
}


def fail(message: str) -> None:
    raise SystemExit(message)


root = Path(__file__).resolve().parent
capture = Path(sys.argv[1])
manifest = json.loads((root / "contract.json").read_text())
if manifest.get("runtime_compatibility") is not False:
    fail("contract oracle must not promote a runtime compatibility claim")
if set(manifest.get("unsupported", [])) != UNSUPPORTED:
    fail("unsupported compatibility matrix drifted")
if manifest.get("protocol_aliases") != {"member-v4": "pb_as64496"}:
    fail("explicit protocol alias matrix drifted")

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
