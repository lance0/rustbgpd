#!/usr/bin/env python3
"""Qualify VPN FlowSpec refusal against released v0.81.0, without peers.

OUT_DIR=/absolute/new/directory python3 tests/interop/scripts/qualify-vpn-flowspec-rollback.py

Both VPN families must refuse add, leased/guarded add, delete, guarded delete,
local listing and export lookup without changing global rules or leases. Each
operation has a matching global positive control. Snapshots are validated before
comparison, as in qualify-guarded-flowspec-rollback.sh. Transport/client failures
are INVALID, never feature refusals. No request is retried with a global family.

QUAL_FAULT=after-read, call-transport or global-fallback seeds checker failures.
Local only; no hosted-CI, forwarding, scale or router qualification is implied.
"""

import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[3]
# Published 2026-11-01, source eb1749d7018cd9691e4f4c9adef3b9adb830e9a8.
IMAGE = "ghcr.io/lance0/rustbgpd@sha256:f8a6d62ced049e415d702e31c43cbd6dac62fa9bcfdd0f410938f3c6cc418a64"
GLOBAL_FAMILIES = ("ADDRESS_FAMILY_IPV4_FLOWSPEC", "ADDRESS_FAMILY_IPV6_FLOWSPEC")


def refusal_status(returncode, stderr):
    if returncode == 0:
        return "FAIL", "scoped request returned OK"
    match = re.fullmatch(
        r"ERROR:\s+Code: (InvalidArgument|Unimplemented)\n\s+Message: .+\s*", stderr
    )
    if match:
        return "PASS", match.group(1)
    return "INVALID", "no definitive application refusal; see stderr"


def read_listing(text, kind):
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("listing is not an object")
    rows = value.get("receivedRoutes" if kind == "routes" else kind, [])
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError(f"malformed {kind} listing")
    if kind == "routes":
        if value.get("receivedView") is not True:
            raise ValueError("local-intent view was not acknowledged")
        if value.get("routes", []) != []:
            raise ValueError("local-intent listing contains selected rows")
        if any(
            not isinstance(row.get("route"), dict)
            or row["route"].get("afiSafi") not in GLOBAL_FAMILIES
            for row in rows
        ):
            raise ValueError("global listing contains an unexpected family")
    return value


def run(args):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)


def stable_rules(text):
    rows = read_listing(text, "routes").get("receivedRoutes", [])
    # Remaining time naturally decreases between positive-control reads.
    for row in rows:
        row["route"].pop("leaseRemainingMs", None)
    return json.dumps(rows, sort_keys=True)


def main():
    out = Path(os.environ["OUT_DIR"])
    if not out.is_absolute():
        raise ValueError("OUT_DIR must be absolute")
    out.mkdir(parents=True, exist_ok=False)
    results = []

    def verdict(name, status, detail):
        results.append({"name": name, "status": status, "detail": detail})
        line = f"{name} {status} {detail}\n"
        print(line, end="", flush=True)
        with (out / "rollback-verdicts").open("a") as handle:
            handle.write(line)

    def require(condition, name, detail):
        if not condition:
            verdict(name, "INVALID", detail)
            raise ValueError(detail)

    with tempfile.TemporaryDirectory(prefix="vpn-flowspec-rollback.") as state:
        name = Path(state).name.replace(".", "-")
        config = Path(state) / "config.toml"
        config.write_text("""[global]
asn = 65001
router_id = "192.0.2.1"
listen_port = 1179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"
token_file = "/run/rustbgpd/token"
principal = "rustbgpd://operator/test-only"
[security.grpc]
enforcement = "tier"
[security.grpc.roles]
"rustbgpd://operator/test-only" = "operator"
""")
        config.chmod(0o644)
        (out / "config.toml").write_text(config.read_text())
        token_file = ROOT / "tests/fixtures/grpc-test-only-operator.token"
        token = token_file.read_text().strip()
        try:
            image = run(["docker", "image", "inspect", IMAGE])
            (out / "rollback-image.json").write_text(image.stdout)
            require(image.returncode == 0, "image", "pinned release image must already be pulled")
            started = run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    name,
                    "--network",
                    "bridge",
                    "--cpuset-cpus",
                    ",".join(map(str, sorted(os.sched_getaffinity(0)))),
                    "-v",
                    f"{config}:/etc/rustbgpd/config.toml:ro",
                    "-v",
                    f"{token_file}:/run/rustbgpd/token:ro",
                    IMAGE,
                ]
            )
            (out / "rollback-start.txt").write_text(started.stdout + started.stderr)
            require(started.returncode == 0, "start", "docker run must succeed")
            inspected = run(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    name,
                ]
            )
            require(
                inspected.returncode == 0 and bool(inspected.stdout.strip()),
                "start",
                "container has no bridge address",
            )
            address = inspected.stdout.strip() + ":50051"

            def call(label, method, body):
                (out / f"{label}.request.json").write_text(json.dumps(body, indent=2) + "\n")
                response = run(
                    [
                        "grpcurl",
                        "-plaintext",
                        "-max-time",
                        "5",
                        "-import-path",
                        ".",
                        "-proto",
                        "proto/rustbgpd.proto",
                        "-H",
                        f"authorization: Bearer {token}",
                        "-d",
                        json.dumps(body),
                        address,
                        f"rustbgpd.v1.{method}",
                    ]
                )
                (out / f"{label}.stdout").write_text(response.stdout)
                (out / f"{label}.stderr").write_text(response.stderr)
                (out / f"{label}.exit").write_text(f"{response.returncode}\n")
                return response

            def ok(label, method, body):
                response = call(label, method, body)
                require(
                    response.returncode == 0, label, "positive control or inventory read failed"
                )
                value = json.loads(response.stdout)
                require(isinstance(value, dict), label, "response is not a JSON object")
                return value

            def snapshot(label):
                snapshots = []
                for kind, method, body in (
                    ("leases", "InjectionService/ListInjectionLeases", {}),
                    ("routes", "RibService/ListFlowSpecRoutes", {"receivedPeerAddress": "0.0.0.0"}),
                ):
                    response = call(f"{label}-{kind}", method, body)
                    require(response.returncode == 0, label, f"{kind} snapshot read failed")
                    read_listing(response.stdout, kind)
                    snapshots.append(response.stdout)
                return tuple(snapshots)

            for attempt in range(30):
                health = call(f"health-{attempt}", "ControlService/GetHealth", {})
                if health.returncode == 0:
                    break
                time.sleep(1)
            require(health.returncode == 0, "start", "daemon never answered GetHealth")
            require(
                json.loads(health.stdout).get("daemonVersion") == "0.81.0",
                "release",
                "unexpected daemon version",
            )

            cases = []
            for global_family, vpn_family, prefix in ((3, 13, "203.0.113."), (4, 14, "2001:db8::")):

                def rule(number, rate=0, family=global_family, base=prefix):
                    return {
                        "afiSafi": family,
                        "components": [
                            {"type": 1, "prefix": f"{base}{number}/{32 if family == 3 else 128}"}
                        ],
                        "actions": [{"trafficRate": {"rate": rate}}],
                    }

                owner = f"rollback-v{4 if global_family == 3 else 6}"
                guard_owner = f"{owner}-guarded"
                window = ok(
                    f"v{vpn_family}-window",
                    "InjectionService/IssueMutationWindow",
                    {"owner": guard_owner, "windowSeconds": 120},
                )["window"]
                ok(f"v{vpn_family}-seed-add", "InjectionService/AddFlowSpec", rule(10))
                ok(f"v{vpn_family}-seed-delete", "InjectionService/AddFlowSpec", rule(20))
                add, leased, guarded = rule(10, 100), rule(30), rule(40)
                delete = {"afiSafi": global_family, "components": rule(20)["components"]}
                guard_delete = {
                    "afiSafi": global_family,
                    "components": guarded["components"],
                    "owner": guard_owner,
                    "revision": "1",
                }
                cases.extend(
                    [
                        (vpn_family, "AddFlowSpec", add, "REPLACED"),
                        (
                            vpn_family,
                            "AddLeasedFlowSpec",
                            {"rule": leased, "lease": {"owner": owner, "leaseSeconds": 120}},
                            "CREATED",
                        ),
                        (
                            vpn_family,
                            "AddGuardedFlowSpec",
                            {
                                "rule": guarded,
                                "lease": {"owner": guard_owner, "leaseSeconds": 120},
                                "window": window,
                                "revision": "1",
                            },
                            "CREATED",
                        ),
                        (vpn_family, "DeleteFlowSpec", delete, "DELETED"),
                        (vpn_family, "DeleteGuardedFlowSpec", guard_delete, "DELETED"),
                        (
                            vpn_family,
                            "ListFlowSpecRoutes",
                            {"afiSafi": global_family, "receivedPeerAddress": "0.0.0.0"},
                            None,
                        ),
                        (
                            vpn_family,
                            "ListFlowSpecExportDispositions",
                            {"afiSafi": global_family, "components": add["components"]},
                            None,
                        ),
                    ]
                )
            before = snapshot("before")
            require(
                not json.loads(before[0]).get("leases"),
                "baseline",
                "baseline lease inventory must be empty",
            )
            require(
                len(json.loads(before[1]).get("receivedRoutes", [])) == 4,
                "baseline",
                "four global sibling rules must exist",
            )
            fault = os.environ.get("QUAL_FAULT", "")
            require(
                fault in ("", "after-read", "call-transport", "global-fallback"),
                "fault",
                "unknown QUAL_FAULT",
            )
            for vpn_family, method, global_body, _ in cases:
                body = json.loads(json.dumps(global_body))
                key = body.get("rule", body)
                key["afiSafi"] = vpn_family
                if method != "ListFlowSpecRoutes":
                    key["rd"] = "44407:40"
                if method.startswith("Add"):
                    key["routeTargets"] = ["44407:777"]
                if fault == "global-fallback":
                    body = global_body
                if fault == "call-transport":
                    run(["docker", "stop", name])
                label = f"vpn-{vpn_family}-{method}"
                service = "RibService" if method == "ListFlowSpecRoutes" else "InjectionService"
                response = call(label, f"{service}/{method}", body)
                verdict(label, *refusal_status(response.returncode, response.stderr))
                if fault == "after-read":
                    run(["docker", "stop", name])
                after = snapshot(f"{label}-after")
                verdict(
                    f"{label}-inventory",
                    "PASS" if before == after else "FAIL",
                    "global rules and leases byte-identical"
                    if before == after
                    else "global rules or leases changed",
                )
                if fault:
                    break
            if not fault:
                for _, method, body, outcome in cases:
                    family = body.get("rule", body)["afiSafi"]
                    label = f"global-{family}-{method}"
                    service = "RibService" if method == "ListFlowSpecRoutes" else "InjectionService"
                    prior = snapshot(f"{label}-before")
                    result = ok(label, f"{service}/{method}", body)
                    after = snapshot(f"{label}-after")
                    if outcome:
                        actual = result.get("result", result).get("outcome", "")
                        require(
                            actual
                            == f"FLOW_SPEC_{'DELETE' if method.startswith('Delete') else 'INJECT'}_OUTCOME_{outcome}",
                            label,
                            "unexpected mutation outcome",
                        )
                        require(
                            stable_rules(prior[1]) != stable_rules(after[1]),
                            label,
                            "global control did not change rules",
                        )
                        if method in ("AddLeasedFlowSpec", "AddGuardedFlowSpec"):
                            owner = body["lease"]["owner"]
                            if method == "AddGuardedFlowSpec":
                                owner = "guarded:" + owner
                            require(
                                owner
                                in {row["owner"] for row in json.loads(after[0]).get("leases", [])},
                                label,
                                "global control did not create its lease",
                            )
                    elif method == "ListFlowSpecRoutes":
                        read_listing(json.dumps(result), "routes")
                        require(
                            bool(result.get("receivedRoutes")),
                            label,
                            "global listing must contain seeded rules",
                        )
                    verdict(
                        label,
                        "PASS",
                        "matching global operation succeeded"
                        + (" and changed inventory" if outcome else ""),
                    )
        except (ValueError, KeyError, OSError) as error:
            verdict("run", "INVALID", str(error))
        finally:
            logs = run(["docker", "logs", name])
            (out / "rollback-daemon.log").write_text(logs.stdout + logs.stderr)
            removed = run(["docker", "rm", "-f", name])
            (out / "rollback-cleanup.txt").write_text(removed.stdout + removed.stderr)
            if removed.returncode != 0:
                verdict("cleanup", "INVALID", "owned container removal failed")
            (out / "summary.json").write_text(
                json.dumps({"image": IMAGE, "results": results}, indent=2) + "\n"
            )
    return (
        2
        if any(row["status"] == "INVALID" for row in results)
        else int(any(row["status"] == "FAIL" for row in results))
    )


if __name__ == "__main__":

    def interrupted(_signal, _frame):
        raise InterruptedError("qualification interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main())
