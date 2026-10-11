#!/usr/bin/env bash
# M69 smoke — RFC 9785 Highest-Preference DF election across rustbgpd
# and FRR.
#
# rustbgpd advertises preference 100, FRR advertises preference 200 via
# `evpn mh es-df-pref 200`. Default service carving would elect
# rustbgpd for VNI 200, so asserting rustbgpd NonDF + FRR DF proves the
# preference-DF signal is understood cross-vendor.

set -euo pipefail

TOPO="m69-evpn-preference-df-frr"
RUSTBGPD="clab-${TOPO}-pe1"
PE1="$RUSTBGPD"
PE2="clab-${TOPO}-pe2"
PE1_IP="10.0.0.1"
PE2_IP="10.0.0.2"
ESI="03:aa:bb:cc:dd:ee:ff:00:00:01"
VNI="200"
# ExtendedCommunity::df_election(HighestPreference=2, capabilities=0,
# preference=200), rendered as protobuf JSON's uint64 string.
FRR_DF_EXTCOMM="434036613111087304"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

wait_grpc_ready() {
    log "Waiting for rustbgpd gRPC..."
    for i in $(seq 1 30); do
        if grpc_health >/dev/null 2>&1; then
            ok "rustbgpd gRPC endpoint ready (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "rustbgpd gRPC endpoint not reachable within 60s"
    return 1
}

grpc_list_type4() {
    grpcurl_call \
        -d '{"route_type_filter": 4}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null
}

type4_route_count() {
    grpc_list_type4 \
        | jq '[.routes[]? | select(.routeType == 4)] | length'
}

wait_for_type4_count() {
    local want=${1:?} timeout=${2:-60}
    for _ in $(seq 1 "$timeout"); do
        local got
        got=$(type4_route_count 2>/dev/null || echo 0)
        if [ "$got" -ge "$want" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

rust_decoded_frr_preference_df() {
    grpc_list_type4 \
        | jq -e --arg peer "$PE2_IP" --arg esi "$ESI" --arg ec "$FRR_DF_EXTCOMM" '
            any(.routes[]?;
                .routeType == 4
                and .peerAddress == $peer
                and .esi == $esi
                and ((.extendedCommunities // []) | map(tostring) | index($ec) != null)
            )' >/dev/null
}

wait_rust_decoded_frr_preference_df() {
    for _ in $(seq 1 60); do
        rust_decoded_frr_preference_df && return 0
        sleep 1
    done
    return 1
}

prom_scrape() {
    local container=${1:?}
    local ip
    ip=$(resolve_ip "$container")
    [ -z "$ip" ] && {
        echo "ERROR: could not resolve management IP for $container" >&2
        return 1
    }
    curl -sfm 5 "http://${ip}:9179/metrics" 2>/dev/null \
        || wget -qO- -T 5 "http://${ip}:9179/metrics" 2>/dev/null \
        || true
}

prom_df_role() {
    local container=${1:?} role=${2:?}
    prom_scrape "$container" \
        | awk -v esi="$ESI" -v vni="$VNI" -v role="$role" '
            $0 ~ /^evpn_df_role\{/ \
                && index($0, "esi=\"" esi "\"") \
                && index($0, "vni=\"" vni "\"") \
                && index($0, "role=\"" role "\"") { print $NF; exit }'
}

wait_for_role() {
    local container=${1:?} role=${2:?} want=${3:?} timeout=${4:-60}
    for _ in $(seq 1 "$timeout"); do
        [ "$(prom_df_role "$container" "$role")" = "$want" ] && return 0
        sleep 1
    done
    return 1
}

frr_sees_both_type4() {
    local out
    out=$(docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type es" 2>/dev/null || true)
    echo "$out" | grep -q "$PE1_IP" && echo "$out" | grep -q "$PE2_IP"
}

wait_frr_sees_both_type4() {
    for _ in $(seq 1 60); do
        frr_sees_both_type4 && return 0
        sleep 1
    done
    return 1
}

frr_reports_preference_df_win() {
    local out
    out=$(docker exec "$PE2" vtysh -c "show evpn es detail" 2>/dev/null || true)
    echo "$out" | grep -qiE 'DF status:[[:space:]]*df' \
        && echo "$out" | grep -qiE 'DF preference:[[:space:]]*200' \
        && echo "$out" | grep -qiE 'df_alg:[[:space:]]*preference' \
        && echo "$out" | grep -qiE 'df_pref:[[:space:]]*100'
}

wait_frr_reports_preference_df_win() {
    for _ in $(seq 1 60); do
        frr_reports_preference_df_win && return 0
        sleep 1
    done
    return 1
}

dump_debug() {
    echo "--- rustbgpd Type 4 routes ---" >&2
    grpc_list_type4 >&2 || true
    echo "--- rustbgpd evpn_df_role metrics ---" >&2
    prom_scrape "$PE1" | grep '^evpn_df_role' >&2 || true
    echo "--- FRR Type 4 routes ---" >&2
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type es" >&2 || true
    echo "--- FRR ES detail ---" >&2
    docker exec "$PE2" vtysh -c "show evpn es detail" >&2 || true
}

restart_without_transient_df() {
    local evidence=${M69_ARTIFACT_DIR:-/tmp/m69-df-wait-$(date -u +%Y%m%dT%H%M%SZ)}
    mkdir -p "$evidence"
    log "Restart evidence: $evidence"
    python3 - "$PE1" "$PE2" "$(resolve_ip "$PE1")" "$evidence" "$ESI" <<'PY'
from datetime import datetime
import json
import pathlib
import re
import subprocess
import sys
import time
import urllib.request

pe1, pe2, management_ip, output, esi = sys.argv[1:]
output = pathlib.Path(output)
samples = []
failures = []
commands = []
release = None
window_end = None

def run(args, timeout=10):
    command = {"time": time.time(), "args": args, "timeout": timeout, "returncode": None}
    commands.append(command)
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    command.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    if result.returncode:
        raise RuntimeError(f"command failed: {args}: {result.stderr}")
    return result.stdout

def wait_daemon_exit(old_stat):
    pid = old_stat.split(" ", 1)[0]
    old_start = old_stat.rsplit(")", 1)[1].split()[19]
    deadline = time.monotonic() + 10
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f"old rustbgpd process {pid} did not exit within 10s")
        current = run(["docker", "exec", pe1, "sh", "-c",
                       'cat "/proc/$1/stat" || test ! -d "/proc/$1"', "sh", pid],
                      timeout=remaining)
        if not current:
            return
        fields = current.rsplit(")", 1)[1].split()
        # An unreaped zombie has exited; a reused PID is a different lifetime.
        if fields[0] in ("Z", "X") or fields[19] != old_start:
            return
        time.sleep(0.1)

def frr_command(shutdown):
    return ["docker", "exec", pe2, "vtysh", "-c", "configure terminal",
            "-c", "router bgp 65000", "-c",
            ("neighbor" if shutdown else "no neighbor") + " 10.0.0.1 shutdown"]

def flood_suppressed(text):
    return "es0" in text and all(
        re.search(r"(?:^|\s)" + flag + r"\s+off(?:\s|$)", text)
        for flag in ("flood", "mcast_flood", "bcast_flood"))

def check_samples(samples, first_role, release_at, window_end):
    errors = []
    if first_role is None:
        return ["new daemon never exposed its DF role"]
    observed = samples[first_role:]
    held = [sample for sample in observed if sample["elapsed"] < release_at]
    if len(held) < 16 or held[-1]["elapsed"] - held[0]["elapsed"] < 4:
        errors.append("fewer than four seconds / 16 valid-role observations during the peer hold")
    for sample in observed:
        if sample["errors"] or sample.get("df") != 0 or not flood_suppressed(sample.get("bridge", "")):
            errors.append(f"bad observation at {sample['elapsed']:.3f}s: {sample}")
        if sample["duration"] > 0.25:
            errors.append(f"sample exceeded 250 ms at {sample['elapsed']:.3f}s")
    for before, after in zip(observed, observed[1:]):
        if after["elapsed"] - before["elapsed"] > 0.25:
            errors.append(f"sampling gap over 250 ms after {before['elapsed']:.3f}s")
    if window_end < 12:
        errors.append("sampling window ended before 12 seconds")
    if not observed or window_end - observed[-1]["elapsed"] > 0.25:
        errors.append("final sample does not cover the window end within 250 ms")
    if not any(sample["elapsed"] > release_at for sample in observed):
        errors.append("no post-release observation")
    return errors

def parse_daemon_log(text):
    # print_startup_banner writes this complete M69 topology block to stderr,
    # which the restart wrapper collects alongside JSON tracing output.
    lines = text.splitlines()
    entries = []
    version = None
    index = 0
    while index < len(lines):
        banner = [
            "", f"  rustbgpd {version} | AS 65000 | router-id 10.0.0.1",
            "  |- 1 peers (1 iBGP)",
            "  |- grpc: tcp://0.0.0.0:50051 (token auth)",
            "  |- grpc: unix:///var/lib/rustbgpd/grpc.sock",
            "  |- metrics: http://0.0.0.0:9179/metrics", "",
        ]
        if version is not None and lines[index:index + len(banner)] == banner:
            index += len(banner)
            version = None
            continue
        entry = json.loads(lines[index])
        entries.append(entry)
        fields = entry.get("fields", {})
        if entry.get("target") == "rustbgpd" and fields.get("message") == "starting rustbgpd":
            version = fields["version"]
        index += 1
    return entries


def check_reconvergence(entries, started_wall, release_at, samples, esi):
    # Initial prepared NonDF metrics are insufficient. In this one-peer
    # Highest-Preference topology, a completed NonDF election requires the
    # returning remote Type 4: a local-only (or fallback modulo) election is DF.
    events = {"established": [], "evpn_eor": [], "nondf_election": []}
    errors = []
    for entry in entries:
        fields = entry.get("fields", {})
        target = entry.get("target")
        if (target == "rustbgpd_transport::session::fsm"
                and fields.get("message") == "session established"
                and fields.get("peer") == "10.0.0.2"):
            event = "established"
        elif (target == "rustbgpd_transport::session::inbound"
              and fields.get("message") == "received End-of-RIB"
              and fields.get("peer") == "10.0.0.2"
              and fields.get("afi") == "L2Vpn" and fields.get("safi") == "Evpn"):
            event = "evpn_eor"
        elif (target == "rustbgpd::evpn_segment"
              and fields.get("message") == "EVPN segment: DF role updated"
              and fields.get("esi") == esi and fields.get("vni") == 200
              and fields.get("role") == "nondf"):
            event = "nondf_election"
        else:
            continue
        try:
            timestamp = datetime.fromisoformat(entry["timestamp"])
            if timestamp.tzinfo is None or timestamp.utcoffset().total_seconds() != 0:
                raise ValueError("timestamp must be UTC aware")
            events[event].append(timestamp.timestamp() - started_wall)
        except (KeyError, TypeError, ValueError) as error:
            errors.append(f"invalid {event} UTC timestamp: {error}")
    recovery = {}
    after = release_at
    for event, times in events.items():
        # Require a later retained kernel/metric sample, not just a log read
        # after the sampler stopped. Missing or slow recovery fails the proof.
        observed = [elapsed for elapsed in times
                    if samples and after <= elapsed < samples[-1]["elapsed"]]
        if not observed:
            errors.append(f"no ordered {event} after peer release and before the final sample")
            break
        after = recovery[event] = min(observed)
    if not errors:
        recovery["post_settlement_sample"] = next(
            sample["elapsed"] for sample in samples if sample["elapsed"] > after)
    return errors, recovery

def reap_release(process):
    if process is None:
        return
    try:
        process.communicate(timeout=10)
    finally:
        try:
            if process.poll() is None:
                process.kill()
        finally:
            process.wait()

try:
    baseline = run(["docker", "exec", pe1, "bridge", "-d", "link", "show", "dev", "es0"])
    (output / "baseline-ac.txt").write_text(baseline)
    if not flood_suppressed(baseline):
        raise RuntimeError("baseline AC must already suppress all three BUM classes")
    # Kill the daemon before shutting down its peer: otherwise the old
    # lifetime could legitimately elect itself when the peer disappears.
    old_stat = run(["docker", "exec", pe1, "sh", "-c",
                    'pid=$(cat /run/rustbgpd/m69.pid); cat "/proc/$pid/stat" && kill -KILL "$pid"'])
    wait_daemon_exit(old_stat)
    reply = run(frr_command(True))
    if "%" in reply:
        raise RuntimeError("FRR rejected the administrative neighbor hold")
    peer = json.loads(run(["docker", "exec", pe2, "vtysh", "-c", "show bgp neighbors 10.0.0.1 json"]))
    if peer["10.0.0.1"]["bgpState"] == "Established":
        raise RuntimeError("FRR neighbor hold did not take effect")
    (output / "held-peer.json").write_text(json.dumps(peer, indent=2) + "\n")
    # The restart entrypoint only starts the process; it does not reset the
    # preserved kernel flags. The pre-daemon interval is excluded below.
    started = time.monotonic()
    started_wall = time.time()
    run(["docker", "exec", pe1, "/usr/local/bin/start-rustbgpd-m69-vtep.sh", "restart"])
    first_role = None
    while time.monotonic() - started < 12:
        now = time.monotonic()
        if release is None and now - started >= 6:
            # Popen keeps the sampler running while vtysh releases the hold.
            release = subprocess.Popen(frr_command(False), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            release_at = now - started
        sample = {"time": time.time(), "elapsed": now - started, "errors": []}
        try:
            with urllib.request.urlopen(f"http://{management_ip}:9179/metrics", timeout=0.1) as response:
                metrics = response.read().decode()
            rows = [line for line in metrics.splitlines() if line.startswith("evpn_df_role{")]
            sample["metrics"] = rows
            values = [float(line.rsplit(" ", 1)[1]) for line in rows
                      if f'esi="{esi}"' in line and 'vni="200"' in line and 'role="df"' in line]
            if len(values) != 1:
                raise ValueError(f"expected one DF gauge, found {values}")
            sample["df"] = values[0]
            if first_role is None:
                first_role = len(samples)
        except Exception as error:
            sample["errors"].append(f"metrics: {error}")
        try:
            result = subprocess.run(["docker", "exec", pe1, "bridge", "-d", "link", "show", "dev", "es0"],
                                    text=True, capture_output=True, timeout=0.15)
            sample["bridge"] = result.stdout
            if result.returncode:
                raise RuntimeError(result.stderr)
            sample["flood_suppressed"] = flood_suppressed(result.stdout)
        except Exception as error:
            sample["errors"].append(f"bridge: {error}")
        sample["duration"] = time.monotonic() - now
        samples.append(sample)
        time.sleep(max(0, 0.1 - sample["duration"]))
    window_end = time.monotonic() - started
    if release is None:
        raise RuntimeError("peer hold was never released")
    stdout, stderr = release.communicate(timeout=10)
    commands.append({"time": time.time(), "args": frr_command(False),
                     "returncode": release.returncode, "stdout": stdout, "stderr": stderr})
    if release.returncode or "%" in stdout:
        failures.append(f"FRR hold release failed: {stdout} {stderr}")
    failures.extend(check_samples(samples, first_role, release_at, window_end))
    daemon_log = run(["docker", "exec", pe1, "cat", "/var/log/rustbgpd.log"])
    (output / "restart-daemon.jsonl").write_text(daemon_log)
    entries = parse_daemon_log(daemon_log)
    recovery_errors, recovery = check_reconvergence(
        entries, started_wall, release_at, samples[first_role:] if first_role is not None else [], esi)
    failures.extend(recovery_errors)
    first_publication = None
    for entry in entries:
        fields = entry.get("fields", {})
        if fields.get("message") == "EVPN segment: published BUM enforcement intent" and first_publication is None:
            first_publication = entry.get("timestamp")
        if fields.get("message") == "EVPN segment: DF role updated" and fields.get("role") == "df":
            failures.append("daemon recorded a DF transition during the restart window")
    if first_publication is None:
        failures.append("first actor enforcement publication was not recorded")
    (output / "window.json").write_text(json.dumps({
        "restart_started": started_wall, "first_role_sample": first_role,
        "first_actor_publication": first_publication,
        "peer_release_elapsed": release_at,
        "reconvergence_elapsed": recovery,
        "declared_window_end_elapsed": 12,
        "observed_window_end_elapsed": window_end,
        "scope": "Restart with preserved suppressed AC; samples before the first new daemon role are recorded but excluded. Kernel observations are sampled, not continuous.",
    }, indent=2) + "\n")
except Exception as error:
    failures.append(str(error))
finally:
    try:
        reap_release(release)
    except Exception as error:
        failures.append(f"release process cleanup: {error}")
    # Never leave the owned peer administratively down on a failed proof.
    try:
        run(frr_command(False))
    except Exception as error:
        failures.append(f"cleanup: {error}")
    (output / "samples.jsonl").write_text("".join(json.dumps(sample) + "\n" for sample in samples))
    (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    (output / "result.json").write_text(json.dumps({
        "passed": not failures, "failures": failures,
        "declared_window_end_elapsed": 12, "observed_window_end_elapsed": window_end,
    }, indent=2) + "\n")
for failure in failures:
    print(failure, file=sys.stderr)
raise SystemExit(bool(failures))
PY
}

resolve_grpc_addr
wait_grpc_ready

log "[baseline] FRR session Established"
wait_frr_established "$PE2" "$PE1_IP" "FRR EVPN" \
    || fail "FRR did not establish to rustbgpd"

log "[test] Both peers exchange Type 4 ES routes"
if wait_for_type4_count 2 90; then
    ok "rustbgpd Loc-RIB has both Type 4 ES candidates"
else
    fail "rustbgpd Loc-RIB did not receive both Type 4 ES candidates"
    dump_debug
fi
if wait_frr_sees_both_type4; then
    ok "FRR sees both Type 4 ES candidates"
else
    fail "FRR did not see both Type 4 ES candidates"
    dump_debug
fi

log "[test] FRR Type 4 carries RFC 9785 preference-DF signal"
if wait_rust_decoded_frr_preference_df; then
    ok "rustbgpd decoded FRR DF Election extcomm as Highest-Preference / preference 200"
else
    fail "rustbgpd did not expose FRR's expected DF Election extcomm"
    dump_debug
fi

log "[test] preference-DF elects FRR, not the modulo winner"
if wait_for_role "$PE1" nondf 1 90; then
    ok "rustbgpd reports NonDF=1 for (esi=$ESI, vni=$VNI)"
else
    fail "rustbgpd did not settle as NonDF"
    dump_debug
fi
if [ "$(prom_df_role "$PE1" df)" = "0" ]; then
    ok "rustbgpd reports DF=0 for the same key"
else
    fail "rustbgpd DF gauge is not 0"
    dump_debug
fi
if wait_frr_reports_preference_df_win; then
    ok "FRR reports local DF with preference 200 and remote preference 100"
else
    fail "FRR did not report the expected preference-DF winner state"
    dump_debug
fi

log "[test] restart holds NonDF and suppresses BUM before FRR Type 4 can return"
if restart_without_transient_df; then
    ok "restart showed no DF role or BUM opening; samples stayed at least 4 Hz"
else
    fail "restart DF wait proof failed (raw observations retained)"
    dump_debug
fi
wait_frr_established "$PE2" "$PE1_IP" "FRR EVPN after restart" \
    || fail "FRR did not re-establish after the controlled hold"
if wait_rust_decoded_frr_preference_df && wait_for_role "$PE1" nondf 1 30 \
    && wait_frr_reports_preference_df_win; then
    ok "FRR preference 200 remains the DF after restart"
else
    fail "the remote preference-DF winner did not recover after restart"
    dump_debug
fi

print_summary
