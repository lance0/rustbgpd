#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
# shellcheck disable=SC1091
source "$root/bench/scale/provenance.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf 'a\n' >"$tmp/a"
printf 'b\n' >"$tmp/b"
a=$(provenance_sha256_file "$tmp/a")
[[ $a =~ ^[0-9a-f]{64}$ ]]
provenance_require_sha256 "$tmp/a" "$a"
if provenance_require_sha256 "$tmp/b" "$a"; then exit 1; fi
printf 'changed\n' >"$tmp/a"
if provenance_require_sha256 "$tmp/a" "$a"; then exit 1; fi
if provenance_require_sha256 "$tmp/a" ABC; then exit 1; fi
ln -s a "$tmp/link"
if provenance_sha256_file "$tmp/link"; then exit 1; fi

python3 - "$root" "$tmp" <<'PY'
import json, pathlib, subprocess, sys
root, tmp = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
h = "a" * 64
common = {p: h for p in ("bench/scale/provenance.sh", "bench/scale/matrix/run-matrix.sh", "bench/scale/matrix/verify-provenance.py", "bench/scale/matrix/rss-sampler.sh", "bench/scale/host-quiet.sh", "tests/soak/host-lock.sh")}
refs = {
    "historical": {"bird":"bird:3.3.1", "openbgpd":"openbgpd/openbgpd:9.1"},
    "current": {
        "bird":"bird:v3.3.2-m101",
        "openbgpd":"openbgpd/openbgpd@sha256:b2e94bd1538102a89cff96867993eabb6dbb27720de4ab7b588860880e3e3bf9",
    },
}
def value(cell="rustbgpd", generation="historical"):
    generator = {"rustbgpd":"bench/scale/reloadstall/gen-scenario.py", "bird":"bench/scale/reloadstall/gen-bird-scenario.py", "openbgpd":"bench/scale/reloadstall/gen-obgpd-scenario.py"}[cell]
    workload = {"binary":"target/release/rustbgpd", "sha256":h} if cell == "rustbgpd" else {"image_ref":refs[generation][cell], "image_id":"sha256:"+h}
    return {"schema":1,"cell":cell,"git":{"commit":"b"*40,"tree":"c"*40,"dirty":False},"toolchain":"rustc","host":"host","sources":{"common":common,"generator":{generator:h},"reloadstall":{"path":"bench/scale/target/release/reloadstall","sha256":h}},"workload":workload}
inputs = {
    "N_PEERS":"700", "TOTAL_PREFIXES":"400400", "PORT":"1790", "RELOADS":"4",
    "CONTROL_SECS":"30", "CHANGED_PEERS":"", "FLAPSTORM":"", "BIRD_THREADS":"8",
    "PROBE_PREFIXES":"",
}
(tmp / "inputs.json").write_text(json.dumps(inputs))
verify = root / "bench/scale/matrix/verify-provenance.py"
def accepted(name, data, want, expected=None, generation=None):
    path=tmp/(name+".json"); path.write_text(json.dumps(data))
    command=[sys.executable, str(verify), str(path), expected or data.get("cell", "rustbgpd")]
    if generation is not None:
        command.append(generation)
    got=subprocess.run(command, capture_output=True).returncode == 0
    assert got == want, (name, got)
accepted("valid", value(), True)
v=value(); v["workload"]=list(v["workload"].items()); accepted("malformed-workload-object",v,False)
v=value(); v["workload"]["inputs"]=inputs.copy(); accepted("with-inputs",v,True)
v=value(); v["workload"]["inputs"]={}; accepted("missing-input-fields",v,False)
v=value(); v["workload"]["inputs"]={**inputs,"GEN_DUALSTACK":"1","RELOADSTALL_IPV4_PREFIXES":"360360"}; accepted("asymmetric-inputs",v,True)
v=value(); v["workload"]["inputs"]={**inputs,"RELOADSTALL_IPV4_PREFIXES":360360}; accepted("malformed-input-value",v,False)
v=value(); v["workload"]["inputs"]={**inputs,"UNTRACKED":"value"}; accepted("unknown-input-key",v,False)

accepted("historical-bird-default", value("bird"), True)
accepted("historical-open-explicit", value("openbgpd"), True, generation="historical")
accepted("current-bird", value("bird", "current"), True, generation="current")
accepted("current-open", value("openbgpd", "current"), True, generation="current")
accepted("current-needs-selection", value("bird", "current"), False)
accepted("historical-rejected-as-current", value("bird"), False, generation="current")
v=value("bird", "current"); v["workload"]["image_ref"]=refs["current"]["openbgpd"]; accepted("mixed-current-tuple",v,False,generation="current")
accepted("unknown-generation", value("bird"), False, generation="arbitrary")
v=value(); del v["schema"]; accepted("missing-schema",v,False)
v=value(); v["schema"]=0; accepted("wrong-schema",v,False)
v=value(); v["sources"]["common"].pop("bench/scale/provenance.sh"); accepted("roster",v,False)
v=value(); v["sources"]["common"]["bench/scale/matrix/verify-provenance.py"]="changed"; accepted("verifier-mutation",v,False)
v=value(); v["workload"]={"binary":"target/release/rustbgpd","sha256":h,"image_id":"sha256:"+h}; accepted("oneof",v,False)
v=value("bird"); v["workload"]["image_id"]="bird:latest"; accepted("image",v,False)
v=value("bird"); v["workload"]["image_ref"]="bird:latest"; accepted("reference",v,False)
accepted("cross-cell-copy", value("openbgpd"), False, "bird")
PY

python3 - "$root" "$tmp" <<'PY'
import pathlib, subprocess, sys

root, tmp = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
bird = root / "bench/scale/reloadstall/gen-bird-scenario.py"
openbgpd = root / "bench/scale/reloadstall/gen-obgpd-scenario.py"

def generate(script, out, generation=None):
    if script == bird:
        command = [sys.executable, str(script), "2", str(out), "1790", "8", "/etc/bird"]
    else:
        command = [sys.executable, str(script), "2", str(out), "1790", "/etc/bgpd"]
    if generation is not None:
        command.append(generation)
    subprocess.check_call(command, stdout=subprocess.DEVNULL)

def prove_version_only(script, main_config, historical_headers, current_headers):
    name = script.stem
    default = tmp / f"{name}-default"
    historical = tmp / f"{name}-historical"
    current = tmp / f"{name}-current"
    generate(script, default)
    generate(script, historical, "historical")
    generate(script, current, "current")
    files = {"gen-a.conf", "gen-b.conf", "gen.conf", main_config}
    assert {path.name for path in default.iterdir()} == files
    assert {path.name for path in historical.iterdir()} == files
    assert {path.name for path in current.iterdir()} == files
    for filename in files:
        assert (default / filename).read_bytes() == (historical / filename).read_bytes()
    for filename in files - {main_config}:
        assert (historical / filename).read_bytes() == (current / filename).read_bytes()
    historical_lines = (historical / main_config).read_text().splitlines(keepends=True)
    current_lines = (current / main_config).read_text().splitlines(keepends=True)
    assert historical_lines[:2] == [line + "\n" for line in historical_headers]
    assert current_lines[:2] == [line + "\n" for line in current_headers]
    assert historical_lines[2:] == current_lines[2:]
    bad = subprocess.run(
        [sys.executable, str(script), "2", str(tmp / f"{name}-bad"), "1790"]
        + (["8", "/etc/bird", "arbitrary"] if script == bird else ["/etc/bgpd", "arbitrary"]),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert bad.returncode != 0

prove_version_only(
    bird,
    "bird.conf",
    (
        "# IXP-matrix BIRD 3.3.1 route server - generated by gen-bird-scenario.py.",
        "# Run: docker run -d --network=host -v <out_dir>:/etc/bird bird:3.3.1 \\",
    ),
    (
        "# IXP-matrix BIRD 3.3.2 route server - generated by gen-bird-scenario.py.",
        "# Run: docker run -d --network=host -v <out_dir>:/etc/bird bird:v3.3.2-m101 \\",
    ),
)
prove_version_only(
    openbgpd,
    "bgpd.conf",
    (
        "# IXP-matrix OpenBGPD 9.1 route server - generated by gen-obgpd-scenario.py.",
        "# Run: docker run -d --network=host -v <out_dir>:/etc/bgpd openbgpd/openbgpd:9.1",
    ),
    (
        "# IXP-matrix OpenBGPD 9.2 route server - generated by gen-obgpd-scenario.py.",
        "# Run: docker run -d --network=host -v <out_dir>:/etc/bgpd openbgpd/openbgpd@sha256:b2e94bd1538102a89cff96867993eabb6dbb27720de4ab7b588860880e3e3bf9",
    ),
)
PY

# shellcheck disable=SC2016 # searching for literal shell source
grep -Fq 'docker run -d --name "$container" --network=host' \
  "$root/bench/scale/matrix/run-matrix.sh"
# shellcheck disable=SC2016 # searching for literal shell source
grep -Fq '"$image_id" bird -f' "$root/bench/scale/matrix/run-matrix.sh"

trace="$tmp/prepare.trace"
image_trace="$tmp/prepare-images.trace"
status="$tmp/status"
: >"$image_trace"
MATRIX_SELF_TEST_IMAGE_TRACE="$image_trace" \
  "$root/bench/scale/matrix/run-matrix.sh" --self-test-prepare-order \
  "$trace" bird "$status" >/dev/null
[[ $(cat "$trace") == $'bird:resolve\nbird:quiet' ]]
[[ $(cat "$image_trace") == bird:3.3.1 ]]
if grep -q openbgpd "$trace"; then exit 1; fi

: >"$trace"
: >"$image_trace"
COMPETITOR_GENERATION=current MATRIX_SELF_TEST_IMAGE_TRACE="$image_trace" \
  "$root/bench/scale/matrix/run-matrix.sh" --self-test-prepare-order \
    "$trace" bird "$status" >/dev/null
[[ $(cat "$trace") == $'bird:resolve\nbird:quiet' ]]
[[ $(cat "$image_trace") == bird:v3.3.2-m101 ]]

: >"$trace"
: >"$image_trace"
COMPETITOR_GENERATION=current MATRIX_SELF_TEST_IMAGE_TRACE="$image_trace" \
  "$root/bench/scale/matrix/run-matrix.sh" --self-test-prepare-order \
    "$trace" openbgpd "$status" >/dev/null
[[ $(cat "$trace") == $'openbgpd:resolve\nopenbgpd:quiet' ]]
[[ $(cat "$image_trace") == \
  openbgpd/openbgpd@sha256:b2e94bd1538102a89cff96867993eabb6dbb27720de4ab7b588860880e3e3bf9 ]]

if COMPETITOR_GENERATION=arbitrary \
  "$root/bench/scale/matrix/run-matrix.sh" --self-test-prepare-order \
    "$trace" bird "$status" >/dev/null 2>&1; then
  exit 1
fi

printf 'pass\n' >"$status"
if "$root/bench/scale/matrix/run-matrix.sh" --self-test-prepare-order \
  "$trace" bird "$status" >/dev/null 2>&1; then
  exit 1
fi

source_repo="$tmp/source-repo"
git init -q "$source_repo"
git -C "$source_repo" config user.email scale-provenance@test.invalid
git -C "$source_repo" config user.name scale-provenance-test
printf 'source\n' >"$source_repo/input"
git -C "$source_repo" add input
git -C "$source_repo" commit -qm initial
source_commit=$(git -C "$source_repo" rev-parse 'HEAD^{commit}')
source_tree=$(git -C "$source_repo" rev-parse 'HEAD^{tree}')
fixture_image_id="sha256:$(printf '%064d' 0)"
changed_image_id="sha256:$(printf '%064d' 1)"
write_source_identity() {
  jq -n --arg commit "$1" --arg tree "$2" --argjson dirty "$3" \
    --arg image_ref "$4" --arg image_id "$5" --slurpfile inputs "$tmp/inputs.json" \
    '{git:{commit:$commit,tree:$tree,dirty:$dirty},workload:{image_ref:$image_ref,image_id:$image_id,inputs:$inputs[0]}}' \
    >"$status.provenance"
}
resume_generation=historical
resume_image_id=$fixture_image_id
run_resume_check() {
  COMPETITOR_GENERATION="$resume_generation" \
    MATRIX_SELF_TEST_IMAGE_ID="$resume_image_id" \
    MATRIX_SELF_TEST_REPO="$source_repo" \
    "$root/bench/scale/matrix/run-matrix.sh" --self-test-prepare-order \
      "$trace" bird "$status" >/dev/null
}

reject_resume() {
  local rejected_rc=0
  run_resume_check || rejected_rc=$?
  [[ $rejected_rc == 1 ]]
}

write_source_identity "$source_commit" "$source_tree" false bird:3.3.1 "$fixture_image_id"
resume_rc=0
run_resume_check || resume_rc=$?
[[ $resume_rc == 10 ]]
[[ $(tail -n2 "$trace") == $'bird:resume-verify\nbird:live-verify' ]]

resume_generation=current
reject_resume
resume_generation=historical

write_source_identity "$source_commit" "$source_tree" false openbgpd/openbgpd:9.1 "$fixture_image_id"
reject_resume

write_source_identity "$source_commit" "$source_tree" false bird:3.3.1 "$fixture_image_id"
resume_image_id=$changed_image_id
reject_resume
resume_image_id=$fixture_image_id

resume_generation=current
write_source_identity "$source_commit" "$source_tree" false bird:v3.3.2-m101 "$fixture_image_id"
resume_rc=0
run_resume_check || resume_rc=$?
[[ $resume_rc == 10 ]]
resume_generation=historical
write_source_identity "$source_commit" "$source_tree" false bird:3.3.1 "$fixture_image_id"

git -C "$source_repo" commit --allow-empty -qm changed-head
reject_resume
git -C "$source_repo" reset -q --hard "$source_commit"

write_source_identity "$source_commit" "$(printf 'f%.0s' {1..40})" false bird:3.3.1 "$fixture_image_id"
reject_resume

write_source_identity "$source_commit" "$source_tree" false bird:3.3.1 "$fixture_image_id"
printf 'dirty\n' >>"$source_repo/input"
reject_resume
git -C "$source_repo" restore input

resume_rc=0
run_resume_check || resume_rc=$?
[[ $resume_rc == 10 ]]
# Effective defaults and explicit equivalent values identify the same workload.
resume_rc=0
N_PEERS=700 TOTAL_PREFIXES=400400 run_resume_check || resume_rc=$?
[[ $resume_rc == 10 ]]
for override in N_PEERS=20 TOTAL_PREFIXES=11440 GEN_DUALSTACK=1 \
    GEN_FILTER_COUNT=32 RELOADSTALL_FILTER_COUNT=32 RELOADSTALL_IPV4_PREFIXES=360360; do
  (export "${override?}"; reject_resume)
done
cp "$status.provenance" "$tmp/with-inputs.json"
for expression in 'del(.workload.inputs)' '.workload.inputs = null' \
    '.workload.inputs.N_PEERS = 700'; do
  jq "$expression" "$tmp/with-inputs.json" >"$status.provenance"
  reject_resume
done
jq '.workload.inputs.RELOADSTALL_IPV4_PREFIXES = "200200"' \
  "$tmp/with-inputs.json" >"$status.provenance"
resume_rc=0
RELOADSTALL_IPV4_PREFIXES=200200 run_resume_check || resume_rc=$?
[[ $resume_rc == 10 ]]
RELOADSTALL_IPV4_PREFIXES=360360 reject_resume

# Exercise the real probe functions and teardown block without a daemon or
# benchmark. FIFOs hold each foreground CLI until both loop owners are stopped.
python3 - "$root" "$tmp" <<'PY'
import csv
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys

root, tmp = map(Path, sys.argv[1:])
source = (root / "bench/scale/matrix/run-matrix.sh").read_text()
probes = source.split("probe_health_loop() {", 1)[1].split("\n# run_cell ", 1)[0]
cleanup = source.split("    # Collect artifacts, then teardown.\n", 1)[1].split(
    "\n}\n\nfor cell ", 1
)[0]
library = tmp / "matrix-lifecycle.sh"
library.write_text("probe_health_loop() {" + probes + "\nfinish_cell() {\n" + cleanup + "\n}\n")
fake = tmp / "fake-rbgp"
fake.write_text('''#!/usr/bin/env python3
import os
from pathlib import Path
import signal
import sys

root = Path(os.environ["PROBE_FIXTURE"])
mode = sys.argv[1] if sys.argv[1] == "daemon" else sys.argv[3]
if mode == "daemon":
    def stop(_signal, _frame):
        for name in ("health", "rib"):
            assert (root / (name + ".done")).exists(), name + " did not finish"
            try:
                os.kill(int((root / (name + ".pid")).read_text()), 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError(name + " child survived its loop")
        (root / "daemon.stopped").write_text("stopped\\n")
        raise SystemExit(int(os.environ["DAEMON_EXIT"]))
    signal.signal(signal.SIGTERM, stop)
else:
    (root / (mode + ".pid")).write_text(str(os.getpid()))
    with (root / (mode + ".starts")).open("a") as stream:
        stream.write("started\\n")
    print(mode + " stderr started", file=sys.stderr, flush=True)
with (root / "events").open("w") as events:
    events.write("ready " + mode + "\\n")
if mode == "daemon":
    while True:
        signal.pause()
with (root / (mode + ".release")).open() as release:
    release.readline()
print(mode + " stderr finished", file=sys.stderr, flush=True)
(root / (mode + ".done")).write_text("done\\n")
raise SystemExit(7 if mode == "health" else 0)
''')
fake.chmod(0o755)
driver = tmp / "matrix-lifecycle-driver.sh"
driver.write_text('''#!/usr/bin/env bash
set -u
source "$1"
cell=rustbgpd
cdir=$PROBE_FIXTURE
run=$cdir/run
container=""
rc=0
hrc=0
recheck_cell_provenance() { return 0; }
"$RBGP" daemon >"$cdir/daemon.log" 2>&1 &
daemon_pid=$!
sleep 60 &
sampler_pid=$!
probe_health_loop fixture "$cdir/probes.csv" &
probe_pids=($!)
probe_query_loop fixture "$cdir/queries.csv" first-prefix second-prefix &
probe_pids+=($!)
printf '%s\\n' "${probe_pids[@]}" >"$cdir/loops"
kill() {
    builtin kill "$@"
    local status=$?
    printf 'signaled %s\\n' "$1" >"$cdir/events"
    return "$status"
}
wait() {
    printf 'waiting %s\\n' "$1" >"$cdir/events"
    builtin wait "$1"
}
printf 'ready driver\\n' >"$cdir/events"
read -r _ <"$cdir/cleanup"
if [ "$FAIL_PROBE_OWNER" = 1 ]; then
    (exit 23) &
    probe_pids+=($!)
fi
finish_cell
''')

for case, daemon_exit, failed_owner in [("normal", 0, 0), ("daemon-failure", 9, 0), ("owner-failure", 0, 1)]:
    fixture = tmp / case
    (fixture / "run").mkdir(parents=True)
    for name in ("events", "cleanup", "health.release", "rib.release"):
        os.mkfifo(fixture / name)
    events_fd = os.open(fixture / "events", os.O_RDWR | os.O_NONBLOCK)
    selector = selectors.DefaultSelector()
    selector.register(events_fd, selectors.EVENT_READ)
    buffered = bytearray()

    def event():
        while b"\n" not in buffered:
            assert selector.select(5), f"{case}: missing lifecycle event"
            buffered.extend(os.read(events_fd, 4096))
        line, _, rest = buffered.partition(b"\n")
        buffered[:] = rest
        return line.decode()

    environment = dict(os.environ, RBGP=str(fake), PROBE_FIXTURE=str(fixture),
                       DAEMON_EXIT=str(daemon_exit), FAIL_PROBE_OWNER=str(failed_owner))
    process = subprocess.Popen(["bash", str(driver), str(library)], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        assert {event() for _ in range(4)} == {
            "ready health", "ready rib", "ready daemon", "ready driver"
        }
        loops = (fixture / "loops").read_text().splitlines()
        with (fixture / "cleanup").open("w") as start:
            start.write("stop\n")
        signaled = []
        while True:
            next_event = event()
            if next_event.startswith("waiting "):
                assert next_event == "waiting " + loops[0]
                break
            signaled.append(next_event.removeprefix("signaled "))
        assert all(pid in signaled for pid in loops), "must signal both loops before waiting"
        assert not (fixture / "daemon.stopped").exists(), "daemon stopped during an active RPC"
        for name, filename in [("health", "probes.csv"), ("rib", "queries.csv")]:
            assert len((fixture / filename).read_text().splitlines()) == 1
            os.kill(int((fixture / (name + ".pid")).read_text()), 0)
            with (fixture / (name + ".release")).open("w") as release:
                release.write("complete\n")
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == (1 if daemon_exit or failed_owner else 0), (case, stdout, stderr)
        expected_cleanup = 1 if daemon_exit or failed_owner else 0
        assert f"harness rc=0 cleanup rc={expected_cleanup} cell rc={expected_cleanup}" in stdout.decode()
        assert (fixture / "daemon.exit").read_text() == str(daemon_exit) + "\n"
        assert (fixture / "daemon.stopped").exists(), (fixture / "daemon.log").read_text()
        for name, filename, expected_exit in [("health", "probes.csv", "7"), ("rib", "queries.csv", "0")]:
            with (fixture / filename).open() as stream:
                rows = list(csv.DictReader(stream))
            assert len(rows) == 1 and rows[0]["exit"] == expected_exit, (case, rows)
            assert float(rows[0]["latency_ms"]) >= 0
            assert (fixture / (name + ".starts")).read_text() == "started\n"
        assert rows[0]["prefix"] == "first-prefix", "query loop started another prefix after stop"
        health_stderr = (fixture / "probes.csv.stderr.log").read_text()
        assert health_stderr.count("probe_start epoch_s=") == 1
        assert "health stderr started\nhealth stderr finished\n" in health_stderr
    finally:
        # Only this fixture's session: leave no fake child behind on assertion failure.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        selector.close()
        os.close(events_fd)
PY
echo "scale provenance tests pass"
