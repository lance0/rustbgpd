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
verify = root / "bench/scale/matrix/verify-provenance.py"
def accepted(name, data, want, expected=None, generation=None):
    path=tmp/(name+".json"); path.write_text(json.dumps(data))
    command=[sys.executable, str(verify), str(path), expected or data.get("cell", "rustbgpd")]
    if generation is not None:
        command.append(generation)
    got=subprocess.run(command, capture_output=True).returncode == 0
    assert got == want, (name, got)
accepted("valid", value(), True)
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
    --arg image_ref "$4" --arg image_id "$5" \
    '{git:{commit:$commit,tree:$tree,dirty:$dirty},workload:{image_ref:$image_ref,image_id:$image_id}}' \
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

write_source_identity "$source_commit" "$source_tree" false bird:3.3.1 "$fixture_image_id"
resume_rc=0
run_resume_check || resume_rc=$?
[[ $resume_rc == 10 ]]
[[ $(tail -n2 "$trace") == $'bird:resume-verify\nbird:live-verify' ]]

resume_generation=current
if run_resume_check; then exit 1; fi
resume_generation=historical

write_source_identity "$source_commit" "$source_tree" false openbgpd/openbgpd:9.1 "$fixture_image_id"
if run_resume_check; then exit 1; fi

write_source_identity "$source_commit" "$source_tree" false bird:3.3.1 "$fixture_image_id"
resume_image_id=$changed_image_id
if run_resume_check; then exit 1; fi
resume_image_id=$fixture_image_id

resume_generation=current
write_source_identity "$source_commit" "$source_tree" false bird:v3.3.2-m101 "$fixture_image_id"
resume_rc=0
run_resume_check || resume_rc=$?
[[ $resume_rc == 10 ]]
resume_generation=historical
write_source_identity "$source_commit" "$source_tree" false bird:3.3.1 "$fixture_image_id"

git -C "$source_repo" commit --allow-empty -qm changed-head
if run_resume_check; then exit 1; fi
git -C "$source_repo" reset -q --hard "$source_commit"

write_source_identity "$source_commit" "$(printf 'f%.0s' {1..40})" false bird:3.3.1 "$fixture_image_id"
if run_resume_check; then exit 1; fi

write_source_identity "$source_commit" "$source_tree" false bird:3.3.1 "$fixture_image_id"
printf 'dirty\n' >>"$source_repo/input"
if run_resume_check; then exit 1; fi
git -C "$source_repo" restore input

resume_rc=0
run_resume_check || resume_rc=$?
[[ $resume_rc == 10 ]]
echo "scale provenance tests pass"
