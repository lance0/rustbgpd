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
def value(cell="rustbgpd"):
    generator = {"rustbgpd":"bench/scale/reloadstall/gen-scenario.py", "bird":"bench/scale/reloadstall/gen-bird-scenario.py", "openbgpd":"bench/scale/reloadstall/gen-obgpd-scenario.py"}[cell]
    workload = {"binary":"target/release/rustbgpd", "sha256":h} if cell == "rustbgpd" else {"image_ref":{"bird":"bird:3.3.1","openbgpd":"openbgpd/openbgpd:9.1"}[cell], "image_id":"sha256:"+h}
    return {"schema":1,"cell":cell,"git":{"commit":"b"*40,"tree":"c"*40,"dirty":False},"toolchain":"rustc","host":"host","sources":{"common":common,"generator":{generator:h},"reloadstall":{"path":"bench/scale/target/release/reloadstall","sha256":h}},"workload":workload}
verify = root / "bench/scale/matrix/verify-provenance.py"
def accepted(name, data, want, expected=None):
    path=tmp/(name+".json"); path.write_text(json.dumps(data))
    got=subprocess.run([sys.executable, str(verify), str(path), expected or data.get("cell", "rustbgpd")], capture_output=True).returncode == 0
    assert got == want, (name, got)
accepted("valid", value(), True)
v=value(); del v["schema"]; accepted("missing-schema",v,False)
v=value(); v["schema"]=0; accepted("wrong-schema",v,False)
v=value(); v["sources"]["common"].pop("bench/scale/provenance.sh"); accepted("roster",v,False)
v=value(); v["sources"]["common"]["bench/scale/matrix/verify-provenance.py"]="changed"; accepted("verifier-mutation",v,False)
v=value(); v["workload"]={"binary":"target/release/rustbgpd","sha256":h,"image_id":"sha256:"+h}; accepted("oneof",v,False)
v=value("bird"); v["workload"]["image_id"]="bird:latest"; accepted("image",v,False)
v=value("bird"); v["workload"]["image_ref"]="bird:latest"; accepted("reference",v,False)
accepted("cross-cell-copy", value("openbgpd"), False, "bird")
PY

# shellcheck disable=SC2016 # searching for literal shell source
grep -Fq 'docker run -d --name "$container" --network=host' \
  "$root/bench/scale/matrix/run-matrix.sh"
# shellcheck disable=SC2016 # searching for literal shell source
grep -Fq '"$image_id" bird -f' "$root/bench/scale/matrix/run-matrix.sh"

trace="$tmp/prepare.trace"
status="$tmp/status"
"$root/bench/scale/matrix/run-matrix.sh" --self-test-prepare-order \
  "$trace" bird "$status" >/dev/null
[[ $(cat "$trace") == $'bird:resolve\nbird:quiet' ]]
if grep -q openbgpd "$trace"; then exit 1; fi

printf 'pass\n' >"$status"
if "$root/bench/scale/matrix/run-matrix.sh" --self-test-prepare-order \
  "$trace" bird "$status" >/dev/null; then
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
write_source_identity() {
  jq -n --arg commit "$1" --arg tree "$2" --argjson dirty "$3" \
    '{git:{commit:$commit,tree:$tree,dirty:$dirty}}' >"$status.provenance"
}
run_resume_check() {
  MATRIX_SELF_TEST_REPO="$source_repo" \
    "$root/bench/scale/matrix/run-matrix.sh" --self-test-prepare-order \
      "$trace" bird "$status" >/dev/null
}

write_source_identity "$source_commit" "$source_tree" false
resume_rc=0
run_resume_check || resume_rc=$?
[[ $resume_rc == 10 ]]
[[ $(tail -n2 "$trace") == $'bird:resume-verify\nbird:live-verify' ]]

git -C "$source_repo" commit --allow-empty -qm changed-head
if run_resume_check; then exit 1; fi
git -C "$source_repo" reset -q --hard "$source_commit"

write_source_identity "$source_commit" "$(printf 'f%.0s' {1..40})" false
if run_resume_check; then exit 1; fi

write_source_identity "$source_commit" "$source_tree" false
printf 'dirty\n' >>"$source_repo/input"
if run_resume_check; then exit 1; fi
git -C "$source_repo" restore input

resume_rc=0
run_resume_check || resume_rc=$?
[[ $resume_rc == 10 ]]
echo "scale provenance tests pass"
