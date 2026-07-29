#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
runner="$root/bench/scale/rrtransport/run-receipt.sh"
verifier="$root/bench/scale/rrtransport/verify_receipt.py"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fixture="$tmp/fixture"
mkdir -p "$fixture"

python3 - "$fixture" <<'PY'
import hashlib, json, pathlib, sys
d = pathlib.Path(sys.argv[1])
shape = "rr1000-v1:peers=1000;prefixes=100000;sources=4;workers=12;afi=ipv4-unicast;role=ibgp-rr"
(d/"phase.json").write_text(json.dumps({"schema":1,"shape":shape,"shape_digest":"109e38772e3bd819",
 "wire_completion":"first_exact_bitmap","sessions":1000,"established_before":1000,"established_after":1000,"prefixes":100000,"sources":4,"workers":12,"groups":1,"initial_eors":1000,
 "injection_ms":1,"staged_ms":2,"wire_ms":3,"established_rss_kib":100,
 "staged_rss_kib":110,"wire_rss_kib":120,"established_vmhwm_kib":105,
 "staged_vmhwm_kib":115,"wire_vmhwm_kib":125})+"\n")
header="peer\tstaged\tnlri\tmessages\twithdrawals\tduplicates\toutside\tdecode_failures\tcoverage\tbitmap_digest\tinitial_eor\twire_ms\n"
rows=[f"127.{2+i//254}.{1+i%254}.1\t100000\t100000\t391\t0\t0\t0\t0\t100000\t7c50a897bc4a4e51\ttrue\t3\n" for i in range(1000)]
(d/"per-peer.tsv").write_text(header+"".join(rows))
(d/"rss.tsv").write_text("checkpoint\trss_kib\nsample\t90\nsample\t125\nestablished\t100\nstaged\t110\nwire\t120\n")
(d/"rss.json").write_text('{"established_kib":100,"staged_kib":110,"wire_kib":120,"established_vmhwm_kib":105,"staged_vmhwm_kib":115,"wire_vmhwm_kib":125,"sampler_max_kib":125}\n')
(d/"source.snapshot").write_bytes(b"source")
(d/"rrtransport.bin").write_bytes(b"binary")
h=lambda p: hashlib.sha256((d/p).read_bytes()).hexdigest()
(d/"provenance.json").write_text(json.dumps({"head_before":"a","head_after":"a","tree_before":"b",
 "tree_after":"b","source_sha256":h("source.snapshot"),"source_after_sha256":h("source.snapshot"),
 "binary_sha256":h("rrtransport.bin"),"governors":["performance"],"load_before":"0.1",
 "load_after":"0.1","pswpin_before":0,"pswpin_after":0,"pswpout_before":0,"pswpout_after":0,"rustc":"rustc fixture",
 "host":"fixture","competitors":[]})+"\n")
(d/"verifier.txt").write_text("fixture\n")
PY

expect_red() {
  local name=$1
  shift
  local copy="$tmp/$name"
  cp -a "$fixture" "$copy"
  "$@" "$copy"
  if python3 "$verifier" "$copy" >"$copy.result" 2>&1; then
    echo "false green: $name" >&2
    exit 1
  fi
}
mutate() { python3 "$@"; }

"$runner" --verify-fixture "$fixture" "$tmp/accepted"
expect_red staged-count mutate -c 'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"per-peer.tsv";r=p.read_text().splitlines();h=r[0].split("\t").index("staged");x=r[1].split("\t");x[h]="99999";r[1]="\t".join(x);p.write_text("\n".join(r)+"\n")'
expect_red nlri-count mutate -c 'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"per-peer.tsv";r=p.read_text().splitlines();h=r[0].split("\t").index("nlri");x=r[1].split("\t");x[h]="99999";r[1]="\t".join(x);p.write_text("\n".join(r)+"\n")'
expect_red corrupt-prefix mutate -c 'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"per-peer.tsv";s=p.read_text();p.write_text(s.replace("7c50a897bc4a4e51","0000000000000000",1))'
expect_red staged-is-wire mutate -c 'import json,pathlib,sys;p=pathlib.Path(sys.argv[1])/"phase.json";d=json.loads(p.read_text());d["wire_ms"]=2;p.write_text(json.dumps(d))'
expect_red group-key mutate -c 'import json,pathlib,sys;p=pathlib.Path(sys.argv[1])/"phase.json";d=json.loads(p.read_text());d["groups"]=2;p.write_text(json.dumps(d))'
expect_red sessions-999 mutate -c 'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"per-peer.tsv";p.write_text("\n".join(p.read_text().splitlines()[:-1])+"\n")'
for field in withdrawals duplicates outside decode_failures; do
  expect_red "$field" mutate -c "import pathlib,sys;p=pathlib.Path(sys.argv[1])/'per-peer.tsv';s=p.read_text();h=s.splitlines()[0].split('\\t').index('$field');r=s.splitlines();x=r[1].split('\\t');x[h]='1';r[1]='\\t'.join(x);p.write_text('\\n'.join(r)+'\\n')"
done
expect_red missing-final-rss mutate -c 'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"rss.tsv";p.write_text("\n".join(p.read_text().splitlines()[:-1])+"\n")'
if "$runner" --classify-rss 2097153 "$tmp/rss-over"; then echo "false green: rss ceiling" >&2; exit 1; fi
grep -q '"root_failure":"rss_ceiling"' "$tmp/rss-over/failure.json"
expect_red changed-head mutate -c 'import json,pathlib,sys;p=pathlib.Path(sys.argv[1])/"provenance.json";d=json.loads(p.read_text());d["head_after"]="changed";p.write_text(json.dumps(d))'
expect_red changed-hash mutate -c 'import pathlib,sys;(pathlib.Path(sys.argv[1])/"source.snapshot").write_bytes(b"changed")'
"$runner" --check-seam "$runner"
[[ $("$runner" --classify-child-exe /expected /expected R) == sample ]]
[[ $("$runner" --classify-child-exe /expected /foreign R) == reject ]]
[[ $("$runner" --classify-child-exe /expected /foreign X) == reject ]]
[[ $("$runner" --classify-child-exe /expected "" R) == retry_live_empty ]]
[[ $("$runner" --classify-child-exe /expected "" X) == exited ]]
[[ $("$runner" --classify-child-exe /expected "" Z) == exited ]]
[[ $("$runner" --classify-child-exe /expected "" absent) == exited ]]
[[ $("$runner" --classify-child-exe /expected /expected X) == exited ]]
[[ $("$runner" --classify-child-exe /expected /expected Z) == exited ]]
[[ $("$runner" --classify-child-exe /expected /expected absent) == retry_expected_absent ]]

resolve_observations() {
  local name=$1 seen=$2 expected=$3
  shift 3
  local log="$tmp/$name.log" stderr="$tmp/$name.stderr" actual
  actual=$("$runner" --resolve-child-observations "$log" "$seen" "$@" 2>"$stderr")
  [[ $actual == "$expected" ]] || {
    echo "unexpected sampler result: $name: $actual" >&2
    exit 1
  }
}

resolve_observations expected-live false $'sample\t200\t77' \
  "1,200,4242,11,expected,R,77,4242,11,true"
resolve_observations expected-terminal true $'exited\tabsent\t0' \
  "1,200,4242,11,expected,X,0,4242,11,true"
resolve_observations expected-z true $'exited\tabsent\t0' \
  "1,200,4242,11,expected,Z,0,4242,11,true"
for state in X Z absent; do
  resolve_observations "empty-$state" true $'exited\tabsent\t0' \
    "1,200,4242,11,empty,$state,0,4242,11,true"
done
resolve_observations foreign-live true $'reject\tabsent\t0' \
  "1,200,4242,11,foreign,R,0,4242,11,true"
resolve_observations foreign-terminal true $'reject\tabsent\t0' \
  "1,200,4242,11,foreign,X,0,4242,11,true"
resolve_observations multiple-children true $'reject\tabsent\t0' \
  "2,absent,absent,absent,empty,absent,0,absent,absent,true"
resolve_observations startup-no-child false $'startup_wait\tabsent\t0' \
  "0,absent,absent,absent,empty,absent,0,absent,absent,true"
resolve_observations exit-no-child true $'exited\tabsent\t0' \
  "0,absent,absent,absent,empty,absent,0,absent,absent,true"
resolve_observations empty-resolves true $'exited\tabsent\t0' \
  "1,200,4242,11,empty,R,0,4242,11,true" \
  "1,200,4242,11,empty,X,0,4242,11,true"
resolve_observations persistent-live-empty true $'reject\tabsent\t0' \
  "1,200,4242,11,empty,R,0,4242,11,true" \
  "1,200,4242,11,empty,S,0,4242,11,true" \
  "1,200,4242,11,empty,D,0,4242,11,true"
resolve_observations transient-expected-absent true $'sample\t200\t77' \
  "1,200,4242,11,expected,absent,0,4242,11,true" \
  "1,200,4242,11,expected,R,77,4242,11,true"
resolve_observations exhausted-expected-absent true $'reject\tabsent\t0' \
  "1,200,4242,11,expected,absent,0,4242,11,true" \
  "1,200,4242,11,expected,absent,0,4242,11,true" \
  "1,200,4242,11,expected,absent,0,4242,11,true"
resolve_observations identity-resolves true $'sample\t201\t88' \
  "1,200,4242,11,expected,R,77,4242,12,true" \
  "1,201,4242,13,expected,S,88,4242,13,true"
resolve_observations parent-resolves true $'sample\t201\t88' \
  "1,200,9999,11,expected,R,77,9999,11,true" \
  "1,201,4242,13,expected,S,88,4242,13,true"
resolve_observations identity-exhausted true $'reject\tabsent\t0' \
  "1,200,4242,11,expected,R,77,4242,12,true" \
  "1,201,4242,13,expected,R,88,4242,14,true" \
  "1,202,4242,15,expected,R,99,4242,16,true"
[[ $(wc -l <"$tmp/persistent-live-empty.log") == 3 ]]
[[ $(wc -l <"$tmp/identity-exhausted.log") == 3 ]]
[[ $(wc -l <"$tmp/exhausted-expected-absent.log") == 3 ]]
[[ $(wc -l <"$tmp/foreign-live.log") == 1 ]]
cmp "$tmp/persistent-live-empty.log" "$tmp/persistent-live-empty.stderr"
grep -Fq "run=1 observation=3 supervisor_pid=4242 supervisor_alive=true child_count=1 child_pid=200 child_starttime=11 parent_match=true executable=empty state=D resolution=reject reason=persistent_live_empty" \
  "$tmp/persistent-live-empty.log"
grep -Fq "resolution=sample reason=stable_after_retry" "$tmp/identity-resolves.log"
grep -Fq "resolution=reject reason=persistent_expected_absent" \
  "$tmp/exhausted-expected-absent.log"
grep -Fq "resolution=reject reason=foreign_executable" "$tmp/foreign-live.log"
if grep -Eq '/expected|/foreign|cmdline|cwd=|user=|host=' "$tmp/"*.log; then
  echo "unsafe sampler diagnostic field" >&2
  exit 1
fi

[[ $("$runner" --stop-reap-fixture sampler_rejected 37 "$tmp/reap-rejected" \
  2>"$tmp/reap-rejected.stderr") == $'sampler_rejected\t1\t37' ]]
[[ $("$runner" --stop-reap-fixture rss_ceiling 43 "$tmp/reap-rss" \
  2>"$tmp/reap-rss.stderr") == $'rss_ceiling\t1\t43' ]]
grep -Fq "sampler_reap reason=sampler_rejected supervisor_status=37" \
  "$tmp/reap-rejected/harness.log"
grep -Fq "sampler_reap reason=rss_ceiling supervisor_status=43" \
  "$tmp/reap-rss/harness.log"
[[ ! -s $tmp/reap-rejected/already-dead-signals.log ]]
[[ ! -s $tmp/reap-rss/already-dead-signals.log ]]
mkdir -p "$tmp/control-rejected"
printf 'stale-log\n' >"$tmp/control-rejected/harness.log"
[[ $("$runner" --sampler-control-fixture sampler_rejected 37 "$tmp/control-rejected" \
  2>"$tmp/control-rejected.stderr") == $'sampler_rejected\t1\t37' ]]
[[ $("$runner" --sampler-control-fixture rss_ceiling 43 "$tmp/control-rss" \
  2>"$tmp/control-rss.stderr") == $'rss_ceiling\t1\t43' ]]
[[ $("$runner" --sampler-control-fixture normal 0 "$tmp/control-normal" \
  2>"$tmp/control-normal.stderr") == $'normal\t0\t0' ]]
grep -Fq harness-before "$tmp/control-rejected/harness.log"
grep -Fq "resolution=reject reason=foreign_executable" "$tmp/control-rejected/harness.log"
grep -Fq harness-after "$tmp/control-rejected/harness.log"
if grep -Fq stale-log "$tmp/control-rejected/harness.log"; then
  echo "harness log was not truncated before launch" >&2
  exit 1
fi
before_line=$(grep -nF harness-before "$tmp/control-rejected/harness.log" | cut -d: -f1)
diagnostic_line=$(grep -nF "resolution=reject reason=foreign_executable" \
  "$tmp/control-rejected/harness.log" | cut -d: -f1)
after_line=$(grep -nF harness-after "$tmp/control-rejected/harness.log" | cut -d: -f1)
(( before_line < diagnostic_line && diagnostic_line < after_line ))
grep -Fq '"root_failure":"rss_ceiling"' "$tmp/control-rss/failure.json"

for seam in \
  "timeout -k 10 1200 \"\$script\" --campaign-inner \"\$output\"" \
  "full_verify \"\$receipt\"" \
  "python3 \"\$verifier\" \"\$receipt\" --full | tee \"\$receipt/verifier.txt\"" \
  "full_checksums \"\$receipt\"" \
  "sha256sum -c SHA256SUMS --strict"; do
  cp "$runner" "$tmp/runner"
  grep -Fv "$seam" "$tmp/runner" >"$tmp/mutated"
  mv "$tmp/mutated" "$tmp/runner"
  if "$runner" --check-seam "$tmp/runner"; then echo "false green: $seam" >&2; exit 1; fi
done

mutate_runner_red() {
  local name=$1 seam=$2 mode=$3 status=$4
  cp "$runner" "$tmp/$name"
  grep -Fv "$seam" "$tmp/$name" >"$tmp/mutated"
  mv "$tmp/mutated" "$tmp/$name"
  chmod +x "$tmp/$name"
  printf '# decoy: %s\n' "$seam" >>"$tmp/$name"
  if "$tmp/$name" --sampler-control-fixture "$mode" "$status" "$tmp/$name-fixture" \
    >"$tmp/$name.stdout" 2>"$tmp/$name.stderr"; then
    echo "false green executable seam: $name" >&2
    exit 1
  fi
}
# shellcheck disable=SC2016 # Exact production source text for destructive proof.
mutate_runner_red no-production-resolver \
  'resolve_sampler_child "$pid" "$expected" "$receipt/harness.log" "$run" "$seen_expected_child"' \
  sampler_rejected 37
# shellcheck disable=SC2016 # Exact production source text for destructive proof.
mutate_runner_red no-failure-reap 'stop_and_reap true "$reason"' sampler_rejected 37
# shellcheck disable=SC2016 # Exact production source text for destructive proof.
mutate_runner_red no-rss-failure-reap 'stop_and_reap true "$reason"' rss_ceiling 43
mutate_runner_red no-normal-reap 'stop_and_reap false completed' normal 0
cp "$runner" "$tmp/no-group-kill"
# shellcheck disable=SC2016 # Exact production source text for destructive proof.
mutate -c 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);s=p.read_text();seam='\''    kill -KILL -- "-$pid" 2>/dev/null || true\n'\'';assert s.count(seam)>=1;p.write_text(s.replace(seam,"",1))' \
  "$tmp/no-group-kill"
chmod +x "$tmp/no-group-kill"
if "$tmp/no-group-kill" --stop-reap-fixture sampler_rejected 37 \
  "$tmp/no-group-kill-fixture" >"$tmp/no-group-kill.stdout" 2>"$tmp/no-group-kill.stderr"; then
  echo "false green executable seam: unconditional group KILL" >&2
  exit 1
fi
cp "$runner" "$tmp/unowned-group-kill"
# shellcheck disable=SC2016 # Exact production source text for destructive proof.
mutate -c 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);s=p.read_text();inside='\''    kill -KILL -- "-$pid" 2>/dev/null || true\n'\'';anchor='\''  fi\n  if wait "$pid"; then\n'\'';outside='\''  kill -KILL -- "-$pid" 2>/dev/null || true\n'\'';assert inside in s and anchor in s;s=s.replace(inside,"",1).replace(anchor,'\''  fi\n'\''+outside+'\''  if wait "$pid"; then\n'\'',1);p.write_text(s)' \
  "$tmp/unowned-group-kill"
chmod +x "$tmp/unowned-group-kill"
if "$tmp/unowned-group-kill" --stop-reap-fixture sampler_rejected 37 \
  "$tmp/unowned-group-kill-fixture" >"$tmp/unowned-group-kill.stdout" \
  2>"$tmp/unowned-group-kill.stderr"; then
  echo "false green executable seam: unowned group KILL" >&2
  exit 1
fi
expect_red changed-shape mutate -c 'import json,pathlib,sys;p=pathlib.Path(sys.argv[1])/"phase.json";d=json.loads(p.read_text());d["workers"]=11;p.write_text(json.dumps(d))'
expect_red completion-semantics mutate -c 'import json,pathlib,sys;p=pathlib.Path(sys.argv[1])/"phase.json";d=json.loads(p.read_text());d["wire_completion"]="settled";p.write_text(json.dumps(d))'
for spec in messages:0 wire_ms:-1; do
  field=${spec%:*}; value=${spec#*:}
  expect_red "$field" mutate -c "import pathlib,sys;p=pathlib.Path(sys.argv[1])/'per-peer.tsv';r=p.read_text().splitlines();h=r[0].split('\\t').index('$field');x=r[1].split('\\t');x[h]='$value';r[1]='\\t'.join(x);p.write_text('\\n'.join(r)+'\\n')"
done
expect_red wrong-peer mutate -c 'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"per-peer.tsv";s=p.read_text();p.write_text(s.replace("127.2.1.1","192.0.2.1",1))'
expect_red wire-max mutate -c 'import json,pathlib,sys;p=pathlib.Path(sys.argv[1])/"phase.json";d=json.loads(p.read_text());d["wire_ms"]=4;p.write_text(json.dumps(d))'
expect_red phase-rss mutate -c 'import json,pathlib,sys;p=pathlib.Path(sys.argv[1])/"phase.json";d=json.loads(p.read_text());d["staged_rss_kib"]=111;p.write_text(json.dumps(d))'
expect_red hwm-below-rss mutate -c 'import json,pathlib,sys;p=pathlib.Path(sys.argv[1]);[(lambda f,d:(d.__setitem__("wire_vmhwm_kib",119),f.write_text(json.dumps(d))))(f,json.loads(f.read_text())) for f in (p/"rss.json",p/"phase.json")]'
expect_red hwm-nonmonotonic mutate -c 'import json,pathlib,sys;p=pathlib.Path(sys.argv[1]);[(lambda f,d:(d.__setitem__("staged_vmhwm_kib",126),f.write_text(json.dumps(d))))(f,json.loads(f.read_text())) for f in (p/"rss.json",p/"phase.json")]'
expect_red no-external-sample mutate -c 'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"rss.tsv";p.write_text("\n".join(x for x in p.read_text().splitlines() if not x.startswith("sample"))+"\n")'
expect_red sampler-max mutate -c 'import json,pathlib,sys;p=pathlib.Path(sys.argv[1])/"rss.json";d=json.loads(p.read_text());d["sampler_max_kib"]=124;p.write_text(json.dumps(d))'
expect_red tsv-checkpoint mutate -c 'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"rss.tsv";s=p.read_text();p.write_text(s.replace("staged\t110","staged\t111"))'
echo "PASS: rrtransport receipt mechanics and destructive proofs"
