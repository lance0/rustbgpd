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
 "sessions":1000,"established_before":1000,"established_after":1000,"prefixes":100000,"sources":4,"workers":12,"groups":1,"initial_eors":1000,
 "injection_ms":1,"staged_ms":2,"wire_ms":3,"established_rss_kib":100,
 "staged_rss_kib":110,"wire_rss_kib":120,"established_vmhwm_kib":105,
 "staged_vmhwm_kib":115,"wire_vmhwm_kib":125})+"\n")
header="peer\tstaged\tnlri\tmessages\twithdrawals\tduplicates\toutside\tdecode_failures\tcoverage\tbitmap_digest\tinitial_eor\twire_ms\n"
rows=[f"127.2.{i//254}.{i%254+1}\t100000\t100000\t391\t0\t0\t0\t0\t100000\t7c50a897bc4a4e51\ttrue\t3\n" for i in range(1000)]
(d/"per-peer.tsv").write_text(header+"".join(rows))
(d/"rss.tsv").write_text("checkpoint\trss_kib\nestablished\t100\nstaged\t110\nwire\t120\n")
(d/"rss.json").write_text('{"established_kib":100,"staged_kib":110,"wire_kib":120,"established_vmhwm_kib":105,"staged_vmhwm_kib":115,"wire_vmhwm_kib":125,"sampler_max_kib":125}\n')
(d/"source.snapshot").write_bytes(b"source")
(d/"rrtransport.bin").write_bytes(b"binary")
h=lambda p: hashlib.sha256((d/p).read_bytes()).hexdigest()
(d/"provenance.json").write_text(json.dumps({"head_before":"a","head_after":"a","tree_before":"b",
 "tree_after":"b","source_sha256":h("source.snapshot"),"source_after_sha256":h("source.snapshot"),
 "binary_sha256":h("rrtransport.bin"),"governors":["performance"],"load_before":"0.1",
 "load_after":"0.1","swap_before_kib":0,"swap_after_kib":0,"rustc":"rustc fixture",
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
expect_red omitted-route mutate -c 'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"per-peer.tsv";s=p.read_text();p.write_text(s.replace("\t100000\t100000\t391", "\t99999\t99999\t391",1))'
expect_red message-count mutate -c 'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"per-peer.tsv";s=p.read_text();p.write_text(s.replace("\t100000\t391", "\t391\t391"))'
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
cp "$runner" "$tmp/runner"
sed -i "/python3 \"\\\$verifier\" \"\\\$receipt\"/d" "$tmp/runner"
if "$runner" --check-seam "$tmp/runner"; then echo "false green: verifier seam" >&2; exit 1; fi
expect_red changed-shape mutate -c 'import json,pathlib,sys;p=pathlib.Path(sys.argv[1])/"phase.json";d=json.loads(p.read_text());d["workers"]=11;p.write_text(json.dumps(d))'
echo "PASS: rrtransport receipt mechanics and destructive proofs"
