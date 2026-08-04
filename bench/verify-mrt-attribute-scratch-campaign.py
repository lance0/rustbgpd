#!/usr/bin/env python3
"""Derive and fail closed on the frozen MRT attribute-scratch campaign."""
import argparse, hashlib, json, pathlib, re, statistics, subprocess
CONTROL = "a1cab917d49541d2137e54f9b2b2128e3c3f6715"
CANDIDATE = "0c98597b2e831423390c050ba3db2571f3e97b53"
TREES = {"control": "2b1039dfdf0cd3526e5c1d0778a30c4bc978530a",
         "candidate": "a6b2a7aee3ff2dfcef98fb2d8096e42244c846ae"}
INSTRUMENT = "860327fc1cb629235b13f29903fd9ca75438e72a0c7859c3411f13bfe35a1f30"
ORDER = ("control", "candidate", "candidate", "control")
SHAPES = {"ixp-700": (400400, 400400, 700), "dual-full-feed": (800800, 400400, 2)}
BASE = set("schema_version variant scratch_variant commit mode shape smoke warmup_count sample_index path_count prefix_count source_count output_len_bytes output_capacity_bytes decoded_entry_count elapsed_ns raw_sha256 semantic_sha256 allocator growth growth_path_assertion".split())
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ALLOC = set("alloc_calls alloc_zeroed_calls realloc_calls dealloc_calls requested_bytes baseline_live_requested_bytes final_live_requested_bytes peak_live_requested_bytes peak_live_delta_bytes peak_live_overhead_bytes".split())
class Invalid(ValueError): pass
def need(ok, message):
    if not ok: raise Invalid(message)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def read_json(path): return json.loads(path.read_text())
def read_rows(path): return [json.loads(x) for x in path.read_text().splitlines() if x]
def median(rows): return statistics.median(row["elapsed_ns"] for row in rows)
def cv_within_limit(rows):
    values = [row["elapsed_ns"] for row in rows]
    n=len(values); total=sum(values); d2=sum((n*value-total)**2 for value in values)
    return 400*d2 <= n*total*total
def expected_commands():
    rows = []
    for variant in ("control","candidate"):
        for mode in ("timing","diagnostic"):
            argv=["cargo","build","--locked","--profile","bench","-p","rustbgpd-mrt","--bench","snapshot_allocation"]
            if mode=="diagnostic": argv += ["--features","snapshot-allocation-diagnostics"]
            rows.append({"kind":"build","variant":variant,"mode":mode,"argv":argv})
    for block in range(1, 5):
        for slot, variant in enumerate(ORDER, 1):
            for shape in SHAPES:
                for mode in ("timing", "diagnostic"):
                    name=f"b{block}-s{slot}-{shape}.{mode}.jsonl"
                    rows.append({"kind":"abba", "block":block, "slot":slot,
                                 "variant":variant, "shape":shape, "mode":mode,
                                 "argv":["taskset","-c","0",f"{variant}-{mode}",mode,"--candidate","--scratch-variant",variant,"--shape",shape,"--commit",CONTROL if variant=="control" else CANDIDATE,"--output",name]})
    for shape in SHAPES:
        for side in ("left", "right"):
            name=f"same-{shape}-{side}.timing.jsonl"
            rows.append({"kind":"same-sha", "side":side, "variant":"control",
                         "shape":shape, "mode":"timing","argv":["taskset","-c","0","control-timing","timing","--candidate","--scratch-variant","control","--shape",shape,"--commit",CONTROL,"--output",name]})
    return rows
def check_raw(rows, variant, shape, mode):
    expected = BASE | ({"attribute_scratch"} if mode == "diagnostic" else set())
    need(len(rows) == (7 if mode == "timing" else 1), "raw sample count")
    paths, prefixes, sources = SHAPES[shape]
    commit = CONTROL if variant == "control" else CANDIDATE
    for index, row in enumerate(rows, 1):
        need(type(row) is dict and set(row) == expected, "closed raw schema")
        need(type(row["schema_version"]) is int and row["schema_version"] == 3 and row["variant"] == "candidate"
             and row["scratch_variant"] == variant and row["commit"] == commit,
             "raw source/variant identity")
        need(row["mode"] == mode and row["shape"] == shape and row["smoke"] is False
             and row["warmup_count"] == 2 and row["sample_index"] == index,
             "raw mode/order identity")
        need(all(type(row[name]) is int for name in ("warmup_count","sample_index","path_count","prefix_count","source_count","output_len_bytes","output_capacity_bytes","decoded_entry_count"))
             and row["output_capacity_bytes"] >= row["output_len_bytes"], "raw numeric contract")
        need((row["path_count"], row["prefix_count"], row["source_count"],
              row["decoded_entry_count"]) == (paths, prefixes, sources, paths)
             and row["output_len_bytes"] > 0, "fleet/count identity")
        need(isinstance(row["raw_sha256"], str) and HEX64.fullmatch(row["raw_sha256"])
             and isinstance(row["semantic_sha256"], str)
             and HEX64.fullmatch(row["semantic_sha256"]), "digest shape")
        if mode == "timing":
            need(type(row["elapsed_ns"]) is int and row["elapsed_ns"] > 0
                 and row["allocator"] is None and row["growth"] is None
                 and row["growth_path_assertion"] is None, "timing-mode contract")
        else:
            scratch, alloc, growth = row["attribute_scratch"], row["allocator"], row["growth"]
            need(row["elapsed_ns"] is None and isinstance(alloc, dict) and set(alloc) == ALLOC
                 and all(type(value) is int and value >= 0 for value in alloc.values())
                 and type(growth) is dict and set(growth) == {"top_level_unbounded_capacity_misses"}
                 and type(growth["top_level_unbounded_capacity_misses"]) is int
                 and 1 <= growth["top_level_unbounded_capacity_misses"] <= 64
                 and type(scratch) is dict and set(scratch) == {"eligible_opportunities","reuse_count","retained_capacity_bytes"}
                 and all(type(scratch[name]) is int for name in scratch)
                 and row["growth_path_assertion"] == "bounded-growth-observed",
                 "diagnostic-mode contract")
            need(scratch["eligible_opportunities"] == paths * 6, "opportunity count")
            if variant == "control": need(scratch["reuse_count"] == 0 and scratch["retained_capacity_bytes"] == 0, "control scratch contract")
            else: need(scratch["reuse_count"] == paths * 6 and 1 <= scratch["retained_capacity_bytes"] <= 131072, "candidate scratch contract")
            need(sum(alloc[k] for k in ("alloc_calls","alloc_zeroed_calls","realloc_calls")) > 0, "allocator signal")
    if mode == "timing": need(cv_within_limit(rows), "timing CV")
def derive(root):
    canonical, cells = [], {}; identities={shape:set() for shape in SHAPES}
    for block in range(1, 5):
        for slot, variant in enumerate(ORDER, 1):
            for shape in SHAPES:
                stem = root / "raw" / f"b{block}-s{slot}-{shape}"
                timing_path, diagnostic_path = stem.with_suffix(".timing.jsonl"), stem.with_suffix(".diagnostic.jsonl")
                timing, diagnostic = read_rows(timing_path), read_rows(diagnostic_path)
                check_raw(timing, variant, shape, "timing"); check_raw(diagnostic, variant, shape, "diagnostic")
                all_rows, d = timing + diagnostic, diagnostic[0]
                need(len({(r["raw_sha256"],r["semantic_sha256"],r["output_len_bytes"],r["decoded_entry_count"]) for r in all_rows}) == 1, "raw/semantic/count mismatch")
                identities[shape].update((r["raw_sha256"],r["semantic_sha256"],r["output_len_bytes"],r["decoded_entry_count"],r["path_count"],r["prefix_count"],r["source_count"]) for r in all_rows)
                alloc = sum(d["allocator"][k] for k in ("alloc_calls","alloc_zeroed_calls","realloc_calls"))
                row = {"schema":2,"block":block,"slot":slot,"scratch_variant":variant,
                       "shape":shape,"source_commit":d["commit"],"source_tree":TREES[variant],
                       "timing_ns":[r["elapsed_ns"] for r in timing],"allocator_calls":alloc,
                       "eligible_opportunities":d["attribute_scratch"]["eligible_opportunities"],
                       "scratch_reuses":d["attribute_scratch"]["reuse_count"],
                       "retained_scratch_capacity_bytes":d["attribute_scratch"]["retained_capacity_bytes"],
                       "output_len_bytes":d["output_len_bytes"],"decoded_entry_count":d["decoded_entry_count"],
                       "prefix_count":d["prefix_count"],"source_count":d["source_count"],
                       "raw_sha256":d["raw_sha256"],"semantic_sha256":d["semantic_sha256"],
                       "timing_jsonl_sha256":sha(timing_path),"diagnostic_jsonl_sha256":sha(diagnostic_path)}
                canonical.append(row); cells[block,slot,shape] = row
    same, same_hashes = {}, {}
    for shape in SHAPES:
        sides = []
        for side in ("left","right"):
            path=root / "raw" / f"same-{shape}-{side}.timing.jsonl"; rows = read_rows(path)
            same_hashes[shape,side]=sha(path)
            check_raw(rows, "control", shape, "timing"); sides.append(median(rows))
            identities[shape].update((r["raw_sha256"],r["semantic_sha256"],r["output_len_bytes"],r["decoded_entry_count"],r["path_count"],r["prefix_count"],r["source_count"]) for r in rows)
        favorable=max(0,sides[0]-sides[1]); need(favorable*100 < sides[0]*5, "same-SHA favorable drift")
        same[shape] = favorable,sides[0]
    need(all(len(values)==1 for values in identities.values()), "cross-cell encoded identity drift")
    for row in canonical:
        row["same_sha_left_jsonl_sha256"]=same_hashes[row["shape"],"left"]
        row["same_sha_right_jsonl_sha256"]=same_hashes[row["shape"],"right"]
    for block in range(1,5):
        for shape in SHAPES:
            controls = [cells[block,s,shape] for s in (1,4)]; candidates = [cells[block,s,shape] for s in (2,3)]
            need(sum(r["allocator_calls"] for r in candidates) * 100 <= sum(r["allocator_calls"] for r in controls) * 80, "allocation reduction")
            cm = sum(statistics.median(r["timing_ns"]) for r in controls); bm = sum(statistics.median(r["timing_ns"]) for r in candidates)
            favorable,left= same[shape]
            need(((cm-bm)*100-5*cm)*left >= favorable*100*cm, "drift-adjusted timing threshold")
    return canonical
def verify(root, repo, write=False, check_seal=True):
    need(not root.is_symlink(), "bundle root symlink"); entries=tuple(root.rglob("*")); need(all(not path.is_symlink() for path in entries), "bundle symlink"); need(all(path.is_file() or path.is_dir() for path in entries), "bundle special entry")
    files=tuple(path for path in entries if path.is_file())
    manifest = read_json(root / "manifest.json")
    need(type(manifest) is dict, "manifest object")
    need(type(manifest.get("schema")) is int, "manifest schema type")
    need(manifest == {"schema":1,"control_commit":CONTROL,"candidate_commit":CANDIDATE,
         "control_tree":TREES["control"],"candidate_tree":TREES["candidate"],
         "instrument_sha256":INSTRUMENT,"runner_sha256":manifest.get("runner_sha256"),
         "verifier_sha256":manifest.get("verifier_sha256"),"binaries":manifest.get("binaries")}, "closed manifest")
    need(type(manifest["binaries"]) is dict and set(manifest["binaries"]) == {"control","candidate"}
         and all(type(manifest["binaries"][v]) is dict and set(manifest["binaries"][v]) == {"timing","diagnostic"} for v in manifest["binaries"]), "binary manifest schema")
    binary_digests=[manifest["binaries"][variant][mode] for variant in ("control","candidate") for mode in ("timing","diagnostic")]
    need(all(isinstance(value,str) and HEX64.fullmatch(value) for value in binary_digests) and len(set(binary_digests))==4, "four distinct binary identities")
    for variant, commit in (("control",CONTROL),("candidate",CANDIDATE)):
        commit_object = subprocess.check_output(["git","-C",str(repo),"cat-file","commit",commit])
        rehashed = subprocess.check_output(["git","-C",str(repo),"hash-object","-t","commit","--stdin"],input=commit_object).decode().strip()
        need(rehashed == commit, "source commit rehash")
        tree = subprocess.check_output(["git","-C",str(repo),"rev-parse",f"{commit}^{{tree}}"], text=True).strip()
        need(tree == TREES[variant] == manifest[f"{variant}_tree"], "source tree rehash")
        source = subprocess.check_output(["git","-C",str(repo),"show",f"{commit}:crates/mrt/benches/snapshot_allocation.rs"])
        need(hashlib.sha256(source).hexdigest() == INSTRUMENT, "committed instrument drift")
        for mode in ("timing","diagnostic"):
            need(sha(root/"binaries"/f"{variant}-{mode}") == manifest["binaries"][variant][mode], "binary rehash")
    for name, current_name in (("runner","run-mrt-attribute-scratch-campaign.py"),("verifier","verify-mrt-attribute-scratch-campaign.py")):
        retained = root/"source"/f"{name}-mrt-attribute-scratch-campaign.py"
        current = repo/"bench"/current_name
        need(sha(retained) == sha(current) == manifest[f"{name}_sha256"], "runner/verifier drift")
    provenance = read_json(root/"provenance.json")
    need(type(provenance) is dict and set(provenance) == {"rustc","cargo","kernel","cpu_model","cpu_count","governor","affinity","taskset"}
         and type(provenance["cpu_count"]) is int and provenance["cpu_count"] > 0
         and all(isinstance(provenance[name],str) and provenance[name] for name in ("rustc","cargo","kernel","cpu_model","governor","affinity","taskset"))
         and provenance["governor"] == "performance" and provenance["affinity"] == "0", "provenance contract")
    commands = read_rows(root/"commands.jsonl"); need(commands == expected_commands(), "command/order contract")
    preflight=read_rows(root/"preflight.jsonl")
    allowed={f"b{b}-s{s}-{shape}.{mode}.jsonl" for b in range(1,5) for s in range(1,5) for shape in SHAPES for mode in ("timing","diagnostic")}
    allowed|={f"same-{shape}-{side}.timing.jsonl" for shape in SHAPES for side in ("left","right")}
    phase_order=[(f"b{c['block']}-s{c['slot']}-{c['shape']}.{c['mode']}.jsonl" if c["kind"]=="abba" else f"same-{c['shape']}-{c['side']}.timing.jsonl") for c in commands if c["kind"]!="build"]
    cursor=0
    for row in preflight:
        need(type(row) is dict and set(row)=={"phase","utc","load_1m","governor","competitors","status"} and isinstance(row["phase"],str) and row["phase"] in allowed
             and isinstance(row["utc"],str) and row["utc"].endswith("+00:00")
             and type(row["load_1m"]) in (int,float) and row["load_1m"] >= 0
             and isinstance(row["governor"],str) and isinstance(row["competitors"],list)
             and all(isinstance(name,str) and re.fullmatch(r"[A-Za-z0-9_.-]+",name) for name in row["competitors"])
             and row["status"] in ("wait","pass") and cursor < len(phase_order)
             and row["phase"]==phase_order[cursor], "preflight contract")
        if row["status"]=="pass":
            need(row["load_1m"] < 2 and row["governor"]=="performance" and row["competitors"]==[], "passing preflight contract"); cursor+=1
    need(cursor == len(phase_order), "preflight phase roster")
    expected_raw = {f"b{b}-s{s}-{shape}.{mode}.jsonl" for b in range(1,5) for s in range(1,5) for shape in SHAPES for mode in ("timing","diagnostic")}
    expected_raw |= {f"same-{shape}-{side}.timing.jsonl" for shape in SHAPES for side in ("left","right")}
    need({p.name for p in (root/"raw").glob("*.jsonl")} == expected_raw, "raw cell roster")
    canonical = "".join(json.dumps(r,sort_keys=True,separators=(",",":"))+"\n" for r in derive(root))
    target = root/"canonical.jsonl"
    if write: target.write_text(canonical)
    else: need(target.read_text() == canonical, "canonical derivation drift")
    if check_seal:
        sealed=sorted((path for path in files if path != root/"SHA256SUMS"),key=lambda path:path.relative_to(root).as_posix())
        expected="".join(f"{sha(path)}  {path.relative_to(root)}\n" for path in sealed)
        need((root/"SHA256SUMS").read_text()==expected, "canonical checksum roster")
    return {"classification":"go","rows":32,"blocks":4}
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("bundle",type=pathlib.Path); parser.add_argument("--repo",type=pathlib.Path,default=pathlib.Path.cwd()); parser.add_argument("--write",action="store_true")
    args=parser.parse_args()
    try: print(json.dumps(verify(args.bundle.absolute(),args.repo.resolve(),args.write,not args.write),sort_keys=True))
    except (OSError,ValueError,json.JSONDecodeError,subprocess.CalledProcessError) as error: parser.error(str(error))
if __name__ == "__main__": main()
