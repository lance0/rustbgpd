import hashlib, importlib.util, json, os, pathlib, shutil, subprocess, tempfile, types, unittest, unittest.mock
REPO = pathlib.Path(__file__).parents[2]
SCRIPT = REPO / "bench/verify-mrt-attribute-scratch-campaign.py"
SPEC = importlib.util.spec_from_file_location("scratch_verify", SCRIPT)
VERIFY = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(VERIFY)
RUN_SPEC = importlib.util.spec_from_file_location("scratch_runner", REPO / "bench/run-mrt-attribute-scratch-campaign.py")
RUNNER = importlib.util.module_from_spec(RUN_SPEC); RUN_SPEC.loader.exec_module(RUNNER)
def write_json(path, value): path.write_text(json.dumps(value, sort_keys=True, indent=2)+"\n")
def write_rows(path, rows): path.write_text("".join(json.dumps(r,sort_keys=True,separators=(",",":"))+"\n" for r in rows))
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def seal(root):
    (root/"SHA256SUMS").write_text("".join(f"{digest(p)}  {p.relative_to(root)}\n" for p in sorted(root.rglob("*")) if p.is_file() and p != root/"SHA256SUMS"))
def raw_row(variant, shape, mode, index, elapsed, calls, capacity):
    paths,prefixes,sources=VERIFY.SHAPES[shape]; hexes=("1" if shape=="ixp-700" else "2")*64
    row={"schema_version":3,"variant":"candidate","scratch_variant":variant,"commit":VERIFY.CONTROL if variant=="control" else VERIFY.CANDIDATE,"mode":mode,"shape":shape,"smoke":False,"warmup_count":2,"sample_index":index,"path_count":paths,"prefix_count":prefixes,"source_count":sources,"output_len_bytes":paths*80,"output_capacity_bytes":paths*80,"decoded_entry_count":paths,"elapsed_ns":elapsed,"raw_sha256":hexes,"semantic_sha256":("3" if shape=="ixp-700" else "4")*64,"allocator":None,"growth":None,"growth_path_assertion":None}
    if mode=="diagnostic":
        row.update(elapsed_ns=None,allocator={name:(calls if name=="alloc_calls" else 0) for name in VERIFY.ALLOC},
                   growth={"top_level_unbounded_capacity_misses":1},growth_path_assertion="bounded-growth-observed",
                   attribute_scratch={"eligible_opportunities":paths*6,"reuse_count":paths*6 if variant=="candidate" else 0,
                                      "retained_capacity_bytes":capacity if variant=="candidate" else 0})
    return row
def fixture(root, candidate_ns=90, same_right=100, candidate_calls=70, capacity=4096, control_ns=100, same_left=100, finalize=True):
    for name in ("raw","binaries","source"): (root/name).mkdir(parents=True)
    shutil.copy2(REPO/"bench/run-mrt-attribute-scratch-campaign.py",root/"source/runner-mrt-attribute-scratch-campaign.py")
    shutil.copy2(SCRIPT,root/"source/verifier-mrt-attribute-scratch-campaign.py")
    binaries={}
    for variant in ("control","candidate"):
        binaries[variant]={}
        for mode in ("timing","diagnostic"):
            path=root/"binaries"/f"{variant}-{mode}"; path.write_bytes(f"{variant}-{mode}".encode()); binaries[variant][mode]=digest(path)
    write_json(root/"manifest.json",{"schema":1,"control_commit":VERIFY.CONTROL,"candidate_commit":VERIFY.CANDIDATE,"control_tree":VERIFY.TREES["control"],"candidate_tree":VERIFY.TREES["candidate"],"instrument_sha256":VERIFY.INSTRUMENT,"runner_sha256":digest(root/"source/runner-mrt-attribute-scratch-campaign.py"),"verifier_sha256":digest(root/"source/verifier-mrt-attribute-scratch-campaign.py"),"binaries":binaries})
    write_json(root/"provenance.json",{"rustc":"rustc","cargo":"cargo","kernel":"Linux","cpu_model":"cpu","cpu_count":64,"governor":"performance","affinity":"0","taskset":"taskset"})
    commands=VERIFY.expected_commands(); write_rows(root/"commands.jsonl",commands)
    phases=[]
    for c in commands:
        if c["kind"]=="build": continue
        phase=(f"b{c['block']}-s{c['slot']}-{c['shape']}.{c['mode']}.jsonl" if c["kind"]=="abba" else f"same-{c['shape']}-{c['side']}.timing.jsonl")
        phases.append({"phase":phase,"utc":"2026-08-03T00:00:00+00:00","load_1m":0.1,"governor":"performance","competitors":[],"status":"pass"})
    write_rows(root/"preflight.jsonl",phases)
    for block in range(1,5):
        for slot,variant in enumerate(VERIFY.ORDER,1):
            for shape in VERIFY.SHAPES:
                stem=root/"raw"/f"b{block}-s{slot}-{shape}"
                ns=candidate_ns if variant=="candidate" else control_ns; calls=candidate_calls if variant=="candidate" else 100
                write_rows(stem.with_suffix(".timing.jsonl"),[raw_row(variant,shape,"timing",i,ns,calls,capacity) for i in range(1,8)])
                write_rows(stem.with_suffix(".diagnostic.jsonl"),[raw_row(variant,shape,"diagnostic",1,None,calls,capacity)])
    for shape in VERIFY.SHAPES:
        for side,ns in (("left",same_left),("right",same_right)):
            write_rows(root/"raw"/f"same-{shape}-{side}.timing.jsonl",[raw_row("control",shape,"timing",i,ns,100,0) for i in range(1,8)])
    if finalize: write_rows(root/"canonical.jsonl",VERIFY.derive(root)); seal(root)
def edit_json(path, change):
    value=json.loads(path.read_text()); change(value); write_json(path,value)
def edit_rows(path, change):
    rows=[json.loads(line) for line in path.read_text().splitlines()]; change(rows); write_rows(path,rows)
class CampaignContract(unittest.TestCase):
    def make(self, **kwargs):
        tmp=tempfile.TemporaryDirectory(); root=pathlib.Path(tmp.name); fixture(root,**kwargs); return tmp,root
    def test_valid_and_drift_adjusted_equality(self):
        for kwargs in ({},{"candidate_ns":91,"same_right":96}):
            with self.subTest(kwargs=kwargs):
                tmp,root=self.make(**kwargs); self.addCleanup(tmp.cleanup)
                self.assertEqual(VERIFY.verify(root,REPO)["classification"],"go")
    def test_runner_plan_is_four_builds_sixty_four_abba_and_four_same_sha(self):
        kinds=[row["kind"] for row in VERIFY.expected_commands()]
        self.assertEqual((VERIFY.CONTROL,VERIFY.CANDIDATE),("a1cab917d49541d2137e54f9b2b2128e3c3f6715","0c98597b2e831423390c050ba3db2571f3e97b53")); self.assertEqual(VERIFY.ORDER,("control","candidate","candidate","control")); self.assertEqual(VERIFY.SHAPES,{"ixp-700":(400400,400400,700),"dual-full-feed":(800800,400400,2)})
        self.assertEqual(VERIFY.TREES,{"control":"2b1039dfdf0cd3526e5c1d0778a30c4bc978530a","candidate":"a6b2a7aee3ff2dfcef98fb2d8096e42244c846ae"}); self.assertEqual(VERIFY.INSTRUMENT,"860327fc1cb629235b13f29903fd9ca75438e72a0c7859c3411f13bfe35a1f30")
        self.assertEqual((kinds.count("build"),kinds.count("abba"),kinds.count("same-sha")),(4,64,4))
        self.assertEqual(VERIFY.expected_commands()[4]["argv"],["taskset","-c","0","control-timing","timing","--candidate","--scratch-variant","control","--shape","ixp-700","--commit","a1cab917d49541d2137e54f9b2b2128e3c3f6715","--output","b1-s1-ixp-700.timing.jsonl"])
        self.assertEqual(VERIFY.expected_commands()[-1]["argv"],["taskset","-c","0","control-timing","timing","--candidate","--scratch-variant","control","--shape","dual-full-feed","--commit","a1cab917d49541d2137e54f9b2b2128e3c3f6715","--output","same-dual-full-feed-right.timing.jsonl"])
    def test_lock_and_cleanup_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory); lock=root/"lock"; lock.write_text("held"); handle=RUNNER.open_lock(lock); handle.close(); self.assertEqual(lock.read_text(),"held")
            link=root/"link"; link.symlink_to(lock); self.assertRaises(OSError,RUNNER.open_lock,link)
            stale=root/"stale"; stale.mkdir(); failed=lambda *args,**kwargs:types.SimpleNamespace(returncode=1)
            with self.assertRaises(RuntimeError): RUNNER.cleanup(REPO,stale,[stale/"tree"],failed)
            self.assertTrue(stale.exists())
    def test_runner_rejects_invalid_cpu_count_before_output_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            for value in (None,True,0,-1):
                with self.subTest(value=value),unittest.mock.patch.object(RUNNER.os,"cpu_count",return_value=value),unittest.mock.patch("sys.argv",["runner",str(root)]),self.assertRaisesRegex(RuntimeError,"positive integer"): RUNNER.main()
            with unittest.mock.patch.object(RUNNER.os,"cpu_count",return_value=64),unittest.mock.patch("sys.argv",["runner",str(root)]),self.assertRaisesRegex(SystemExit,"refusing existing output"): RUNNER.main()
    def test_exact_threshold_rejects_fraction_below_boundary(self):
        tmp=tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); root=pathlib.Path(tmp.name)
        fixture(root,candidate_ns=909999993,control_ns=999999992,same_left=1000000007,same_right=960000007,finalize=False)
        with self.assertRaises(VERIFY.Invalid): VERIFY.derive(root)
    def rejected(self, mutate, rederive=False, exact=False):
        tmp,root=self.make(); self.addCleanup(tmp.cleanup); mutate(root); seal(root)
        if rederive:
            try: write_rows(root/"canonical.jsonl",VERIFY.derive(root)); seal(root)
            except (VERIFY.Invalid,KeyError,ValueError): pass
        expected=VERIFY.Invalid if exact else (VERIFY.Invalid,KeyError,ValueError,json.JSONDecodeError)
        with self.assertRaises(expected): VERIFY.verify(root,REPO)
    def test_checksum_mutation_is_rejected(self):
        for mode in ("reorder","duplicate","nested"):
            tmp,root=self.make(); self.addCleanup(tmp.cleanup); lines=(root/"SHA256SUMS").read_text().splitlines()
            if mode=="nested": (root/"raw/SHA256SUMS").write_text("nested authority name\n")
            else: (root/"SHA256SUMS").write_text("\n".join((list(reversed(lines)) if mode=="reorder" else lines+[lines[0]]))+"\n")
            with self.subTest(mode=mode),self.assertRaises(VERIFY.Invalid): VERIFY.verify(root,REPO)
            if mode=="nested":
                for sealer in (seal,RUNNER.seal): sealer(root); self.assertIn("raw/SHA256SUMS",(root/"SHA256SUMS").read_text()); self.assertEqual(VERIFY.verify(root,REPO)["classification"],"go")
        tmp,root=self.make(); self.addCleanup(tmp.cleanup); link=root.parent/f"{root.name}-link"; link.symlink_to(root,target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaises(VERIFY.Invalid): VERIFY.verify(link,REPO)
        result=subprocess.run(["python3",str(SCRIPT),str(link),"--repo",str(REPO)],capture_output=True,text=True)
        self.assertEqual(result.returncode,2); self.assertIn("bundle root symlink",result.stderr)
    def test_load_bearing_mutations(self):
        def both(root,suffix,change):
            for slot in (2,3): edit_rows(root/"raw"/f"b1-s{slot}-ixp-700.{suffix}.jsonl",change)
        def identity(root, stem):
            for suffix in ("timing","diagnostic") if stem.startswith("b") else ("timing",): edit_rows(root/"raw"/f"{stem}.{suffix}.jsonl",lambda rows:[row.update(raw_sha256="9"*64,semantic_sha256="8"*64) for row in rows])
        def binary_alias(root):
            target=root/"binaries/candidate-timing"; target.write_bytes((root/"binaries/control-timing").read_bytes())
            edit_json(root/"manifest.json",lambda value:value["binaries"]["candidate"].update(timing=digest(target)))
        def cv_witness(root):
            for slot,values in ((1,[9000000000]*7),(2,[6790711581,7491474890,7491474890,7491474890,7491474890,7491474890,8192238199]),(3,[7491474890]*7),(4,[9000000000]*7)): edit_rows(root/"raw"/f"b1-s{slot}-ixp-700.timing.jsonl",lambda rows,values=values:[row.update(elapsed_ns=value) for row,value in zip(rows,values)])
        mutations={
          "reorder":lambda r: (r/"canonical.jsonl").write_text("\n".join(reversed((r/"canonical.jsonl").read_text().splitlines()))+"\n"),
          "raw-edit":lambda r: edit_rows(r/"raw/b1-s1-ixp-700.timing.jsonl",lambda x:x[0].update(elapsed_ns=101)),
          "raw-opaque-edit":lambda r: edit_rows(r/"raw/b1-s1-ixp-700.timing.jsonl",lambda x:x[0].update(output_capacity_bytes=x[0]["output_capacity_bytes"]+1)),
          "tree":lambda r:edit_json(r/"manifest.json",lambda x:x.update(control_tree="0"*40)),
          "source-commit":lambda r:edit_rows(r/"raw/b1-s1-ixp-700.timing.jsonl",lambda x:x[0].update(commit="0"*40)),
          "raw-schema-float":lambda r:edit_rows(r/"raw/b1-s1-ixp-700.timing.jsonl",lambda x:x[0].update(schema_version=3.0)),
          "binary-hash":lambda r:edit_json(r/"manifest.json",lambda x:x["binaries"]["control"].update(timing="0"*64)),
          "missing-cell":lambda r:(r/"raw/b1-s1-ixp-700.timing.jsonl").unlink(),
          "instrument":lambda r:edit_json(r/"manifest.json",lambda x:x.update(instrument_sha256="0"*64)),
          "manifest-schema-bool":lambda r:edit_json(r/"manifest.json",lambda x:x.update(schema=True)),
          "provenance-cpu-bool":lambda r:edit_json(r/"provenance.json",lambda x:x.update(cpu_count=True)),
          "runner":lambda r:(r/"source/runner-mrt-attribute-scratch-campaign.py").write_text("changed\n"),
          "verifier":lambda r:(r/"source/verifier-mrt-attribute-scratch-campaign.py").write_text("changed\n"),
          "command":lambda r:write_rows(r/"commands.jsonl",list(reversed(VERIFY.expected_commands()))),
          "preflight":lambda r:edit_rows(r/"preflight.jsonl",lambda x:x[0].update(status="wait")),
          "cv":cv_witness,
          "allocation":lambda r:both(r,"diagnostic",lambda x:x[0]["allocator"].update(alloc_calls=81)),
          "timing":lambda r:both(r,"timing",lambda x:[v.update(elapsed_ns=96) for v in x]),
          "same-sha":lambda r:edit_rows(r/"raw/same-ixp-700-right.timing.jsonl",lambda x:[v.update(elapsed_ns=95) for v in x]),
          "reuse":lambda r:edit_rows(r/"raw/b1-s2-ixp-700.diagnostic.jsonl",lambda x:x[0]["attribute_scratch"].update(reuse_count=0)),
          "opportunities":lambda r:edit_rows(r/"raw/b1-s2-ixp-700.diagnostic.jsonl",lambda x:x[0]["attribute_scratch"].update(eligible_opportunities=1)),
          "cap-zero":lambda r:edit_rows(r/"raw/b1-s2-ixp-700.diagnostic.jsonl",lambda x:x[0]["attribute_scratch"].update(retained_capacity_bytes=0)),
          "cap-large":lambda r:edit_rows(r/"raw/b1-s2-ixp-700.diagnostic.jsonl",lambda x:x[0]["attribute_scratch"].update(retained_capacity_bytes=131073)),
          "cap-bool":lambda r:edit_rows(r/"raw/b1-s2-ixp-700.diagnostic.jsonl",lambda x:x[0]["attribute_scratch"].update(retained_capacity_bytes=True)),
          "growth":lambda r:edit_rows(r/"raw/b1-s2-ixp-700.diagnostic.jsonl",lambda x:x[0]["growth"].update(top_level_unbounded_capacity_misses=0)),
          "growth-large":lambda r:edit_rows(r/"raw/b1-s2-ixp-700.diagnostic.jsonl",lambda x:x[0]["growth"].update(top_level_unbounded_capacity_misses=65)),
          "growth-bool":lambda r:edit_rows(r/"raw/b1-s2-ixp-700.diagnostic.jsonl",lambda x:x[0]["growth"].update(top_level_unbounded_capacity_misses=True)),
          "abba-identity":lambda r:identity(r,"b1-s2-ixp-700"),
          "same-sha-identity":lambda r:identity(r,"same-ixp-700-right"),
          "binary-alias":binary_alias,
          "manifest-object":lambda r:write_json(r/"manifest.json",[]),
          "binaries-object":lambda r:edit_json(r/"manifest.json",lambda x:x.update(binaries=[{}])),
          "binary-mode-map":lambda r:edit_json(r/"manifest.json",lambda x:x["binaries"].update(control=["timing","diagnostic"])),
          "provenance-object":lambda r:write_json(r/"provenance.json",["rustc","cargo","kernel","cpu_model","cpu_count","governor","affinity","taskset"]),
          "preflight-row-object":lambda r:edit_rows(r/"preflight.jsonl",lambda x:x.__setitem__(0,["phase","utc","load_1m","governor","competitors","status"])),
          "preflight-phase-object":lambda r:edit_rows(r/"preflight.jsonl",lambda x:x[0].update(phase=[])),
          "growth-object":lambda r:edit_rows(r/"raw/b1-s2-ixp-700.diagnostic.jsonl",lambda x:x[0].update(growth=None)),
          "scratch-object":lambda r:edit_rows(r/"raw/b1-s2-ixp-700.diagnostic.jsonl",lambda x:x[0].update(attribute_scratch=None)),
          "sealed-symlink":lambda r:((r/"manifest.json").rename(r/"manifest.real"),(r/"manifest.json").symlink_to("manifest.real")),
          "special-node":lambda r:os.mkfifo(r/"raw/unsealed.fifo"),
        }
        gate_mutations={"source-commit","raw-schema-float","cv","allocation","timing","same-sha","reuse","opportunities","cap-zero","cap-large","cap-bool","growth","growth-large","growth-bool","abba-identity","same-sha-identity"}
        exact_mutations={"manifest-object","binaries-object","binary-mode-map","provenance-object","preflight-row-object","preflight-phase-object","growth-object","scratch-object","sealed-symlink","special-node"}
        for name,mutate in mutations.items():
            with self.subTest(name=name): self.rejected(mutate,name in gate_mutations,name in exact_mutations)
if __name__ == "__main__": unittest.main()
