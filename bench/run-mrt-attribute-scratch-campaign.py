#!/usr/bin/env python3
"""Build and run the frozen MRT scratch A/B under one host fence."""
import argparse, datetime, fcntl, hashlib, importlib.util, json, os, pathlib, shutil, subprocess, tempfile, time
HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("scratch_verify", HERE / "verify-mrt-attribute-scratch-campaign.py")
VERIFY = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(VERIFY)
def run(argv, check=True, **kwargs): return subprocess.run(argv, check=check, **kwargs)
def output(argv): return subprocess.check_output(argv, text=True).strip()
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def dump(path, value): path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
def open_lock(path): return os.fdopen(os.open(path,os.O_RDWR|os.O_CREAT|os.O_CLOEXEC|os.O_NOFOLLOW,0o600),"r+")
def cleanup(repo,temp,trees,remove=run):
    ok=True
    for tree in trees: ok &= remove(["git","-C",str(repo),"worktree","remove","--force",str(tree)],check=False).returncode == 0
    if ok: shutil.rmtree(temp)
    else: raise RuntimeError(f"worktree cleanup failed; retained recovery state in {temp}")
def governor(cpu):
    path = pathlib.Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor")
    return path.read_text().strip()
def wait_idle(cpu, log, phase):
    deadline = time.monotonic() + 300
    while True:
        load = float(pathlib.Path("/proc/loadavg").read_text().split()[0]); gov = governor(cpu)
        competitors=sorted(name for name in output(["ps","-eo","comm="]).splitlines() if name.strip() in {"cargo","rustc","perf","rustbgpd"} or name.strip().startswith(("snapshot_alloc","rrharness","reloadstall")))
        record = {"phase":phase,"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"load_1m":load,"governor":gov,"competitors":competitors,"status":"pass" if load < 2 and gov == "performance" and not competitors else "wait"}
        with log.open("a") as stream: stream.write(json.dumps(record,sort_keys=True,separators=(",",":"))+"\n")
        if record["status"] == "pass": return
        if time.monotonic() >= deadline: raise RuntimeError(f"host preflight timed out for {phase}")
        time.sleep(1)
def build(repo, tree, variant, mode, target, commands):
    command = next(row for row in commands if row.get("kind") == "build" and row["variant"] == variant and row["mode"] == mode)
    env = os.environ.copy(); env["CARGO_TARGET_DIR"] = str(target)
    run(command["argv"], cwd=tree, env=env)
    binaries = [p for p in (target/"release"/"deps").glob("snapshot_allocation-*") if p.is_file() and os.access(p,os.X_OK)]
    if len(binaries) != 1: raise RuntimeError(f"expected one {variant} {mode} binary, found {len(binaries)}")
    destination = repo/"binaries"/f"{variant}-{mode}"; shutil.copy2(binaries[0],destination)
def seal(root):
    rows=[]
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p != root/"SHA256SUMS"):
        rows.append(f"{sha(path)}  {path.relative_to(root)}\n")
    (root/"SHA256SUMS").write_text("".join(rows))
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("output",type=pathlib.Path); parser.add_argument("--repo",type=pathlib.Path,default=HERE.parent)
    args=parser.parse_args(); cpu_count=os.cpu_count()
    if type(cpu_count) is not int or cpu_count <= 0: raise RuntimeError("os.cpu_count() must return a positive integer")
    repo=args.repo.resolve(); root=args.output.absolute()
    if root.exists(): raise SystemExit(f"refusing existing output: {root}")
    for script in (HERE/"run-mrt-attribute-scratch-campaign.py",HERE/"verify-mrt-attribute-scratch-campaign.py"):
        run(["git","-C",str(repo),"ls-files","--error-unmatch",str(script.relative_to(repo))],stdout=subprocess.DEVNULL)
        run(["git","-C",str(repo),"diff","--quiet","--",str(script.relative_to(repo))])
        run(["git","-C",str(repo),"diff","--cached","--quiet","--",str(script.relative_to(repo))])
    lock_path=pathlib.Path(os.environ.get("RUSTBGPD_HOST_LOCK",pathlib.Path.home()/".local/state/rustbgpd-host.lock")); lock_path.parent.mkdir(parents=True,exist_ok=True)
    lock=open_lock(lock_path)
    try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: raise SystemExit("shared rustbgpd host lock is busy")
    root.mkdir(); (root/"raw").mkdir(); (root/"binaries").mkdir(); (root/"source").mkdir()
    shutil.copy2(HERE/"run-mrt-attribute-scratch-campaign.py",root/"source"/"runner-mrt-attribute-scratch-campaign.py")
    shutil.copy2(HERE/"verify-mrt-attribute-scratch-campaign.py",root/"source"/"verifier-mrt-attribute-scratch-campaign.py")
    commands=VERIFY.expected_commands(); temp=pathlib.Path(tempfile.mkdtemp(prefix="mrt-scratch-")); trees={}
    try:
        for variant, commit in (("control",VERIFY.CONTROL),("candidate",VERIFY.CANDIDATE)):
            tree=temp/variant; run(["git","-C",str(repo),"worktree","add","--detach",str(tree),commit]); trees[variant]=tree
        for variant in ("control","candidate"):
            for mode in ("timing","diagnostic"): build(root,trees[variant],variant,mode,temp/f"target-{variant}-{mode}",commands)
        binaries={variant:{mode:sha(root/"binaries"/f"{variant}-{mode}") for mode in ("timing","diagnostic")} for variant in ("control","candidate")}
        dump(root/"manifest.json",{"schema":1,"control_commit":VERIFY.CONTROL,"candidate_commit":VERIFY.CANDIDATE,"control_tree":VERIFY.TREES["control"],"candidate_tree":VERIFY.TREES["candidate"],"instrument_sha256":VERIFY.INSTRUMENT,"runner_sha256":sha(root/"source"/"runner-mrt-attribute-scratch-campaign.py"),"verifier_sha256":sha(root/"source"/"verifier-mrt-attribute-scratch-campaign.py"),"binaries":binaries})
        cpu_model=next(line.split(":",1)[1].strip() for line in pathlib.Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name"))
        dump(root/"provenance.json",{"rustc":output(["rustc","-Vv"]),"cargo":output(["cargo","-V"]),"kernel":output(["uname","-srmo"]),"cpu_model":cpu_model,"cpu_count":cpu_count,"governor":governor(0),"affinity":"0","taskset":output(["taskset","--version"])})
        with (root/"commands.jsonl").open("w") as stream:
            for row in commands: stream.write(json.dumps({k:v for k,v in row.items() if k != "binary_sha256"},sort_keys=True,separators=(",",":"))+"\n")
        for command in commands:
            if command["kind"] == "build": continue
            variant,shape,mode=command["variant"],command["shape"],command["mode"]
            if command["kind"] == "abba": name=f"b{command['block']}-s{command['slot']}-{shape}.{mode}.jsonl"
            else: name=f"same-{shape}-{command['side']}.timing.jsonl"
            target=root/"raw"/name; wait_idle(0,root/"preflight.jsonl",name)
            argv=command["argv"][:3]+[str(root/"binaries"/f"{variant}-{mode}")]+command["argv"][4:-1]+[str(target)]
            run(argv)
        VERIFY.verify(root,repo,write=True,check_seal=False); seal(root); VERIFY.verify(root,repo)
    finally:
        cleanup(repo,temp,trees.values())
    print(json.dumps({"classification":"go","bundle":str(root)},sort_keys=True))
if __name__ == "__main__": main()
