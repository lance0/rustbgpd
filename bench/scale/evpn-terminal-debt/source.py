"""Compose this harness with an explicit, immutable qualification dependency."""

import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time

import patches

# A campaign's input is one explicit clean commit, named with `--base`: the
# product tree plus the qualification harness and driver. This harness adds
# only its own directory to it.
PREFIX = "bench/scale/evpn-terminal-debt/"
# What an input commit and the terminal head must have in common.
INPUT_PATHS = ("bench/scale/evpn-qualification", "bench/evpn-load")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
# Builds use the rustbgpd share of the host; placement does not change the binaries.
BUILD_CPUS = "0-23,32-55"
DAEMON_CPUS = "24-27,56-59"
HARNESS_CPUS = "28-31,60-63"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()


def archive_files(path):
    with tarfile.open(path) as archive:
        require(all(member.isdir() or member.isfile() or member.issym() for member in archive),
                "unexpected non-file archive entry")
        return {member.name: (("symlink", member.linkname) if member.issym() else archive.extractfile(member).read())
                for member in archive if member.isfile() or member.issym()}


def helpers(source):
    sys.dont_write_bytecode = True
    directory = str(Path(source) / "bench/scale/evpn-qualification")
    require(not any(name in sys.modules and Path(sys.modules[name].__file__).parent != Path(directory)
                    for name in ("qualify", "recovery", "wire")), "mixed qualification inputs")
    sys.path.insert(0, directory)
    return tuple(importlib.import_module(name) for name in ("qualify", "recovery", "wire"))


def expected(output, arm, q):
    files = archive_files(output / "qualification.tar")
    own = archive_files(output / "terminal.tar")
    require(own and all(name.startswith(PREFIX) for name in own), "terminal archive escaped owned directory")
    files.update(own)
    names = ("src/main.rs", "crates/rib/src/manager/mod.rs")
    main, rib = q.derived_texts(*(files[name].decode() for name in names),
                              files["bench/scale/evpn-qualification/observer.rs"].decode(), arm,
                              files["bench/scale/evpn-qualification/input_observer.rs"].decode())
    # The qualification derivation also records the dirty-set high-water mark
    # its observer reports; without it the observer does not compile.
    groups = "crates/rib/src/manager/update_groups.rs"
    rib, grouped = q.derived_high_water(rib, files[groups].decode())
    files.update(zip((*names, groups), (main.encode(), rib.encode(), grouped.encode()), strict=True))
    # patches.py and its Rust includes belong to the immutable terminal archive.
    require((HERE / "patches.py").read_bytes() == own[PREFIX + "patches.py"], "patch consumer drift")
    for name in ("work.rs", "completion.rs"):
        require((HERE / name).read_bytes() == own[PREFIX + name], "Rust observer input drift")
    return patches.instrument(files, HERE)


def verify_tree(source, files):
    actual = {str(path.relative_to(source)) for path in source.rglob("*") if path.is_file() or path.is_symlink()}
    require(actual == set(files), "export contains missing or untracked inputs")
    for name, data in files.items():
        if isinstance(data, tuple):
            require((source / name).is_symlink() and str((source / name).readlink()) == data[1], f"export symlink drift: {name}")
            continue
        require(not (source / name).is_symlink() and (source / name).read_bytes() == data,
                f"export input drift: {name}")


def manifest(output):
    row = json.loads((output / "campaign.json").read_text())
    # A campaign names its own input. A parent-versus-candidate comparison
    # freezes one campaign per product tree, each on its own input commit
    # (see compare.py).
    require(row["schema"] == "rustbgpd.evpn-terminal-debt.v1" and row["qualification_head"] == row["base"]
            and type(row["base"]) is str and len(row["base"]) == 40, "wrong qualification dependency")
    import hashlib
    for name in ("qualification", "terminal"):
        require(hashlib.sha256((output / f"{name}.tar").read_bytes()).hexdigest() == row[f"{name}_sha256"],
                f"{name} archive changed")
        archive_head = subprocess.run(["git", "get-tar-commit-id"], input=(output / f"{name}.tar").read_bytes(),
                                      capture_output=True, check=True).stdout.decode().strip()
        require(archive_head == row["qualification_head" if name == "qualification" else "head"],
                f"{name} archive does not match its source commit")
    require(row["production_activation"] is False and row["enhanced_refresh"] is False,
            "campaign activation/protocol scope changed")
    require(row["daemon_cpus"] == DAEMON_CPUS and row["harness_cpus"] == HARNESS_CPUS,
            "predeclared runtime CPU assignments changed")
    require(row["rustfmt"] == subprocess.check_output(["rustfmt", "--version"], text=True).strip(),
            "source formatter differs from frozen derivation")
    return row


def load(output):
    row = manifest(output)
    verify_tree(output / "input", archive_files(output / "qualification.tar"))
    q, r, wire = helpers(output / "input")
    for arm in ("candidate", "private"):
        verify_tree(output / "sources" / arm, expected(output, arm, q))
    return row, q, r, wire


def prepare(args, bars):
    dependency, output = Path(args.qualification_source).resolve(), Path(args.output).resolve()
    require(not output.exists(), "campaign directory must be new")
    require(args.daemon_cpus == DAEMON_CPUS and args.harness_cpus == HARNESS_CPUS,
            "CPU assignments must match the predeclared workload")
    pin = args.base
    require(git(dependency, "rev-parse", "HEAD") == pin and not git(dependency, "status", "--porcelain"),
            "qualification source must be the clean declared input commit")
    require(not git(ROOT, "status", "--porcelain"), "commit terminal harness before freezing")
    head = git(ROOT, "rev-parse", "HEAD")
    # The input supplies the product tree and the qualification harness; this
    # head supplies only its own directory. Both must carry the same
    # qualification harness and driver, or the two derivations would disagree.
    require(git(ROOT, "ls-tree", head, "--", PREFIX), "terminal harness is not committed at this head")
    # Tree ids, each read from its own repository: the input may be a separate
    # clone whose commit this checkout does not have.
    require(all(git(dependency, "rev-parse", f"{pin}:{path}") == git(ROOT, "rev-parse", f"{head}:{path}")
                for path in INPUT_PATHS),
            "input commit and terminal head carry different qualification harnesses")
    output.mkdir(parents=True)
    for source, commit, name, paths in ((dependency, pin, "qualification", []),
                                        (ROOT, head, "terminal", [PREFIX])):
        subprocess.run(["git", "-C", str(source), "archive", "--format=tar", "-o",
                        str(output / f"{name}.tar"), commit, *paths], check=True)
    destination = output / "input"
    destination.mkdir()
    with tarfile.open(output / "qualification.tar") as archive:
        archive.extractall(destination, filter="data")
    q, _, _ = helpers(destination)
    for arm in ("candidate", "private"):
        source = output / "sources" / arm
        source.mkdir(parents=True)
        for name in ("qualification", "terminal"):
            with tarfile.open(output / f"{name}.tar") as archive:
                archive.extractall(source, filter="data")
        for name, data in expected(output, arm, q).items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(data, tuple):
                require(path.is_symlink() and str(path.readlink()) == data[1], "export symlink extraction drift")
            else:
                path.write_bytes(data)
    daemon, driver = q.COMMON.cpu_set(args.daemon_cpus), q.COMMON.cpu_set(args.harness_cpus)
    require(not daemon & driver and daemon | driver <= os.sched_getaffinity(0), "invalid runtime CPU sets")
    q.write_json(output / "campaign.json", {
        "schema": "rustbgpd.evpn-terminal-debt.v1", "head": head,
        "qualification_head": pin, "base": pin,
        "qualification_sha256": q.digest(output / "qualification.tar"),
        "terminal_sha256": q.digest(output / "terminal.tar"),
        "derivation": "pinned qualification derivation, then terminal patches.py from terminal head",
        "production_activation": False, "enhanced_refresh": False, "bars": bars,
        "rustfmt": subprocess.check_output(["rustfmt", "--version"], text=True).strip(),
        "build_toolchain": {name: subprocess.check_output([name, "--version"], text=True).strip()
                            for name in ("rustc", "cargo")},
        "daemon_cpus": args.daemon_cpus, "harness_cpus": args.harness_cpus,
        "timing_window": q.timing_window(args.window_start, args.window_end)})


def build(args):
    output = Path(args.output).resolve()
    manifest_row, q, _, _ = load(output)
    binary = output / "bin"
    binary.mkdir()
    toolchain = {name: subprocess.check_output([name, "--version"], text=True).strip() for name in ("rustc", "cargo")}
    require(toolchain == manifest_row["build_toolchain"], "toolchain changed since source freeze")
    q.write_json(output / "toolchain.json", toolchain)
    env = {key: value for key, value in os.environ.items()
           if key not in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS")}
    for arm, package, target in (("candidate", "rustbgpd", "rustbgpd"),
                                  ("private", "rustbgpd", "rustbgpd"),
                                  ("candidate", "rustbgpd-evpn-load", "evpn-rr-soak")):
        # The caller coordinates the host's two-build limit. Each invocation is
        # serial, pinned, and uses a separate target for each measured arm.
        env["CARGO_TARGET_DIR"] = str(output / f"target-{arm}")
        label = arm if target == "rustbgpd" else "driver"
        # The daemon is a release binary; the driver is a scale harness.
        profile = "release" if target == "rustbgpd" else "scale"
        command = ["taskset", "-c", BUILD_CPUS, "cargo", "build", "--locked", "--profile", profile,
                   "-p", package, "--bin", target, "-j", "8"]
        if target == "rustbgpd":
            command += ["--features", "rustbgpd-transport/bench-internals"]
        # Wait, bounded, for the host's two-build limit instead of failing a
        # partly built campaign on a busy host.
        deadline = time.monotonic() + 1800
        while True:
            roster = subprocess.run(["ps", "-C", "cargo", "-o", "pid="], capture_output=True, text=True)
            require(roster.returncode in (0, 1), "cargo roster unavailable; no build started")
            if len(roster.stdout.split()) < 2:
                break
            require(time.monotonic() < deadline, "two host Cargo processes stayed active; no build started")
            time.sleep(10)
        with (output / f"build-{label}.log").open("x") as log:
            result = subprocess.run(command, cwd=output / "sources" / arm, env=env,
                                    stdout=log, stderr=subprocess.STDOUT)
        (output / f"build-{label}.exit").write_text(f"{result.returncode}\n")
        require(result.returncode == 0, f"{label} build failed; first log retained")
        shutil.copy2(Path(env["CARGO_TARGET_DIR"]) / profile / target,
                     binary / (f"rustbgpd-{arm}" if target == "rustbgpd" else target))
    identities = {path.name: q.digest(path) for path in binary.iterdir()}
    require(identities["rustbgpd-candidate"] != identities["rustbgpd-private"], "identical arms")
    q.write_json(output / "binaries.json", {"head": manifest_row["head"],
                                           "qualification_head": manifest_row["qualification_head"],
                                           "qualification_sha256": manifest_row["qualification_sha256"],
                                           "terminal_sha256": manifest_row["terminal_sha256"],
                                           "toolchain": toolchain, "binaries": identities})
    verify_build(output, manifest_row, q)


def verify_build(output, manifest_row, q):
    receipt = json.loads((output / "binaries.json").read_text())
    require(all(receipt[name] == manifest_row[name] for name in
                ("head", "qualification_head", "qualification_sha256", "terminal_sha256")),
            "build source/archive lineage differs")
    toolchain = json.loads((output / "toolchain.json").read_text())
    require(toolchain == receipt["toolchain"] == manifest_row["build_toolchain"]
            and set(toolchain) == {"rustc", "cargo"}
            and all(type(toolchain[name]) is str and toolchain[name].startswith(name + " ") for name in toolchain),
            "build toolchain receipt differs")
    expected = {"rustbgpd-candidate", "rustbgpd-private", "evpn-rr-soak"}
    identities = receipt["binaries"]
    require(set(identities) == expected and {path.name for path in (output / "bin").iterdir()} == expected,
            "missing/extra built binaries")
    require(all(type(identities[name]) is str and q.digest(output / "bin" / name) == identities[name] for name in expected)
            and identities["rustbgpd-candidate"] != identities["rustbgpd-private"], "built binary changed or arms identical")
    for label in ("candidate", "private", "driver"):
        require((output / f"build-{label}.exit").read_text().strip() == "0"
                and (output / f"build-{label}.log").stat().st_size > 0, "missing/failed independent arm build receipt")
    return identities
