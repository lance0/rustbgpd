#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

repo=$(git rev-parse --show-toplevel)
profiles="$repo/bench/netns-calibration/profiles.json"
verifier="$repo/bench/netns-calibration/verify-receipt.py"
runner="$repo/bench/netns-calibration/run-vm.sh"
guest="$repo/bench/netns-calibration/guest-smoke.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/netns-calibration-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

python3 "$verifier" profiles "$profiles"
python3 "$verifier" source "$repo"

python3 - "$repo" "$profiles" "$verifier" "$tmp" <<'PY'
import copy, csv, hashlib, importlib.util, json, os, pathlib, shutil, subprocess, sys

repo, profiles_path, verifier_path, tmp = map(pathlib.Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("netns_verify", verifier_path)
verify = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(verify)
profiles = verify.verify_profiles(profiles_path)
h = "a" * 64

def run(*args):
    return subprocess.run([sys.executable, str(verifier_path), *map(str, args)], capture_output=True, text=True)

def expect(ok, name, *args):
    result = run(*args)
    assert (result.returncode == 0) == ok, (name, result.stdout, result.stderr)

def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

# Profile mutations must not turn the data file into policy.
for name, mutate in {
    "mutable-url": lambda p: p["profiles"][0]["source"].update(url=p["profiles"][0]["source"]["url"].replace("release-20260826", "current")),
    "wrong-image": lambda p: p["profiles"][0]["source"].update(sha256=h),
    "mixed-kernel": lambda p: p["profiles"][0]["guest"].update(kernel_release=p["profiles"][1]["guest"]["kernel_release"]),
    "extra-profile": lambda p: p["profiles"].append(copy.deepcopy(p["profiles"][0])),
    "qemu-drift": lambda p: p["host_tools"]["qemu_system_x86"].update(version="8.2.3"),
    "qemu-path-drift": lambda p: p["host_tools"]["qemu_system_x86"].update(path="/opt/qemu-system-x86_64"),
}.items():
    candidate = copy.deepcopy(profiles); mutate(candidate)
    path = tmp / f"profiles-{name}.json"; write_json(path, candidate)
    expect(False, name, "profiles", path)

profile = profiles["profiles"][0]
plan = {
    "args": verify.expected_plan(profile, profiles["vm"], profiles["host_tools"]),
    "profile": profile["name"],
    "schema": 1,
}
plan_path = tmp / "plan.json"; write_json(plan_path, plan)
expect(True, "valid-plan", "plan", profiles_path, plan_path)
for name, mutate in {
    "plan-path-shadow": lambda p: p["args"].__setitem__(0, "qemu-system-x86_64"),
    "plan-network": lambda p: p["args"].__setitem__(p["args"].index("none", p["args"].index("-nic")), "user"),
    "plan-no-snapshot": lambda p: p["args"].remove("-snapshot"),
    "plan-tcg": lambda p: p["args"].__setitem__(p["args"].index("pc-q35-8.2,accel=kvm"), "pc-q35-8.2,accel=tcg"),
    "plan-cpu": lambda p: p["args"].__setitem__(p["args"].index("host", p["args"].index("-cpu")), "max"),
    "plan-memory": lambda p: p["args"].__setitem__(p["args"].index("2048"), "4096"),
    "plan-home-share": lambda p: p["args"].__setitem__(p["args"].index("local,path=<PAYLOAD>,mount_tag=payload,security_model=none,readonly=on"), "local,path=/home/user,mount_tag=payload,security_model=none,readonly=on"),
    "plan-writable-payload": lambda p: p["args"].__setitem__(p["args"].index("local,path=<PAYLOAD>,mount_tag=payload,security_model=none,readonly=on"), "local,path=<PAYLOAD>,mount_tag=payload,security_model=none"),
    "plan-writable-seed": lambda p: p["args"].__setitem__(p["args"].index("file=<SEED>,format=raw,media=cdrom,readonly=on"), "file=<SEED>,format=raw,media=cdrom"),
}.items():
    candidate = copy.deepcopy(plan); mutate(candidate)
    path = tmp / f"plan-{name}.json"; write_json(path, candidate)
    expect(False, name, "plan", profiles_path, path)

argv = verify.render_argv(
    profile,
    profiles["vm"],
    profiles["host_tools"],
    pathlib.Path("/images/base.img"),
    pathlib.Path("/staging/seed.img"),
    pathlib.Path("/staging/payload"),
    pathlib.Path("/receipts/guest"),
)
assert argv[0] == "/usr/bin/qemu-system-x86_64"
assert "file=/images/base.img,format=qcow2,if=virtio" in argv
assert "local,path=/staging/payload,mount_tag=payload,security_model=none,readonly=on" in argv
assert not any("<" in item or ">" in item for item in argv)
shadow = tmp / "path-shadow"
shadow.mkdir()
marker = tmp / "path-shadow-ran"
for command in ("qemu-system-x86_64", "cloud-localds"):
    executable = shadow / command
    executable.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 99\n")
    executable.chmod(0o755)
shadow_env = {**os.environ, "PATH": f"{shadow}:{os.environ['PATH']}"}
selected = subprocess.run(
    [sys.executable, str(verifier_path), "select", str(profiles_path), profile["name"]],
    capture_output=True,
    text=True,
    env=shadow_env,
)
assert selected.returncode == 0, selected.stderr
assert selected.stdout.splitlines()[2:] == [
    "/usr/bin/qemu-system-x86_64",
    "/usr/bin/cloud-localds",
]
rendered = subprocess.run(
    [
        sys.executable,
        str(verifier_path),
        "argv",
        str(profiles_path),
        profile["name"],
        "/images/base.img",
        "/staging/seed.img",
        "/staging/payload",
        "/receipts/guest",
    ],
    capture_output=True,
    env=shadow_env,
)
assert rendered.returncode == 0, rendered.stderr
assert rendered.stdout.split(b"\0") == [*(item.encode() for item in argv), b""]
assert not marker.exists()
expect(
    False,
    "relative-qemu-path",
    "argv",
    profiles_path,
    profile["name"],
    "relative.img",
    "/seed.img",
    "/payload",
    "/guest",
)

def valid_receipt(path):
    (path / "guest").mkdir(parents=True)
    config = b"CONFIG_NET_NS=y\nCONFIG_BRIDGE=y\n"
    (path / "guest/kernel.config").write_bytes(config)
    write_json(path / "request.json", {
        "git": {"commit": "b"*40, "dirty": False, "origin_main": "b"*40, "status_sha256": verify.EMPTY_SHA256},
        "image": profile["source"], "profile": profile["name"], "schema": 1,
        "sources": {name: verify.sha256(repo / rel) for name, rel in verify.SOURCE_PATHS.items()},
    })
    write_json(path / "plan.json", plan)
    write_json(path / "host.json", {
        "cloud_image_utils": {
            "approved_deb_sha256": profiles["host_tools"]["cloud_image_utils"]["deb_sha256"],
            "binary_sha256": h,
            "dpkg_verified": True,
            "package": profiles["host_tools"]["cloud_image_utils"]["package"],
            "package_version": profiles["host_tools"]["cloud_image_utils"]["version"],
            "path": profiles["host_tools"]["cloud_image_utils"]["path"],
        },
        "cpu_model": "fixture cpu", "host_kernel": "Linux fixture x86_64", "kvm_access": True,
        "profile": profile["name"],
        "qemu_system_x86": {
            "approved_deb_sha256": profiles["host_tools"]["qemu_system_x86"]["deb_sha256"],
            "binary_sha256": h,
            "dpkg_verified": True,
            "package": profiles["host_tools"]["qemu_system_x86"]["package"],
            "package_version": profiles["host_tools"]["qemu_system_x86"]["version"],
            "path": profiles["host_tools"]["qemu_system_x86"]["path"],
            "version_output": "QEMU emulator version 8.2.2",
        },
        "schema": 1,
    })
    header = ["sample","epoch_s","load1","pswpin","pswpout","governors","performance_governors","governor_count","competitors","quiet","failed_dimensions","original_attempt"]
    with (path / "quiet.tsv").open("w", newline="") as stream:
        writer = csv.writer(stream, delimiter="\t", lineterminator="\n"); writer.writerow(header)
        writer.writerow([1,100,0.2,0,0,"performance",1,1,"none","true","none",1])
        writer.writerow([2,130,0.3,0,0,"performance",1,1,"none","true","none",2])
    (path / "console.log").write_text("generic guest console\n")
    write_json(path / "guest/guest.json", {
        "after_netns_sha256": h, "before_netns_sha256": h, "bridge_binary_sha256": h,
        "ip_binary_sha256": h, "ip_version_output": "ip utility fixture",
        "iproute2_package_version": profile["guest"]["iproute2_package_version"],
        "kernel_config_sha256": hashlib.sha256(config).hexdigest(),
        "kernel_package_version": profile["guest"]["kernel_package_version"],
        "kernel_release": profile["guest"]["kernel_release"], "profile": profile["name"], "schema": 1,
        "smoke": {"bridge_vlan_filtering": True,"deterministic_cleanup": True,"netns": True,"veth": True,"vlan_10": True,"vlan_20": True},
        "status": "pass", "uid": 0,
    })

base = tmp / "receipt-base"; valid_receipt(base)
expect(True, "valid-finalize", "receipt", profiles_path, base, "--write-manifest")
expect(True, "valid-sealed", "receipt", profiles_path, base)
unsealed = tmp / "receipt-unsuccessful"; shutil.copytree(base, unsealed)
(unsealed / "SHA256SUMS").unlink()
expect(False, "unsuccessful-receipt-is-unsealed", "receipt", profiles_path, unsealed)

def receipt_mutation(name, mutate):
    path = tmp / f"receipt-{name}"; shutil.copytree(base, path)
    (path / "SHA256SUMS").unlink()
    mutate(path)
    expect(False, name, "receipt", profiles_path, path, "--write-manifest")

def mutate_json(path, relative, mutate):
    value = json.loads((path / relative).read_text())
    mutate(value)
    write_json(path / relative, value)

def mutate_quiet(path, mutate):
    quiet = path / "quiet.tsv"
    with quiet.open(newline="") as stream:
        rows = list(csv.reader(stream, delimiter="\t"))
    mutate(rows)
    with quiet.open("w", newline="") as stream:
        csv.writer(stream, delimiter="\t", lineterminator="\n").writerows(rows)

receipt_mutation("wrong-kernel", lambda p: (lambda x: (x.update(kernel_release="9.9.9"), write_json(p/"guest/guest.json",x)))(json.loads((p/"guest/guest.json").read_text())))
receipt_mutation("mixed-profile", lambda p: (lambda x: (x.update(profile=profiles["profiles"][1]["name"]), write_json(p/"guest/guest.json",x)))(json.loads((p/"guest/guest.json").read_text())))
receipt_mutation("tool-drift", lambda p: mutate_json(p, "host.json", lambda x: x["qemu_system_x86"].update(package_version="8.2.3")))
receipt_mutation("tool-path-drift", lambda p: mutate_json(p, "host.json", lambda x: x["qemu_system_x86"].update(path="qemu-system-x86_64")))
receipt_mutation("tool-unverified", lambda p: mutate_json(p, "host.json", lambda x: x["qemu_system_x86"].update(dpkg_verified=False)))
receipt_mutation("no-kvm", lambda p: (lambda x: (x.update(kvm_access=False), write_json(p/"host.json",x)))(json.loads((p/"host.json").read_text())))
receipt_mutation("dirty", lambda p: (lambda x: (x["git"].update(dirty=True), write_json(p/"request.json",x)))(json.loads((p/"request.json").read_text())))
receipt_mutation("image-drift", lambda p: mutate_json(p, "request.json", lambda x: x["image"].update(sha256="c"*64)))
receipt_mutation("commit-drift", lambda p: mutate_json(p, "request.json", lambda x: x["git"].update(origin_main="c"*40)))
receipt_mutation("source-drift", lambda p: mutate_json(p, "request.json", lambda x: x["sources"].update(guest="c"*64)))
receipt_mutation("config-drift", lambda p: (p/"guest/kernel.config").write_text("changed\n"))
receipt_mutation("residue", lambda p: (lambda x: (x.update(after_netns_sha256="c"*64), write_json(p/"guest/guest.json",x)))(json.loads((p/"guest/guest.json").read_text())))
receipt_mutation("quiet-spacing", lambda p: mutate_quiet(p, lambda rows: rows[2].__setitem__(1, "129")))
receipt_mutation("quiet-swap", lambda p: mutate_quiet(p, lambda rows: rows[2].__setitem__(3, "1")))
receipt_mutation("quiet-governor", lambda p: mutate_quiet(p, lambda rows: rows[1].__setitem__(5, "powersave")))
receipt_mutation("quiet-extra-column", lambda p: mutate_quiet(p, lambda rows: [row.append("extra") for row in rows]))
receipt_mutation("extra", lambda p: (p/"extra.txt").write_text("extra\n"))
receipt_mutation("missing", lambda p: (p/"console.log").unlink())
receipt_mutation("oversize", lambda p: (p/"console.log").write_bytes(b"x"*(2*1024*1024+1)))
receipt_mutation("unsanitized", lambda p: (p/"console.log").write_text("/home/private/token\n"))

symlink = tmp / "receipt-symlink"; shutil.copytree(base, symlink); (symlink/"SHA256SUMS").unlink()
(symlink/"console.log").unlink(); (symlink/"console.log").symlink_to("request.json")
expect(False, "symlink", "receipt", profiles_path, symlink, "--write-manifest")

tampered = tmp / "receipt-manifest"; shutil.copytree(base, tampered)
(tampered/"console.log").write_text("tampered\n")
expect(False, "manifest", "receipt", profiles_path, tampered)
PY

# Exercise the runner's real cleanup functions without booting a VM. Every
# unsuccessful exit must destroy the final seal, including image drift that is
# discovered only by the EXIT recheck.
cleanup_lib="$tmp/cleanup-functions.sh"
sed -n '/^verify_pinned_image_unchanged() {/,/^trap cleanup EXIT$/p' "$runner" |
    sed '$d' >"$cleanup_lib"
bash -n "$cleanup_lib"
for mode in failed-command image-drift image-disappeared; do
    receipt="$tmp/receipt-cleanup-$mode"
    image="$tmp/image-cleanup-$mode"
    staging="$tmp/staging-cleanup-$mode"
    cp -a "$tmp/receipt-base" "$receipt"
    printf 'pinned image fixture\n' >"$image"
    image_sha=$(sha256sum -- "$image"); image_sha=${image_sha%% *}
    mkdir "$staging"
    case $mode in
        image-drift) printf 'drift\n' >>"$image" ;;
        image-disappeared) rm -f -- "$image" ;;
    esac
    set +e
    (
        set -uo pipefail
        export IMAGE=$image
        export IMAGE_SHA_BEFORE=$image_sha
        export OUTPUT=$receipt
        export TMP_DIR=$staging
        export QEMU_GROUP_PID=''
        # shellcheck disable=SC1090 # Generated from the reviewed runner functions above.
        source "$cleanup_lib"
        if [ "$mode" = failed-command ]; then
            false
        fi
        cleanup
    ) >/dev/null 2>&1
    cleanup_rc=$?
    set -e
    [ "$cleanup_rc" -ne 0 ]
    [ ! -e "$receipt/SHA256SUMS" ]
    [ ! -e "$staging" ]
    if python3 "$verifier" receipt "$profiles" "$receipt" >/dev/null 2>&1; then
        echo "false green: unsuccessful cleanup left a verifier-green receipt: $mode" >&2
        exit 1
    fi
done

# The guest's injected post-create failure must still run its deletion trap.
fakebin="$tmp/fakebin"
mkdir "$fakebin"
state="$tmp/fake-netns-state"
cat >"$fakebin/ip" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
state=${RUSTBGPD_FAKE_NETNS_STATE:?}
if [ "$1" = netns ] && [ "$2" = list ]; then
    [ ! -e "$state" ] || echo rustbgpd-cal-smoke
elif [ "$1" = netns ] && [ "$2" = add ]; then
    touch "$state"
elif [ "$1" = netns ] && { [ "$2" = del ] || [ "$2" = delete ]; }; then
    rm -f "$state"
else
    echo "unexpected fake ip invocation: $*" >&2
    exit 1
fi
SH
chmod +x "$fakebin/ip"
mkdir "$tmp/guest-out"
set +e
PATH="$fakebin:$PATH" RUSTBGPD_FAKE_NETNS_STATE="$state" \
    RUSTBGPD_GUEST_SMOKE_TEST_FAIL_AFTER_CREATE=1 \
    "$guest" --inside "$tmp/guest-out" >/dev/null 2>&1
guest_rc=$?
set -e
[ "$guest_rc" -eq 97 ]
[ ! -e "$state" ]

# Mutating any load-bearing lifecycle anchor must fail the independent source checker.
for anchor in root trap package qemu-path cloud-path cloud-exec qemu-exec lock quiet render timeout qemu image-preseal image-exit unseal cleanup-exit verify guest-trap guest-delete guest-readonly guest-env; do
    candidate_runner="$tmp/runner-$anchor.sh"
    candidate_guest="$tmp/guest-$anchor.sh"
    cp "$runner" "$candidate_runner"
    cp "$guest" "$candidate_guest"
    # shellcheck disable=SC2016 # Match candidate literal variable references.
    case $anchor in
        root) sed -i 's/if \[ "$EUID" -eq 0 \]/if [ 0 -eq 1 ]/' "$candidate_runner" ;;
        trap) sed -i '/trap cleanup EXIT/d' "$candidate_runner" ;;
        package) sed -i '/dpkg --verify qemu-system-x86 cloud-image-utils/d' "$candidate_runner" ;;
        qemu-path) sed -i 's/QEMU_BIN=${PROFILE_FIELDS\[2\]}/QEMU_BIN=$(command -v qemu-system-x86_64)/' "$candidate_runner" ;;
        cloud-path) sed -i 's/CLOUD_BIN=${PROFILE_FIELDS\[3\]}/CLOUD_BIN=$(command -v cloud-localds)/' "$candidate_runner" ;;
        cloud-exec) sed -i 's/"$CLOUD_BIN" --network-config/cloud-localds --network-config/' "$candidate_runner" ;;
        qemu-exec) sed -i 's/"${QEMU_COMMAND\[@\]}" >"$OUTPUT\/console.log"/qemu-system-x86_64 "${QEMU_COMMAND[@]:1}" >"$OUTPUT\/console.log"/' "$candidate_runner" ;;
        lock) sed -i '/^acquire_rustbgpd_host_lock$/d' "$candidate_runner" ;;
        quiet) sed -i '/^wait_for_rustbgpd_quiet_host/d' "$candidate_runner" ;;
        render) sed -i '/python3 "$VERIFIER" argv/d' "$candidate_runner" ;;
        timeout) sed -i 's/TIMEOUT_SECONDS=300/TIMEOUT_SECONDS=301/' "$candidate_runner" ;;
        qemu) sed -i 's/setsid timeout --signal=TERM/setsid timeout --signal=INT/' "$candidate_runner" ;;
        image-preseal) sed -i '/^verify_pinned_image_unchanged "pre-seal"$/d' "$candidate_runner" ;;
        image-exit) sed -i '/verify_pinned_image_unchanged "exit"/d' "$candidate_runner" ;;
        unseal) sed -i '/rm -f -- "$OUTPUT\/SHA256SUMS"/d' "$candidate_runner" ;;
        cleanup-exit) sed -i 's/exit "$rc"/exit 0/' "$candidate_runner" ;;
        verify) sed -i '/python3 "$VERIFIER" receipt/d' "$candidate_runner" ;;
        guest-trap) sed -i '/trap cleanup_guest EXIT/d' "$candidate_guest" ;;
        guest-delete) sed -i '/ip netns delete "$NETNS"$/d' "$candidate_guest" ;;
        guest-readonly) sed -i 's/,ro payload/ payload/' "$candidate_guest" ;;
        guest-env) sed -i 's/env -i PATH=/env PATH=/' "$candidate_guest" ;;
    esac
    if python3 "$verifier" source "$repo" --runner "$candidate_runner" --guest "$candidate_guest" \
        >/dev/null 2>&1; then
        echo "false green: source mutation accepted: $anchor" >&2
        exit 1
    fi
done

echo "PASS: pinned-kernel netns VM offline contract and destructive mutations"
