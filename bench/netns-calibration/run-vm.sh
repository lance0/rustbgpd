#!/usr/bin/env bash
# Run one closed pinned-kernel netns smoke in an isolated, networkless QEMU VM.
set -euo pipefail

if [ "$EUID" -eq 0 ]; then
    echo "run pinned-kernel calibration as a normal user, never root" >&2
    exit 1
fi

for tool in python3 realpath setsid sha256sum timeout; do
    command -v "$tool" >/dev/null || { echo "required tool is missing: $tool" >&2; exit 1; }
done

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/../.." && pwd)
PROFILES="$SCRIPT_DIR/profiles.json"
VERIFIER="$SCRIPT_DIR/verify-receipt.py"
GUEST="$SCRIPT_DIR/guest-smoke.sh"
SKEW="$SCRIPT_DIR/raw_bridge_skew.py"
# shellcheck disable=SC1091 # REPO is resolved from this tracked script.
source "$REPO/tests/soak/host-lock.sh"
# shellcheck disable=SC1091 # REPO is resolved from this tracked script.
source "$REPO/bench/scale/host-quiet.sh"

usage() {
    echo "usage: $0 [--raw-bridge-skew CAMPAIGN] PROFILE PINNED_CLOUD_IMAGE FRESH_RECEIPT_DIR" >&2
}

CAMPAIGN=''
if [ "$#" -eq 5 ] && [ "$1" = --raw-bridge-skew ]; then
    CAMPAIGN=$2
    shift 2
fi
if [ "$#" -ne 3 ]; then
    usage
    exit 2
fi
PROFILE=$1
IMAGE=$2
OUTPUT=$3

mapfile -t PROFILE_FIELDS < <(python3 "$VERIFIER" select "$PROFILES" "$PROFILE")
[ "${#PROFILE_FIELDS[@]}" -eq 4 ] || { echo "profile selection failed" >&2; exit 1; }
EXPECTED_IMAGE_SHA=${PROFILE_FIELDS[0]}
EXPECTED_IMAGE_URL=${PROFILE_FIELDS[1]}
QEMU_BIN=${PROFILE_FIELDS[2]}
CLOUD_BIN=${PROFILE_FIELDS[3]}
CAMPAIGN_TIMEOUT_SECONDS=''
if [ -n "$CAMPAIGN" ]; then
    CAMPAIGN_TIMEOUT_SECONDS=$(python3 "$VERIFIER" skew-select "$PROFILES" "$CAMPAIGN")
fi

if [ ! -f "$IMAGE" ] || [ -L "$IMAGE" ] || [ ! -r "$IMAGE" ]; then
    echo "pinned cloud image must be a readable regular file: $IMAGE" >&2
    exit 1
fi
IMAGE=$(realpath -- "$IMAGE")
IMAGE_SHA_BEFORE=$(sha256sum -- "$IMAGE"); IMAGE_SHA_BEFORE=${IMAGE_SHA_BEFORE%% *}
[ "$IMAGE_SHA_BEFORE" = "$EXPECTED_IMAGE_SHA" ] || {
    echo "pinned cloud image SHA-256 mismatch for $EXPECTED_IMAGE_URL" >&2
    exit 1
}

if [ -e "$OUTPUT" ] || [ -L "$OUTPUT" ]; then
    echo "receipt directory must not already exist: $OUTPUT" >&2
    exit 1
fi
OUTPUT_PARENT=$(dirname -- "$OUTPUT")
if [ ! -d "$OUTPUT_PARENT" ] || [ -L "$OUTPUT_PARENT" ] || [ ! -w "$OUTPUT_PARENT" ]; then
    echo "receipt parent must be an existing writable real directory: $OUTPUT_PARENT" >&2
    exit 1
fi
OUTPUT_PARENT=$(realpath -- "$OUTPUT_PARENT")
OUTPUT="$OUTPUT_PARENT/$(basename -- "$OUTPUT")"
mkdir -m 700 -- "$OUTPUT"
mkdir -m 700 -- "$OUTPUT/guest"

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustbgpd-netns-calibration.XXXXXX")
QEMU_GROUP_PID=''
verify_pinned_image_unchanged() {
    local phase=$1 image_after=''
    if [ ! -f "$IMAGE" ] || [ -L "$IMAGE" ]; then
        echo "pinned cloud image disappeared during the run ($phase)" >&2
        return 1
    fi
    image_after=$(sha256sum -- "$IMAGE" 2>/dev/null) || {
        echo "pinned cloud image could not be hashed after the run ($phase)" >&2
        return 1
    }
    image_after=${image_after%% *}
    if [ "$image_after" != "$IMAGE_SHA_BEFORE" ]; then
        echo "pinned cloud image changed during the run ($phase)" >&2
        return 1
    fi
    return 0
}
cleanup() {
    local rc=$?
    trap - EXIT
    if [ -n "$QEMU_GROUP_PID" ]; then
        kill -TERM -- "-$QEMU_GROUP_PID" >/dev/null 2>&1 || true
        wait "$QEMU_GROUP_PID" >/dev/null 2>&1 || true
    fi
    if ! verify_pinned_image_unchanged "exit"; then
        rc=1
    fi
    if ! rm -rf -- "$TMP_DIR"; then
        echo "failed to remove pinned-kernel calibration staging" >&2
        rc=1
    fi
    if [ "$rc" -ne 0 ]; then
        rm -f -- "$OUTPUT/SHA256SUMS" || rc=1
        if [ -e "$OUTPUT/SHA256SUMS" ] || [ -L "$OUTPUT/SHA256SUMS" ]; then
            echo "failed to unseal unsuccessful pinned-kernel receipt" >&2
            rc=1
        fi
    fi
    exit "$rc"
}
trap cleanup EXIT

verify_dpkg_owned_tool() {
    local package=$1 path=$2 item owned=false
    if [ ! -f "$path" ] || [ -L "$path" ] || [ ! -x "$path" ]; then
        echo "approved package tool is not an executable regular file: $path" >&2
        return 1
    fi
    while IFS= read -r item; do
        if [ "$item" = "$path" ]; then
            owned=true
        fi
    done < <(/usr/bin/dpkg-query -L "$package")
    [ "$owned" = true ] || {
        echo "$path is not owned by the verified $package package" >&2
        return 1
    }
}
verify_dpkg_owned_tool qemu-system-x86 "$QEMU_BIN"
verify_dpkg_owned_tool cloud-image-utils "$CLOUD_BIN"
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
    echo "KVM access is required; timing receipts may not fall back to TCG" >&2
    exit 1
fi
QEMU_PACKAGE_VERSION=$(/usr/bin/dpkg-query -W -f='${Version}' qemu-system-x86)
CLOUD_PACKAGE_VERSION=$(/usr/bin/dpkg-query -W -f='${Version}' cloud-image-utils)
[ "$QEMU_PACKAGE_VERSION" = "1:8.2.2+ds-0ubuntu1.18" ] || {
    echo "qemu-system-x86 package version drift: $QEMU_PACKAGE_VERSION" >&2
    exit 1
}
[ "$CLOUD_PACKAGE_VERSION" = "0.33-1" ] || {
    echo "cloud-image-utils package version drift: $CLOUD_PACKAGE_VERSION" >&2
    exit 1
}
DPKG_VERIFY=$(/usr/bin/dpkg --verify qemu-system-x86 cloud-image-utils)
[ -z "$DPKG_VERIFY" ] || {
    echo "installed QEMU/cloud-image-utils files differ from package metadata" >&2
    exit 1
}

python3 "$VERIFIER" profiles "$PROFILES"
python3 "$VERIFIER" source "$REPO"
GIT_COMMIT=$(git -C "$REPO" rev-parse HEAD)
ORIGIN_MAIN=$(git -C "$REPO" rev-parse origin/main)
GIT_STATUS=$(git -C "$REPO" status --porcelain=v1 --untracked-files=all)
GIT_STATUS_SHA=$(printf '%s' "$GIT_STATUS" | sha256sum | cut -d' ' -f1)
if [ "$GIT_COMMIT" != "$ORIGIN_MAIN" ] || [ -n "$GIT_STATUS" ]; then
    echo "publishable calibration requires a clean checkout at exact origin/main" >&2
    exit 1
fi

PAYLOAD_DIR="$TMP_DIR/payload"
mkdir -m 700 -- "$PAYLOAD_DIR"
python3 - "$REPO" "$PROFILE" "$EXPECTED_IMAGE_URL" "$EXPECTED_IMAGE_SHA" \
    "$GIT_COMMIT" "$ORIGIN_MAIN" "$GIT_STATUS_SHA" "$CAMPAIGN" \
    "$OUTPUT/request.json" <<'PY'
import hashlib, json, pathlib, sys
repo = pathlib.Path(sys.argv[1])
profile, image_url, image_sha, commit, origin_main, status_sha, campaign, output = sys.argv[2:]
paths = {
    "guest": "bench/netns-calibration/guest-smoke.sh",
    "host_lock": "tests/soak/host-lock.sh",
    "host_quiet": "bench/scale/host-quiet.sh",
    "profiles": "bench/netns-calibration/profiles.json",
    "runner": "bench/netns-calibration/run-vm.sh",
    "verifier": "bench/netns-calibration/verify-receipt.py",
}
if campaign:
    paths["raw_bridge_skew"] = "bench/netns-calibration/raw_bridge_skew.py"
payload = {
    "git": {"commit": commit, "dirty": False, "origin_main": origin_main, "status_sha256": status_sha},
    "image": {"sha256": image_sha, "url": image_url},
    "profile": profile,
    "schema": 1,
    "sources": {name: hashlib.sha256((repo / path).read_bytes()).hexdigest() for name, path in paths.items()},
}
if campaign:
    payload["raw_bridge_skew"] = {"profile": campaign}
pathlib.Path(output).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
cp -- "$PROFILES" "$GUEST" "$OUTPUT/request.json" "$PAYLOAD_DIR/"
if [ -n "$CAMPAIGN" ]; then
    cp -- "$SKEW" "$PAYLOAD_DIR/"
fi
chmod 500 "$PAYLOAD_DIR/guest-smoke.sh"
chmod 400 "$PAYLOAD_DIR/profiles.json" "$PAYLOAD_DIR/request.json"

QEMU_BIN_SHA=$(sha256sum -- "$QEMU_BIN"); QEMU_BIN_SHA=${QEMU_BIN_SHA%% *}
CLOUD_BIN_SHA=$(sha256sum -- "$CLOUD_BIN"); CLOUD_BIN_SHA=${CLOUD_BIN_SHA%% *}
QEMU_VERSION=$($QEMU_BIN --version | head -n 1)
CPU_MODEL=$(awk -F: '$1 ~ /^model name[[:space:]]*$/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}' /proc/cpuinfo)
HOST_KERNEL=$(uname -srmo)
python3 - "$OUTPUT/host.json" "$PROFILE" "$QEMU_BIN" "$QEMU_PACKAGE_VERSION" \
    "$QEMU_BIN_SHA" "$QEMU_VERSION" "$CLOUD_BIN" "$CLOUD_PACKAGE_VERSION" \
    "$CLOUD_BIN_SHA" "$CPU_MODEL" "$HOST_KERNEL" <<'PY'
import json, pathlib, sys
(
    output, profile, qemu_path, qemu_package, qemu_sha, qemu_version,
    cloud_path, cloud_package, cloud_sha, cpu_model, host_kernel,
) = sys.argv[1:]
payload = {
    "cloud_image_utils": {
        "binary_sha256": cloud_sha,
        "approved_deb_sha256": "c4203167b5f2ccc8d7e2ff66f6ed5bb55d1ce467511d27732b91e1389e15cd9e",
        "dpkg_verified": True,
        "package": "cloud-image-utils",
        "package_version": cloud_package,
        "path": cloud_path,
    },
    "cpu_model": cpu_model,
    "host_kernel": host_kernel,
    "kvm_access": True,
    "profile": profile,
    "qemu_system_x86": {
        "binary_sha256": qemu_sha,
        "approved_deb_sha256": "14602e262627adac030329d2cecfee5f6c0938b34566ff2ea2d4c9a9eb02430d",
        "dpkg_verified": True,
        "package": "qemu-system-x86",
        "package_version": qemu_package,
        "path": qemu_path,
        "version_output": qemu_version,
    },
    "schema": 1,
}
pathlib.Path(output).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY

acquire_rustbgpd_host_lock
wait_for_rustbgpd_quiet_host "$OUTPUT/quiet.tsv"

cat >"$TMP_DIR/meta-data" <<EOF
instance-id: rustbgpd-netns-calibration-$PROFILE-$GIT_COMMIT
local-hostname: rustbgpd-calibration
EOF
cat >"$TMP_DIR/network-config" <<'EOF'
version: 2
ethernets: {}
EOF
SEED="$TMP_DIR/seed.img"
"$CLOUD_BIN" --network-config="$TMP_DIR/network-config" \
    "$SEED" "$PAYLOAD_DIR/guest-smoke.sh" "$TMP_DIR/meta-data"

python3 - "$PROFILES" "$PROFILE" "$OUTPUT/plan.json" <<'PY'
import importlib.util, json, pathlib, sys
profiles_path, profile_name, output = map(pathlib.Path, (sys.argv[1], sys.argv[2], sys.argv[3]))
spec = importlib.util.spec_from_file_location("netns_verify", profiles_path.parent / "verify-receipt.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
profiles = module.verify_profiles(profiles_path)
profile = module.selected_profile(profiles, str(profile_name))
payload = {
    "args": module.expected_plan(profile, profiles["vm"], profiles["host_tools"]),
    "profile": str(profile_name),
    "schema": 1,
}
output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
python3 "$VERIFIER" plan "$PROFILES" "$OUTPUT/plan.json"

python3 "$VERIFIER" argv "$PROFILES" "$PROFILE" "$IMAGE" "$SEED" \
    "$PAYLOAD_DIR" "$OUTPUT/guest" >"$TMP_DIR/qemu-argv.nul"
mapfile -d '' -t QEMU_COMMAND <"$TMP_DIR/qemu-argv.nul"
[ "${QEMU_COMMAND[0]}" = "$QEMU_BIN" ] || {
    echo "QEMU command rendering failed closed" >&2
    exit 1
}
TIMEOUT_SECONDS=300
if [ -n "$CAMPAIGN" ]; then
    TIMEOUT_SECONDS=$CAMPAIGN_TIMEOUT_SECONDS
fi
setsid timeout --signal=TERM --kill-after=10s "${TIMEOUT_SECONDS}s" \
    "${QEMU_COMMAND[@]}" >"$OUTPUT/console.log" 2>&1 &
QEMU_GROUP_PID=$!
set +e
wait "$QEMU_GROUP_PID"
QEMU_RC=$?
set -e
QEMU_GROUP_PID=''
[ "$QEMU_RC" -eq 0 ] || {
    echo "pinned-kernel VM failed with status $QEMU_RC" >&2
    exit 1
}

verify_pinned_image_unchanged "pre-seal"
python3 "$VERIFIER" receipt "$PROFILES" "$OUTPUT" --write-manifest
echo "pinned-kernel netns smoke passed: $OUTPUT"
