#!/usr/bin/env bash
# cloud-init user-data and in-guest smoke for the pinned-kernel VM harness.
set -euo pipefail

NETNS=rustbgpd-cal-smoke
NETNS_CREATED=false

cleanup_guest() {
    local rc=$?
    if [ "$NETNS_CREATED" = true ]; then
        ip netns del "$NETNS" >/dev/null 2>&1 || rc=1
        NETNS_CREATED=false
    fi
    return "$rc"
}

inside_guest() {
    if [ "$#" -ne 1 ]; then
        echo "usage: guest-smoke.sh --inside RECEIPT_DIR" >&2
        return 2
    fi
    local output=$1 before after kernel package_kernel package_iproute
    local ip_path bridge_path ip_hash bridge_hash config_hash ip_version profile
    if [ "${RUSTBGPD_GUEST_SMOKE_TEST_FAIL_AFTER_CREATE:-}" != 1 ]; then
        [ "$(id -u)" -eq 0 ] || { echo "guest smoke must run as root" >&2; return 1; }
    fi
    if [ ! -d "$output" ] || [ -L "$output" ]; then
        echo "bad guest receipt directory" >&2
        return 1
    fi
    if [ -e "$output/guest.json" ] || [ -e "$output/kernel.config" ]; then
        echo "guest receipt directory is not fresh" >&2
        return 1
    fi
    if [ "${RUSTBGPD_GUEST_SMOKE_TEST_FAIL_AFTER_CREATE:-}" != 1 ]; then
        if [ ! -r /mnt/payload/profiles.json ] || [ ! -r /mnt/payload/request.json ]; then
            echo "guest payload is incomplete" >&2
            return 1
        fi
    fi

    before=$(ip netns list | LC_ALL=C sort)
    trap cleanup_guest EXIT
    ip netns add "$NETNS"
    NETNS_CREATED=true
    if [ "${RUSTBGPD_GUEST_SMOKE_TEST_FAIL_AFTER_CREATE:-}" = 1 ]; then
        return 97
    fi

    ip -n "$NETNS" link add rbgpbr0 type bridge vlan_filtering 1
    ip -n "$NETNS" link add rbgpce10 type veth peer name rgbph10
    ip -n "$NETNS" link add rbgpce20 type veth peer name rgbph20
    ip -n "$NETNS" link set rbgpce10 master rbgpbr0
    ip -n "$NETNS" link set rbgpce20 master rbgpbr0
    ip netns exec "$NETNS" bridge vlan add dev rbgpce10 vid 10 pvid untagged
    ip netns exec "$NETNS" bridge vlan add dev rbgpce20 vid 20 pvid untagged
    ip -n "$NETNS" link set rbgpbr0 up
    ip -n "$NETNS" link set rbgpce10 up
    ip -n "$NETNS" link set rbgpce20 up
    # shellcheck disable=SC2016 # Expansion belongs to the in-netns shell.
    ip netns exec "$NETNS" sh -c \
        '[ "$(cat /sys/class/net/rbgpbr0/bridge/vlan_filtering)" = 1 ]'
    ip netns exec "$NETNS" bridge vlan show dev rbgpce10 | grep -Eq '(^|[[:space:]])10([[:space:]]|$)'
    ip netns exec "$NETNS" bridge vlan show dev rbgpce20 | grep -Eq '(^|[[:space:]])20([[:space:]]|$)'

    ip netns delete "$NETNS"
    NETNS_CREATED=false
    trap - EXIT
    after=$(ip netns list | LC_ALL=C sort)
    [ "$after" = "$before" ] || { echo "guest netns inventory changed" >&2; return 1; }

    kernel=$(uname -r)
    [ -r "/boot/config-$kernel" ] || { echo "guest kernel config is unavailable" >&2; return 1; }
    cp -- "/boot/config-$kernel" "$output/kernel.config.tmp"
    mv -- "$output/kernel.config.tmp" "$output/kernel.config"
    package_kernel=$(dpkg-query -W -f='${Version}' "linux-image-$kernel")
    package_iproute=$(dpkg-query -W -f='${Version}' iproute2)
    ip_path=$(command -v ip)
    bridge_path=$(command -v bridge)
    ip_hash=$(sha256sum -- "$ip_path"); ip_hash=${ip_hash%% *}
    bridge_hash=$(sha256sum -- "$bridge_path"); bridge_hash=${bridge_hash%% *}
    config_hash=$(sha256sum -- "$output/kernel.config"); config_hash=${config_hash%% *}
    ip_version=$(ip -Version 2>&1)
    profile=$(python3 -c 'import json; print(json.load(open("/mnt/payload/request.json"))["profile"])')

    python3 - "$output/guest.json.tmp" "$profile" "$kernel" "$package_kernel" \
        "$package_iproute" "$ip_version" "$ip_hash" "$bridge_hash" "$config_hash" \
        "$(printf '%s' "$before" | sha256sum | cut -d' ' -f1)" \
        "$(printf '%s' "$after" | sha256sum | cut -d' ' -f1)" <<'PY'
import json, pathlib, sys
(
    output, profile, kernel, kernel_package, iproute_package, ip_version,
    ip_hash, bridge_hash, config_hash, before_hash, after_hash,
) = sys.argv[1:]
payload = {
    "after_netns_sha256": after_hash,
    "before_netns_sha256": before_hash,
    "bridge_binary_sha256": bridge_hash,
    "ip_binary_sha256": ip_hash,
    "ip_version_output": ip_version,
    "iproute2_package_version": iproute_package,
    "kernel_config_sha256": config_hash,
    "kernel_package_version": kernel_package,
    "kernel_release": kernel,
    "profile": profile,
    "schema": 1,
    "smoke": {
        "bridge_vlan_filtering": True,
        "deterministic_cleanup": True,
        "netns": True,
        "veth": True,
        "vlan_10": True,
        "vlan_20": True,
    },
    "status": "pass",
    "uid": 0,
}
pathlib.Path(output).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
    mv -- "$output/guest.json.tmp" "$output/guest.json"
}

bootstrap_guest() {
    local rc=0
    mkdir -p /mnt/payload /mnt/receipt
    mount -t 9p -o trans=virtio,version=9p2000.L,ro payload /mnt/payload || rc=$?
    if [ "$rc" -eq 0 ]; then
        mount -t 9p -o trans=virtio,version=9p2000.L receipt /mnt/receipt || rc=$?
    fi
    if [ "$rc" -eq 0 ]; then
        env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
            /mnt/payload/guest-smoke.sh --inside /mnt/receipt || rc=$?
    fi
    sync || true
    poweroff -f || true
    return "$rc"
}

case ${1:-} in
    --inside)
        shift
        inside_guest "$@"
        ;;
    "")
        bootstrap_guest
        ;;
    *)
        echo "unknown guest-smoke mode: $1" >&2
        exit 2
        ;;
esac
