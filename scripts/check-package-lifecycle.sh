#!/usr/bin/env bash
# Exercise the native package's maintainer scripts against a running systemd:
# install, start, upgrade, then purge/erase. Asserts that
#   - the daemon's log lines reach journald at their own priority,
#   - an upgrade prints the restart notice and leaves the running daemon
#     (same PID) alone,
#   - removal stops the daemon before its binary goes (ExecStopPost runs
#     cleanly), disables the unit and template instances, and keeps
#     /var/lib/rustbgpd.
#
# Usage (as root, on a host or container booted with systemd):
#   scripts/check-package-lifecycle.sh <old.deb|old.rpm> <new.deb|new.rpm>
#
# Both packages come from scripts/build-packages.sh; the old one only needs
# a lower version. The check changes the host's package and unit state.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <old-package> <new-package>" >&2
    exit 2
fi
old=$1
new=$2

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

case "$old" in
    *.deb)
        pkg_install() { dpkg -i "$1"; }
        pkg_remove() { dpkg --purge rustbgpd; }
        ;;
    *.rpm)
        pkg_install() { rpm -U "$1"; }
        pkg_remove() { rpm -e rustbgpd; }
        ;;
    *) fail "unknown package type: $old" ;;
esac

[ -d /run/systemd/system ] || fail "systemd is not running"
[ "$(id -u)" -eq 0 ] || fail "run as root"
wants=/etc/systemd/system/multi-user.target.wants
dropin=/etc/systemd/system/rustbgpd.service.d/lifecycle-check.conf
trap 'rm -f "$dropin"' EXIT

echo "== install $old"
out=$(pkg_install "$old" 2>&1) || { echo "$out"; fail "install failed"; }
echo "$out"
grep -q 'rustbgpd installed' <<<"$out" || fail "fresh install printed no install notice"

# Debug lines give the priority check a level that journald would otherwise
# store at the default PRIORITY=6.
mkdir -p "$(dirname "$dropin")"
printf '[Service]\nEnvironment=RUST_LOG=debug\n' >"$dropin"
systemctl daemon-reload
# Type=notify: returns once the daemon reports ready.
systemctl enable --now rustbgpd.service
systemctl enable rustbgpd@lifecycle.service
pid=$(systemctl show -P MainPID rustbgpd.service)
[ "$pid" -gt 0 ] || fail "rustbgpd did not start"

echo "== journald priority"
journalctl --sync
unit_log() { journalctl --no-pager -q -o cat _SYSTEMD_UNIT=rustbgpd.service "$@"; }
[ -n "$(unit_log -p 7..7)" ] || fail "no daemon line stored at PRIORITY=7 (debug)"
[ -n "$(unit_log -p 6..6)" ] || fail "no daemon line stored at PRIORITY=6 (info)"
if unit_log | grep -q '^<[0-7]>'; then
    fail "journald kept a <N> prefix in MESSAGE"
fi

echo "== upgrade to $new"
out=$(pkg_install "$new" 2>&1) || { echo "$out"; fail "upgrade failed"; }
echo "$out"
grep -q 'restart required' <<<"$out" || fail "upgrade printed no restart notice"
systemctl is-active --quiet rustbgpd.service || fail "upgrade stopped rustbgpd"
[ "$(systemctl show -P MainPID rustbgpd.service)" = "$pid" ] \
    || fail "upgrade restarted rustbgpd"

echo "== remove"
pkg_remove
if systemctl is-active --quiet rustbgpd.service; then
    fail "rustbgpd still active after removal"
fi
if kill -0 "$pid" 2>/dev/null; then
    fail "daemon process $pid still running after removal"
fi
# A missing ExecStopPost binary fails the stop with 203/EXEC.
if systemctl is-failed --quiet rustbgpd.service; then
    fail "rustbgpd stop failed during removal"
fi
for link in "$wants/rustbgpd.service" "$wants/rustbgpd@lifecycle.service"; do
    if [ -e "$link" ] || [ -L "$link" ]; then
        fail "$link left enabled after removal"
    fi
done
[ ! -e /usr/bin/rustbgpd ] || fail "/usr/bin/rustbgpd left behind"
[ -d /var/lib/rustbgpd ] || fail "/var/lib/rustbgpd removed"

echo "PASS: package lifecycle"
