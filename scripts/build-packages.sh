#!/usr/bin/env bash
# Build the rustbgpd .deb and .rpm packages with nfpm.
#
# Usage: scripts/build-packages.sh <staging-dir> <deb-arch> <version> <out-dir> [nfpm-binary]
#
#   staging-dir  the release.yml tarball staging tree: rustbgpd, rbgp,
#                rs-config-render at the top level, man pages and
#                completions under share/ (see the "Package binaries"
#                step in .github/workflows/release.yml)
#   deb-arch     amd64 | arm64
#   version      package version, no leading v (e.g. 0.63.0)
#   out-dir      where the .deb/.rpm land
#   nfpm-binary  path to nfpm (default: nfpm on PATH)
#
# The packaged systemd unit and config skeleton are the checked-in
# examples with their paths rewritten for a package install
# (/usr/local/bin -> /usr/bin, /tmp/rustbgpd -> /var/lib/rustbgpd).
# Each rewrite asserts its pattern first so a drifted example fails the
# build instead of silently shipping a broken file.
set -euo pipefail

if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    echo "usage: $0 <staging-dir> <deb-arch> <version> <out-dir> [nfpm-binary]" >&2
    exit 2
fi

staging=$1
arch=$2
version=$3
outdir=$4
nfpm=${5:-nfpm}

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

case "$arch" in
    amd64|arm64) ;;
    *) echo "error: deb-arch must be amd64 or arm64, got '$arch'" >&2; exit 2 ;;
esac

for f in rustbgpd rbgp rs-config-render \
         share/man/man1/rbgp.1 share/man/man8/rustbgpd.8 \
         share/completions/rbgp.bash share/completions/rbgp.zsh \
         share/completions/rbgp.fish; do
    if [ ! -s "$staging/$f" ]; then
        echo "error: $staging/$f missing or empty" >&2
        exit 1
    fi
done

pkgroot=$(mktemp -d)
trap 'rm -rf "$pkgroot"' EXIT

install -D -m 0755 "$staging/rustbgpd" "$pkgroot/usr/bin/rustbgpd"
install -D -m 0755 "$staging/rbgp" "$pkgroot/usr/bin/rbgp"
install -D -m 0755 "$staging/rs-config-render" "$pkgroot/usr/bin/rs-config-render"

# systemd unit: packages install binaries to /usr/bin, the example unit
# points at /usr/local/bin (the tarball install path).
grep -q '^ExecStart=/usr/local/bin/rustbgpd ' examples/systemd/rustbgpd.service || {
    echo "error: examples/systemd/rustbgpd.service ExecStart no longer matches the expected /usr/local/bin path; update this script" >&2
    exit 1
}
mkdir -p "$pkgroot/lib/systemd/system"
sed 's|^ExecStart=/usr/local/bin/rustbgpd |ExecStart=/usr/bin/rustbgpd |' \
    examples/systemd/rustbgpd.service > "$pkgroot/lib/systemd/system/rustbgpd.service"

# Config skeleton: the minimal example with its dev-friendly /tmp state
# dir rewritten to the production path the systemd unit provides.
grep -q '^runtime_state_dir = "/tmp/rustbgpd"$' examples/minimal/config.toml || {
    echo "error: examples/minimal/config.toml runtime_state_dir no longer matches /tmp/rustbgpd; update this script" >&2
    exit 1
}
grep -q '^path = "/tmp/rustbgpd/grpc.sock"$' examples/minimal/config.toml || {
    echo "error: examples/minimal/config.toml grpc_uds path no longer matches /tmp/rustbgpd; update this script" >&2
    exit 1
}
grep -q '^# For local development' examples/minimal/config.toml || {
    echo "error: examples/minimal/config.toml dev-paths comment paragraph moved; update this script" >&2
    exit 1
}
mkdir -p "$pkgroot/etc/rustbgpd"
# Swap the dev-paths comment paragraph for a package-accurate one, then
# point the state paths at the production directory.
sed -e '/^# For local development/,/^# systemd unit (examples\/systemd\/)/c\
# Installed by the rustbgpd package. State lives in /var/lib/rustbgpd,\
# created and owned by the systemd unit (StateDirectory=rustbgpd).' \
    -e 's|/tmp/rustbgpd|/var/lib/rustbgpd|g' \
    examples/minimal/config.toml > "$pkgroot/etc/rustbgpd/config.toml"
if grep -q '/tmp/rustbgpd' "$pkgroot/etc/rustbgpd/config.toml"; then
    echo "error: dev path survived the config skeleton rewrite" >&2
    exit 1
fi

# Man pages (gzipped per packaging convention) + completions.
install -D -m 0644 "$staging/share/man/man1/rbgp.1" "$pkgroot/usr/share/man/man1/rbgp.1"
install -D -m 0644 "$staging/share/man/man8/rustbgpd.8" "$pkgroot/usr/share/man/man8/rustbgpd.8"
gzip -9 -n "$pkgroot/usr/share/man/man1/rbgp.1" "$pkgroot/usr/share/man/man8/rustbgpd.8"
mkdir -p "$pkgroot/usr/share/completions"
install -m 0644 "$staging"/share/completions/rbgp.bash \
    "$staging"/share/completions/rbgp.zsh \
    "$staging"/share/completions/rbgp.fish \
    "$pkgroot/usr/share/completions/"

mkdir -p "$outdir"
# nfpm does not expand env vars in `contents.src`; resolve the
# ${ARCH}/${VERSION}/${PKGROOT} placeholders into a temp config.
config="$pkgroot/nfpm.resolved.yaml"
sed -e "s|\${ARCH}|$arch|g" -e "s|\${VERSION}|$version|g" \
    -e "s|\${PKGROOT}|$pkgroot|g" packaging/nfpm.yaml > "$config"
"$nfpm" package --config "$config" --packager deb --target "$outdir/"
"$nfpm" package --config "$config" --packager rpm --target "$outdir/"

echo "built:"
ls -l "$outdir"/rustbgpd*"$version"*.{deb,rpm}
