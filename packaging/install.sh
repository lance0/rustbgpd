#!/bin/sh
# Download one rustbgpd release artifact, verify its published digest, and
# install it only on a documented native-package path or an explicit prefix.
set -eu

REPOSITORY='https://github.com/lance0/rustbgpd'
LATEST_URL="${REPOSITORY}/releases/latest"

die() {
    echo "rustbgpd installer: $*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: install.sh [--tag vMAJOR.MINOR.PATCH] [--prefix DIR | --download-only DIR]

Downloads one verified rustbgpd release artifact for this GNU/Linux host.
Without a mode, Debian/Ubuntu installs the verified .deb and RHEL, Rocky, or
AlmaLinux 9+ installs the verified .rpm. Other GNU/Linux distributions must
use --prefix or --download-only. --prefix extracts the verified tarball's
existing layout into an empty directory; it does not configure or start a
service. --download-only writes the verified artifact and checksum manifest to
DIR without installing anything.

--tag accepts stable release tags only, such as v0.69.0.
EOF
}

stable_tag() {
    case "$1" in
        v*) version=${1#v} ;;
        *) return 1 ;;
    esac
    major=${version%%.*}
    remainder=${version#*.}
    [ "$remainder" != "$version" ] || return 1
    minor=${remainder%%.*}
    patch=${remainder#*.}
    [ "$patch" != "$remainder" ] || return 1
    case "$patch" in
        *.*) return 1 ;;
    esac
    for part in "$major" "$minor" "$patch"; do
        case "$part" in
            ''|*[!0-9]*) return 1 ;;
        esac
    done
}

normalize_directory() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        -*) printf './%s\n' "$1" ;;
        *) printf '%s\n' "$1" ;;
    esac
}

tag=''
prefix=''
download_dir=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --tag)
            [ "$#" -ge 2 ] || die '--tag needs a value'
            [ -n "$2" ] || die '--tag needs a non-empty value'
            tag=$2
            shift 2
            ;;
        --prefix)
            [ "$#" -ge 2 ] || die '--prefix needs a directory'
            [ -n "$2" ] || die '--prefix needs a non-empty directory'
            prefix=$(normalize_directory "$2")
            shift 2
            ;;
        --download-only)
            [ "$#" -ge 2 ] || die '--download-only needs a directory'
            [ -n "$2" ] || die '--download-only needs a non-empty directory'
            download_dir=$(normalize_directory "$2")
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown argument: $1"
            ;;
    esac
done

[ -z "$prefix" ] || [ -z "$download_dir" ] \
    || die '--prefix and --download-only cannot be combined'
[ -z "$prefix" ] || [ ! -L "$prefix" ] \
    || die "prefix must not be a symlink: $prefix"
[ -z "$download_dir" ] || [ ! -L "$download_dir" ] \
    || die "download destination must not be a symlink: $download_dir"

case "$(uname -s)" in
    Linux) ;;
    *) die 'only GNU/Linux release artifacts are supported' ;;
esac

case "$(uname -m)" in
    x86_64)
        suffix='linux-amd64'
        deb_arch='amd64'
        rpm_arch='x86_64'
        ;;
    aarch64)
        suffix='linux-arm64'
        deb_arch='arm64'
        rpm_arch='aarch64'
        ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac

glibc=$(getconf GNU_LIBC_VERSION 2>/dev/null || true)
printf '%s\n' "$glibc" | awk '
    $1 == "glibc" && $2 ~ /^[0-9]+\.[0-9]+$/ && NF == 2 {
        split($2, version, ".")
        exit !(version[1] > 2 || version[1] == 2 && version[2] >= 31)
    }
    { exit 1 }
' \
    || die 'requires GNU glibc 2.31 or newer'

if [ -n "$tag" ]; then
    stable_tag "$tag" || die "requires a stable release tag such as v0.69.0"
else
    resolved_url=$(curl -fsSIL -o /dev/null -w '%{url_effective}' "$LATEST_URL") \
        || die 'could not resolve the latest release tag'
    expected_prefix="${REPOSITORY}/releases/tag/"
    case "$resolved_url" in
        "$expected_prefix"*) tag=${resolved_url#"$expected_prefix"} ;;
        *) die "latest release resolved outside rustbgpd: $resolved_url" ;;
    esac
    stable_tag "$tag" || die "latest redirect returned a non-stable release tag"
fi

version=${tag#v}
tarball="rustbgpd-${suffix}.tar.gz"
artifact=$tarball
install_kind='tarball'

os_field() {
    sed -n "s/^$1=//p" /etc/os-release 2>/dev/null | head -n 1 | tr -d '"'
}

if [ -z "$prefix" ]; then
    os_id=$(os_field ID)
    os_version=$(os_field VERSION_ID)
    case "$os_id" in
        debian|ubuntu)
            artifact="rustbgpd_${version}_${deb_arch}.deb"
            install_kind='deb'
            if [ -z "$download_dir" ]; then
                command -v apt-get >/dev/null 2>&1 \
                    || die 'Debian/Ubuntu requires apt-get; use --prefix or --download-only'
            fi
            ;;
        rhel|rocky|almalinux)
            rhel_major=${os_version%%.*}
            case "$rhel_major" in
                ''|*[!0-9]*) die 'RHEL/Rocky/AlmaLinux version is not supported; use --prefix or --download-only' ;;
            esac
            [ "$rhel_major" -ge 9 ] \
                || die 'RHEL/Rocky/AlmaLinux 9+ is required; use --prefix or --download-only'
            artifact="rustbgpd-${version}-1.${rpm_arch}.rpm"
            install_kind='rpm'
            if [ -z "$download_dir" ]; then
                command -v dnf >/dev/null 2>&1 \
                    || die 'RHEL/Rocky/AlmaLinux requires dnf; use --prefix or --download-only'
            fi
            ;;
        *)
            if [ -z "$download_dir" ]; then
                die 'this GNU/Linux distribution requires --prefix or --download-only'
            fi
            ;;
    esac
fi

checksum="checksums-${suffix}.txt"
base_url="${REPOSITORY}/releases/download/${tag}"
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

curl -fsSL --retry 3 -o "$tmpdir/$checksum" "$base_url/$checksum" \
    || die "could not download $checksum for $tag"
curl -fsSL --retry 3 -o "$tmpdir/$artifact" "$base_url/$artifact" \
    || die "could not download $artifact for $tag"

match_count=$(awk -v file="$artifact" \
    '$2 == file || $2 == "./" file { count++ } END { print count + 0 }' \
    "$tmpdir/$checksum")
[ "$match_count" -eq 1 ] \
    || die "$checksum must contain exactly one digest for $artifact"
awk -v file="$artifact" '$2 == file || $2 == "./" file { print }' \
    "$tmpdir/$checksum" > "$tmpdir/checksum-row"
(cd "$tmpdir" && sha256sum -c checksum-row) \
    || die "checksum mismatch for $artifact"

if [ -n "$download_dir" ]; then
    mkdir -p "$download_dir"
    if [ -e "$download_dir/$artifact" ] || [ -L "$download_dir/$artifact" ] \
        || [ -e "$download_dir/$checksum" ] || [ -L "$download_dir/$checksum" ]; then
        die "download destination already contains $artifact or $checksum"
    fi
    mv "$tmpdir/$artifact" "$tmpdir/$checksum" "$download_dir/"
    echo "Verified $artifact and $checksum in $download_dir"
    exit 0
fi

if [ -n "$prefix" ]; then
    if [ -e "$prefix" ] || [ -L "$prefix" ]; then
        [ -d "$prefix" ] || die "prefix is not a directory: $prefix"
        [ -z "$(find "$prefix" -mindepth 1 -maxdepth 1 -print -quit)" ] \
            || die "prefix must be empty: $prefix"
    else
        mkdir -p "$prefix"
    fi
    tar -xzf "$tmpdir/$tarball" -C "$prefix"
    echo "Verified $tarball extracted into $prefix"
    echo "Next: $prefix/rbgp doctor"
    exit 0
fi

run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        die 'root privileges or sudo are required for native package installation'
    fi
}

case "$install_kind" in
    deb) run_privileged apt-get install -y -o 'Dpkg::Options::=--force-confold' "$tmpdir/$artifact" < /dev/null ;;
    rpm) run_privileged dnf install -y "$tmpdir/$artifact" < /dev/null ;;
    *) die 'internal error: no native package selected' ;;
esac
echo 'Installed verified rustbgpd package. Edit its configuration, then run: rbgp doctor'
