#!/usr/bin/env bash

set -euo pipefail

readonly GNMIC_VERSION="0.46.0"
readonly GNMIC_SHA256="a3ded2f355a615df73900f31b9791f41e796e9c5c63b171e1ce041e8139ee00e"
readonly GNMIC_ASSET="gnmic_${GNMIC_VERSION}_Linux_x86_64.tar.gz"
readonly GNMIC_URL="https://github.com/openconfig/gnmic/releases/download/v${GNMIC_VERSION}/${GNMIC_ASSET}"
readonly GNMIC_ATTEMPTS=3

verify_archive() {
    local sha256=${1:?sha256}
    local archive=${2:?archive}

    [[ -f "$archive" ]] || return 1
    if ! printf '%s  %s\n' "$sha256" "$archive" \
        | sha256sum --check --status; then
        echo "gnmic archive checksum mismatch: ${archive}" >&2
        return 1
    fi
}

verify_version() {
    local binary=${1:?binary}
    local version=${2:?version}
    local reported

    reported=$("$binary" version 2>&1) || return 1
    if [[ "${reported%%$'\n'*}" != "version : ${version}" ]]; then
        echo "unexpected gnmic version: ${reported%%$'\n'*}" >&2
        return 1
    fi
}

install_from_archive() (
    local version=${1:?version}
    local sha256=${2:?sha256}
    local archive=${3:?archive}
    local install_dir=${4:?install directory}
    local work_dir staged_target

    # This path is deliberately offline. Only the producer may fetch the
    # release archive; consumers re-verify the same-run artifact before tar.
    verify_archive "$sha256" "$archive" || return 1
    work_dir=$(mktemp -d) || return 1
    trap 'rm -rf -- "$work_dir"' EXIT
    tar -xzf "$archive" -C "$work_dir" gnmic || return 1
    [[ -f "$work_dir/gnmic" ]] || {
        echo "gnmic archive did not contain gnmic" >&2
        return 1
    }
    chmod 0755 "$work_dir/gnmic"
    verify_version "$work_dir/gnmic" "$version" || return 1

    if [[ -d "$install_dir" && -w "$install_dir" ]] \
        || { [[ ! -e "$install_dir" ]] && [[ -w "$(dirname "$install_dir")" ]]; }; then
        mkdir -p "$install_dir"
        staged_target=$(mktemp "${install_dir}/.gnmic.XXXXXX")
        trap 'rm -rf -- "$work_dir"; rm -f -- "$staged_target"' EXIT
        install -m 0755 "$work_dir/gnmic" "$staged_target"
        mv -f -- "$staged_target" "$install_dir/gnmic"
    else
        staged_target="${install_dir}/.gnmic.$$.${RANDOM}"
        sudo mkdir -p "$install_dir"
        sudo install -m 0755 "$work_dir/gnmic" "$staged_target"
        trap 'rm -rf -- "$work_dir"; sudo rm -f -- "$staged_target"' EXIT
        sudo mv -f -- "$staged_target" "$install_dir/gnmic"
    fi
    verify_version "$install_dir/gnmic" "$version"
    printf 'gnmic version %s\n' "$version"
)

download_archive_once() {
    local url=${1:?url}
    local destination=${2:?destination}

    curl -fsSL \
        --connect-timeout 10 \
        --max-time 120 \
        --output "$destination" \
        "$url"
}

prepare_archive() {
    local sha256=${1:?sha256}
    local url=${2:?url}
    local archive=${3:?archive}
    local attempt staged_archive

    if verify_archive "$sha256" "$archive" 2>/dev/null; then
        echo "using verified cached gnmic archive"
        return 0
    fi
    if [[ -e "$archive" ]]; then
        echo "::warning::discarding invalid cached gnmic archive" >&2
        rm -f -- "$archive"
    fi

    mkdir -p "$(dirname "$archive")"
    for ((attempt = 1; attempt <= GNMIC_ATTEMPTS; attempt++)); do
        staged_archive=$(mktemp "${archive}.download.XXXXXX")
        if download_archive_once "$url" "$staged_archive" \
            && verify_archive "$sha256" "$staged_archive"; then
            mv -f -- "$staged_archive" "$archive"
            echo "downloaded and verified gnmic archive"
            return 0
        fi
        rm -f -- "$staged_archive"
        if ((attempt < GNMIC_ATTEMPTS)); then
            echo "::warning::gnmic download/verify attempt ${attempt}/${GNMIC_ATTEMPTS} failed; retrying" >&2
            sleep $((attempt * 5))
        fi
    done

    echo "::error::gnmic download/verification failed after ${GNMIC_ATTEMPTS} attempts: ${url}" >&2
    return 1
}

fail_self_test() {
    echo "gnmic installer self-test failed: $*" >&2
    return 1
}

self_test() (
    local fixture_dir source_dir valid_archive valid_checksum wrong_dir wrong_archive
    local wrong_checksum expected_url installed_hash attempts

    fixture_dir=$(mktemp -d)
    trap 'rm -rf -- "$fixture_dir"' EXIT
    [[ "$GNMIC_VERSION" == "0.46.0" ]] || fail_self_test "version pin drifted"
    [[ "$GNMIC_SHA256" == "a3ded2f355a615df73900f31b9791f41e796e9c5c63b171e1ce041e8139ee00e" ]] \
        || fail_self_test "checksum pin drifted"
    [[ "$GNMIC_ASSET" == "gnmic_0.46.0_Linux_x86_64.tar.gz" ]] \
        || fail_self_test "archive name drifted"
    printf -v expected_url '%s%s' \
        'https://github.com/openconfig/gnmic/releases' \
        '/download/v0.46.0/gnmic_0.46.0_Linux_x86_64.tar.gz'
    [[ "$GNMIC_URL" == "$expected_url" ]] \
        || fail_self_test "release URL drifted"
    [[ "$GNMIC_ATTEMPTS" -eq 3 ]] || fail_self_test "retry bound drifted"

    source_dir="$fixture_dir/source"
    mkdir -p "$source_dir"
    cat >"$source_dir/gnmic" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'version : 0.46.0'
EOF
    chmod +x "$source_dir/gnmic"
    valid_archive="$fixture_dir/valid.tar.gz"
    tar -czf "$valid_archive" -C "$source_dir" gnmic
    valid_checksum=$(sha256sum "$valid_archive" | awk '{print $1}')

    install_from_archive "$GNMIC_VERSION" "$valid_checksum" "$valid_archive" \
        "$fixture_dir/install" >/dev/null
    [[ -x "$fixture_dir/install/gnmic" ]] \
        || fail_self_test "verified archive was not installed"
    installed_hash=$(sha256sum "$fixture_dir/install/gnmic" | awk '{print $1}')

    if install_from_archive "$GNMIC_VERSION" "$GNMIC_SHA256" \
        "$valid_archive" "$fixture_dir/install" 2>/dev/null; then
        fail_self_test "wrong checksum was accepted"
    fi
    [[ "$(sha256sum "$fixture_dir/install/gnmic" | awk '{print $1}')" == "$installed_hash" ]] \
        || fail_self_test "checksum failure replaced the installed target"
    head -c 12 "$valid_archive" >"$fixture_dir/truncated.tar.gz"
    if install_from_archive "$GNMIC_VERSION" "$valid_checksum" \
        "$fixture_dir/truncated.tar.gz" "$fixture_dir/truncated" 2>/dev/null; then
        fail_self_test "truncated archive was accepted"
    fi
    printf '<html>503</html>\n' >"$fixture_dir/http-body.tar.gz"
    if install_from_archive "$GNMIC_VERSION" "$valid_checksum" \
        "$fixture_dir/http-body.tar.gz" "$fixture_dir/http" 2>/dev/null; then
        fail_self_test "HTTP response body was accepted"
    fi

    wrong_dir="$fixture_dir/wrong"
    mkdir -p "$wrong_dir"
    cat >"$wrong_dir/gnmic" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'version : 0.45.0'
EOF
    chmod +x "$wrong_dir/gnmic"
    wrong_archive="$fixture_dir/wrong-version.tar.gz"
    tar -czf "$wrong_archive" -C "$wrong_dir" gnmic
    wrong_checksum=$(sha256sum "$wrong_archive" | awk '{print $1}')
    if install_from_archive "$GNMIC_VERSION" "$wrong_checksum" "$wrong_archive" \
        "$fixture_dir/install" 2>/dev/null; then
        fail_self_test "wrong binary version was accepted"
    fi
    [[ "$(sha256sum "$fixture_dir/install/gnmic" | awk '{print $1}')" == "$installed_hash" ]] \
        || fail_self_test "version failure replaced the installed target"

    printf 'invalid cache\n' >"$fixture_dir/cache.tar.gz"
    attempts=0
    download_archive_once() {
        ((attempts += 1))
        if ((attempts == 1)); then
            printf 'transient failure\n' >"$2"
        else
            cp "$valid_archive" "$2"
        fi
    }
    sleep() { :; }
    prepare_archive "$valid_checksum" "https://example.invalid/retry" \
        "$fixture_dir/cache.tar.gz" >/dev/null 2>&1
    [[ "$attempts" -eq 2 ]] || fail_self_test "bounded retry count drifted"
    cmp -s "$valid_archive" "$fixture_dir/cache.tar.gz" \
        || fail_self_test "invalid cache was not atomically replaced"

    download_archive_once() { fail_self_test "warm cache reached upstream"; }
    prepare_archive "$valid_checksum" "https://example.invalid/unreachable" \
        "$fixture_dir/cache.tar.gz" \
        | grep -Fxq "using verified cached gnmic archive" \
        || fail_self_test "warm cache attempted an upstream fetch"

    attempts=0
    download_archive_once() {
        ((attempts += 1))
        printf '<html>503</html>\n' >"$2"
    }
    if prepare_archive "$valid_checksum" "https://example.invalid/unavailable" \
        "$fixture_dir/cold-cache.tar.gz" >/dev/null 2>&1; then
        fail_self_test "cold-cache upstream failure was accepted"
    fi
    [[ "$attempts" -eq "$GNMIC_ATTEMPTS" ]] \
        || fail_self_test "cold-cache retry bound was not enforced"
    [[ ! -e "$fixture_dir/cold-cache.tar.gz" ]] \
        || fail_self_test "failed cold-cache fetch left an artifact"

    echo "gnmic installer self-test passed"
)

usage() {
    echo "usage: $0 --prepare-archive ARCHIVE | --install-archive ARCHIVE INSTALL_DIR | --self-test" >&2
    return 2
}

case "${1:-}" in
    --prepare-archive)
        [[ $# -eq 2 ]] || usage
        prepare_archive "$GNMIC_SHA256" "$GNMIC_URL" "$2"
        ;;
    --install-archive)
        [[ $# -eq 3 ]] || usage
        install_from_archive "$GNMIC_VERSION" "$GNMIC_SHA256" "$2" "$3"
        ;;
    --self-test)
        [[ $# -eq 1 ]] || usage
        self_test
        ;;
    *) usage ;;
esac
