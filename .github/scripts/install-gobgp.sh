#!/usr/bin/env bash

set -euo pipefail

readonly GOBGP_VERSION="3.37.0"
readonly GOBGP_SHA256="e20b2a155fe14450b9fe37e5c1a1d1bfe101eb479645f5bbea860a8fde30e522"
readonly GOBGP_ASSET="gobgp_${GOBGP_VERSION}_linux_amd64.tar.gz"
readonly GOBGP_URL="https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/${GOBGP_ASSET}"
readonly GOBGP_ATTEMPTS=3

verify_archive() {
    local sha256=${1:?sha256}
    local archive=${2:?archive}

    [[ -f "$archive" ]] || return 1
    if ! printf '%s  %s\n' "$sha256" "$archive" \
        | sha256sum --check --status; then
        echo "gobgp archive checksum mismatch: ${archive}" >&2
        return 1
    fi
}

verify_archive_contents() (
    local sha256=${1:?sha256}
    local archive=${2:?archive}
    local work_dir binary reported

    verify_archive "$sha256" "$archive" || return 1
    work_dir=$(mktemp -d) || return 1
    trap 'rm -rf -- "$work_dir"' EXIT
    tar -xzf "$archive" -C "$work_dir" gobgp gobgpd || return 1
    for binary in gobgp gobgpd; do
        [[ -f "$work_dir/$binary" ]] || {
            echo "gobgp archive did not contain ${binary}" >&2
            return 1
        }
        chmod 0755 "$work_dir/$binary"
        reported=$("$work_dir/$binary" --version 2>&1) || return 1
        if [[ "$reported" != "${binary} version ${GOBGP_VERSION}" ]]; then
            echo "unexpected ${binary} version: ${reported}" >&2
            return 1
        fi
    done
)

stage_archive() (
    local sha256=${1:?sha256}
    local archive=${2:?archive}
    local stage_dir=${3:?stage directory}
    local staged_target

    # This path is deliberately offline. Only the producer may fetch the
    # release archive; consumers re-verify the same-run artifact before the
    # gobgp image build context sees any bytes. The archive itself is staged
    # (not extracted): Dockerfile.gobgp re-verifies the checksum and both
    # binary versions inside the build.
    verify_archive_contents "$sha256" "$archive" || return 1
    mkdir -p "$stage_dir"
    staged_target=$(mktemp "${stage_dir}/.${GOBGP_ASSET}.XXXXXX")
    trap 'rm -f -- "$staged_target"' EXIT
    install -m 0644 "$archive" "$staged_target"
    mv -f -- "$staged_target" "${stage_dir}/${GOBGP_ASSET}"
    printf 'staged verified gobgp %s archive\n' "$GOBGP_VERSION"
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

    if verify_archive_contents "$sha256" "$archive" 2>/dev/null; then
        echo "using verified cached gobgp archive"
        return 0
    fi
    if [[ -e "$archive" ]]; then
        echo "::warning::discarding invalid cached gobgp archive" >&2
        rm -f -- "$archive"
    fi

    mkdir -p "$(dirname "$archive")"
    for ((attempt = 1; attempt <= GOBGP_ATTEMPTS; attempt++)); do
        staged_archive=$(mktemp "${archive}.download.XXXXXX")
        if download_archive_once "$url" "$staged_archive" \
            && verify_archive_contents "$sha256" "$staged_archive"; then
            mv -f -- "$staged_archive" "$archive"
            echo "downloaded and verified gobgp archive"
            return 0
        fi
        rm -f -- "$staged_archive"
        if ((attempt < GOBGP_ATTEMPTS)); then
            echo "::warning::gobgp download/verify attempt ${attempt}/${GOBGP_ATTEMPTS} failed; retrying" >&2
            sleep $((attempt * 5))
        fi
    done

    echo "::error::gobgp download/verification failed after ${GOBGP_ATTEMPTS} attempts: ${url}" >&2
    return 1
}

fail_self_test() {
    echo "gobgp installer self-test failed: $*" >&2
    return 1
}

self_test() (
    local fixture_dir source_dir valid_archive valid_checksum wrong_dir wrong_archive
    local wrong_checksum partial_archive expected_url staged_hash attempts

    fixture_dir=$(mktemp -d)
    trap 'rm -rf -- "$fixture_dir"' EXIT
    [[ "$GOBGP_VERSION" == "3.37.0" ]] || fail_self_test "version pin drifted"
    [[ "$GOBGP_SHA256" == "e20b2a155fe14450b9fe37e5c1a1d1bfe101eb479645f5bbea860a8fde30e522" ]] \
        || fail_self_test "checksum pin drifted"
    [[ "$GOBGP_ASSET" == "gobgp_3.37.0_linux_amd64.tar.gz" ]] \
        || fail_self_test "archive name drifted"
    printf -v expected_url '%s%s' \
        'https://github.com/osrg/gobgp/releases' \
        '/download/v3.37.0/gobgp_3.37.0_linux_amd64.tar.gz'
    [[ "$GOBGP_URL" == "$expected_url" ]] \
        || fail_self_test "release URL drifted"
    [[ "$GOBGP_ATTEMPTS" -eq 3 ]] || fail_self_test "retry bound drifted"

    source_dir="$fixture_dir/source"
    mkdir -p "$source_dir"
    cat >"$source_dir/gobgp" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'gobgp version 3.37.0'
EOF
    cat >"$source_dir/gobgpd" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'gobgpd version 3.37.0'
EOF
    chmod +x "$source_dir/gobgp" "$source_dir/gobgpd"
    valid_archive="$fixture_dir/valid.tar.gz"
    tar -czf "$valid_archive" -C "$source_dir" gobgp gobgpd
    valid_checksum=$(sha256sum "$valid_archive" | awk '{print $1}')

    stage_archive "$valid_checksum" "$valid_archive" \
        "$fixture_dir/stage" >/dev/null
    [[ -f "$fixture_dir/stage/$GOBGP_ASSET" ]] \
        || fail_self_test "verified archive was not staged"
    cmp -s "$valid_archive" "$fixture_dir/stage/$GOBGP_ASSET" \
        || fail_self_test "staged archive bytes drifted"
    staged_hash=$(sha256sum "$fixture_dir/stage/$GOBGP_ASSET" | awk '{print $1}')

    if stage_archive "$GOBGP_SHA256" "$valid_archive" \
        "$fixture_dir/stage" 2>/dev/null; then
        fail_self_test "wrong checksum was accepted"
    fi
    [[ "$(sha256sum "$fixture_dir/stage/$GOBGP_ASSET" | awk '{print $1}')" == "$staged_hash" ]] \
        || fail_self_test "checksum failure replaced the staged target"
    head -c 12 "$valid_archive" >"$fixture_dir/truncated.tar.gz"
    if stage_archive "$valid_checksum" "$fixture_dir/truncated.tar.gz" \
        "$fixture_dir/truncated" 2>/dev/null; then
        fail_self_test "truncated archive was accepted"
    fi
    printf '<html>503</html>\n' >"$fixture_dir/http-body.tar.gz"
    if stage_archive "$valid_checksum" "$fixture_dir/http-body.tar.gz" \
        "$fixture_dir/http" 2>/dev/null; then
        fail_self_test "HTTP response body was accepted"
    fi

    partial_archive="$fixture_dir/gobgp-only.tar.gz"
    tar -czf "$partial_archive" -C "$source_dir" gobgp
    if stage_archive "$(sha256sum "$partial_archive" | awk '{print $1}')" \
        "$partial_archive" "$fixture_dir/partial" 2>/dev/null; then
        fail_self_test "archive without gobgpd was accepted"
    fi

    wrong_dir="$fixture_dir/wrong"
    mkdir -p "$wrong_dir"
    cat >"$wrong_dir/gobgp" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'gobgp version 3.36.0'
EOF
    cat >"$wrong_dir/gobgpd" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'gobgpd version 3.36.0'
EOF
    chmod +x "$wrong_dir/gobgp" "$wrong_dir/gobgpd"
    wrong_archive="$fixture_dir/wrong-version.tar.gz"
    tar -czf "$wrong_archive" -C "$wrong_dir" gobgp gobgpd
    wrong_checksum=$(sha256sum "$wrong_archive" | awk '{print $1}')
    if stage_archive "$wrong_checksum" "$wrong_archive" \
        "$fixture_dir/stage" 2>/dev/null; then
        fail_self_test "wrong binary version was accepted"
    fi
    [[ "$(sha256sum "$fixture_dir/stage/$GOBGP_ASSET" | awk '{print $1}')" == "$staged_hash" ]] \
        || fail_self_test "version failure replaced the staged target"

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
        | grep -Fxq "using verified cached gobgp archive" \
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
    [[ "$attempts" -eq "$GOBGP_ATTEMPTS" ]] \
        || fail_self_test "cold-cache retry bound was not enforced"
    [[ ! -e "$fixture_dir/cold-cache.tar.gz" ]] \
        || fail_self_test "failed cold-cache fetch left an artifact"

    # shellcheck disable=SC2317
    curl() { fail_self_test "offline stage invoked curl"; }
    stage_archive "$valid_checksum" "$valid_archive" \
        "$fixture_dir/offline-stage" >/dev/null \
        || fail_self_test "offline archive stage failed"

    echo "gobgp installer self-test passed"
)

usage() {
    echo "usage: $0 --prepare-archive ARCHIVE | --stage-archive ARCHIVE STAGE_DIR | --self-test" >&2
    return 2
}

case "${1:-}" in
    --prepare-archive)
        [[ $# -eq 2 ]] || usage
        prepare_archive "$GOBGP_SHA256" "$GOBGP_URL" "$2"
        ;;
    --stage-archive)
        [[ $# -eq 3 ]] || usage
        stage_archive "$GOBGP_SHA256" "$2" "$3"
        ;;
    --self-test)
        [[ $# -eq 1 ]] || usage
        self_test
        ;;
    *) usage ;;
esac
