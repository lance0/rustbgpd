#!/usr/bin/env bash

set -euo pipefail

readonly VERSION=0.64.0
readonly SHA256=bd4829de08d0c50074f9ecd5c351399fae42be06d456b3880a04aa4a7cda1137
readonly ARCHIVE=rustbgpd-linux-amd64.tar.gz
readonly BINARY=rustbgpd-v0.64.0
readonly URL="https://github.com/lance0/rustbgpd/releases/download/v${VERSION}/${ARCHIVE}"
readonly ATTEMPTS=3

verify_archive() {
    local sha256=${1:?sha256}
    local archive=${2:?archive}

    [[ -f "$archive" ]] || return 1
    if ! printf '%s  %s\n' "$sha256" "$archive" \
        | sha256sum --check --status; then
        echo "v0.64 validator archive checksum mismatch: ${archive}" >&2
        return 1
    fi
}

install_from_archive() (
    local version=${1:?version}
    local sha256=${2:?sha256}
    local archive=${3:?archive}
    local install_dir=${4:?install directory}
    local binary_name=${5:?binary name}
    local work_dir staged_binary reported_version

    # This path is deliberately offline. The producer is the only workflow
    # job allowed to fetch the release archive; consumers re-verify the
    # same-run artifact before tar sees any bytes.
    verify_archive "$sha256" "$archive" || return 1

    work_dir=$(mktemp -d) || return 1
    mkdir -p "$install_dir" || return 1
    staged_binary=$(mktemp "${install_dir}/.${binary_name}.XXXXXX") || return 1
    trap 'rm -rf -- "$work_dir"; rm -f -- "$staged_binary"' EXIT
    tar -xzf "$archive" -C "$work_dir" rustbgpd || return 1
    [[ -f "$work_dir/rustbgpd" ]] || {
        echo "v0.64 validator archive did not contain rustbgpd" >&2
        return 1
    }
    chmod 0755 "$work_dir/rustbgpd" || return 1
    reported_version=$("$work_dir/rustbgpd" --version 2>&1) || return 1
    if [[ "$reported_version" != "rustbgpd ${version}" ]]; then
        echo "unexpected v0.64 validator version: ${reported_version}" >&2
        return 1
    fi

    install -m 0755 "$work_dir/rustbgpd" "$staged_binary" || return 1
    mv -f -- "$staged_binary" "$install_dir/$binary_name" || return 1
    [[ $("$install_dir/$binary_name" --version 2>&1) == "rustbgpd ${version}" ]]
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
        echo "using verified cached v0.64 validator archive"
        return 0
    fi
    if [[ -e "$archive" ]]; then
        echo "::warning::discarding invalid cached v0.64 validator archive" >&2
        rm -f -- "$archive"
    fi

    mkdir -p "$(dirname "$archive")"
    for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
        staged_archive=$(mktemp "${archive}.download.XXXXXX")
        if download_archive_once "$url" "$staged_archive" \
            && verify_archive "$sha256" "$staged_archive"; then
            mv -f -- "$staged_archive" "$archive"
            echo "downloaded and verified v0.64 validator archive"
            return 0
        fi
        rm -f -- "$staged_archive"
        if ((attempt < ATTEMPTS)); then
            echo "::warning::v0.64 validator download/verify attempt ${attempt}/${ATTEMPTS} failed; retrying" >&2
            sleep $((attempt * 5))
        fi
    done

    echo "::error::v0.64 validator download/verification failed after ${ATTEMPTS} attempts: ${url}" >&2
    return 1
}

fail_self_test() {
    echo "v0.64 validator installer self-test failed: $*" >&2
    return 1
}

self_test() (
    local fixture_dir source_dir base_archive valid_archive checksum truncated_size
    local wrong_source wrong_archive wrong_checksum counter cache_path target_path

    fixture_dir=$(mktemp -d)
    trap 'rm -rf -- "$fixture_dir"' EXIT
    [[ "$VERSION" == "0.64.0" ]] \
        || fail_self_test "version pin drifted"
    [[ "$SHA256" == "bd4829de08d0c50074f9ecd5c351399fae42be06d456b3880a04aa4a7cda1137" ]] \
        || fail_self_test "archive checksum pin drifted"
    [[ "$ARCHIVE" == "rustbgpd-linux-amd64.tar.gz" ]] \
        || fail_self_test "archive name drifted"
    [[ "$BINARY" == "rustbgpd-v0.64.0" ]] \
        || fail_self_test "installed binary name drifted"
    [[ "$URL" == "https://github.com/lance0/rustbgpd/releases/download/v0.64.0/rustbgpd-linux-amd64.tar.gz" ]] \
        || fail_self_test "release URL drifted"
    [[ "$ATTEMPTS" -eq 3 ]] \
        || fail_self_test "retry bound drifted"

    source_dir="$fixture_dir/source"
    mkdir -p "$source_dir"
    cat >"$source_dir/rustbgpd" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'rustbgpd 0.64.0'
EOF
    chmod +x "$source_dir/rustbgpd"
    # The extra empty gzip member makes the full fixture distinct while the
    # truncated prefix remains an extractable tar. Only checksum verification
    # can reject that otherwise-plausible truncated transfer before extraction.
    base_archive="$fixture_dir/base.tar.gz"
    valid_archive="$fixture_dir/valid.tar.gz"
    tar -czf "$base_archive" -C "$source_dir" rustbgpd
    cp "$base_archive" "$valid_archive"
    printf '' | gzip >>"$valid_archive"
    checksum=$(sha256sum "$valid_archive" | awk '{print $1}')

    install_from_archive \
        "$VERSION" "$checksum" "$valid_archive" \
        "$fixture_dir/valid-install" "$BINARY"
    [[ -x "$fixture_dir/valid-install/$BINARY" ]] \
        || fail_self_test "verified archive was not installed"

    truncated_size=$(wc -c <"$base_archive")
    head -c "$truncated_size" "$valid_archive" >"$fixture_dir/truncated.tar.gz"
    if install_from_archive \
        "$VERSION" "$checksum" "$fixture_dir/truncated.tar.gz" \
        "$fixture_dir/truncated-install" "$BINARY" 2>/dev/null; then
        fail_self_test "truncated archive was accepted"
    fi
    [[ ! -e "$fixture_dir/truncated-install/$BINARY" ]] \
        || fail_self_test "truncated archive installed a binary"

    if install_from_archive \
        "$VERSION" \
        0000000000000000000000000000000000000000000000000000000000000000 \
        "$valid_archive" "$fixture_dir/wrong-checksum-install" "$BINARY" \
        2>/dev/null; then
        fail_self_test "wrong checksum was accepted"
    fi

    wrong_source="$fixture_dir/wrong-source"
    mkdir -p "$wrong_source"
    cat >"$wrong_source/rustbgpd" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'rustbgpd 0.63.0'
EOF
    chmod +x "$wrong_source/rustbgpd"
    wrong_archive="$fixture_dir/wrong-version.tar.gz"
    tar -czf "$wrong_archive" -C "$wrong_source" rustbgpd
    wrong_checksum=$(sha256sum "$wrong_archive" | awk '{print $1}')
    if install_from_archive \
        "$VERSION" "$wrong_checksum" "$wrong_archive" \
        "$fixture_dir/wrong-version-install" "$BINARY" 2>/dev/null; then
        fail_self_test "wrong binary version was accepted"
    fi
    [[ ! -e "$fixture_dir/wrong-version-install/$BINARY" ]] \
        || fail_self_test "wrong-version binary reached the install path"

    # Cache and retry cases stub the network primitive and sleep, keeping this
    # suite entirely offline while exercising the real selection and bounds.
    counter="$fixture_dir/download-count"
    cache_path="$fixture_dir/cache/$ARCHIVE"
    mkdir -p "$(dirname "$cache_path")"
    cp "$valid_archive" "$cache_path"
    printf '0' >"$counter"
    (
        download_archive_once() {
            printf '%s' "$(($(cat "$counter") + 1))" >"$counter"
            return 1
        }
        prepare_archive "$checksum" unused://cache-hit "$cache_path"
    ) >/dev/null || fail_self_test "valid cache hit failed"
    [[ $(cat "$counter") -eq 0 ]] \
        || fail_self_test "valid cache hit used the network"

    printf 'corrupt' >"$cache_path"
    printf '0' >"$counter"
    (
        sleep() { :; }
        download_archive_once() {
            printf '%s' "$(($(cat "$counter") + 1))" >"$counter"
            cp "$valid_archive" "$2"
        }
        prepare_archive "$checksum" unused://corrupt-cache "$cache_path"
    ) >/dev/null 2>&1 || fail_self_test "corrupt cache was not replaced"
    [[ $(cat "$counter") -eq 1 ]] \
        || fail_self_test "corrupt cache did not perform one download"
    verify_archive "$checksum" "$cache_path" \
        || fail_self_test "corrupt cache replacement was not verified"

    target_path="$fixture_dir/transient/$ARCHIVE"
    printf '0' >"$counter"
    (
        sleep() { :; }
        download_archive_once() {
            local count
            count=$(($(cat "$counter") + 1))
            printf '%s' "$count" >"$counter"
            if [[ "$count" -eq 1 ]]; then
                printf 'truncated' >"$2"
            else
                cp "$valid_archive" "$2"
            fi
        }
        prepare_archive "$checksum" unused://transient "$target_path"
    ) >/dev/null 2>&1 || fail_self_test "retry did not recover"
    [[ $(cat "$counter") -eq 2 ]] \
        || fail_self_test "retry did not stop on first verified success"
    verify_archive "$checksum" "$target_path" \
        || fail_self_test "retry published unverified bytes"

    target_path="$fixture_dir/persistent/$ARCHIVE"
    printf '0' >"$counter"
    if (
        sleep() { :; }
        download_archive_once() {
            printf '%s' "$(($(cat "$counter") + 1))" >"$counter"
            printf 'corrupt' >"$2"
        }
        prepare_archive "$checksum" unused://persistent "$target_path"
    ) >/dev/null 2>&1; then
        fail_self_test "persistent corruption was not surfaced"
    fi
    [[ $(cat "$counter") -eq "$ATTEMPTS" ]] \
        || fail_self_test "persistent failure escaped retry bound"
    [[ ! -e "$target_path" ]] \
        || fail_self_test "persistent failure published an archive"

    # Installing a downloaded artifact remains usable when every network
    # primitive is disabled, proving consumers have no hidden fetch fallback.
    (
        # These tripwires are reachable only if install_from_archive regresses
        # into a network consumer, which is precisely the negative under test.
        # shellcheck disable=SC2317
        curl() { fail_self_test "offline install invoked curl"; }
        # shellcheck disable=SC2317
        download_archive_once() { fail_self_test "offline install downloaded"; }
        install_from_archive \
            "$VERSION" "$checksum" "$valid_archive" \
            "$fixture_dir/offline-install" "$BINARY"
    ) || fail_self_test "offline artifact install failed"

    printf '%s\n' 'v0.64 validator installer self-test passed'
)

usage() {
    echo "usage: $0 --prepare-archive ARCHIVE | --install-archive ARCHIVE INSTALL_DIR | --self-test" >&2
    exit 2
}

case ${1:-} in
    --prepare-archive)
        [[ $# -eq 2 ]] || usage
        prepare_archive "$SHA256" "$URL" "$2"
        ;;
    --install-archive)
        [[ $# -eq 3 ]] || usage
        install_from_archive "$VERSION" "$SHA256" "$2" "$3" "$BINARY"
        ;;
    --self-test)
        [[ $# -eq 1 ]] || usage
        self_test
        ;;
    *)
        usage
        ;;
esac
