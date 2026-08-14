#!/usr/bin/env bash

set -euo pipefail

readonly GRPCURL_VERSION="1.9.1"
readonly GRPCURL_SHA256="588c9c429476d9ed66cd3b2ae32283a6da36e0cfbb7e446f5d6a1b68dc770214"
readonly GRPCURL_ASSET="grpcurl_${GRPCURL_VERSION}_linux_x86_64.tar.gz"
readonly GRPCURL_URL="https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/${GRPCURL_ASSET}"
readonly GRPCURL_ATTEMPTS=3

verify_archive() {
    local sha256=${1:?sha256}
    local archive=${2:?archive}

    [[ -f "$archive" ]] || return 1
    if ! printf '%s  %s\n' "$sha256" "$archive" \
        | sha256sum --check --status; then
        echo "grpcurl archive checksum mismatch: ${archive}" >&2
        return 1
    fi
}

install_from_archive() (
    local version=${1:?version}
    local sha256=${2:?sha256}
    local archive=${3:?archive}
    local install_dir=${4:?install directory}
    local work_dir staged_target reported_version

    # This path is deliberately offline. Producers are the only workflow jobs
    # allowed to fetch the release archive; consumers re-verify the same-run
    # artifact before tar sees any bytes.
    verify_archive "$sha256" "$archive" || return 1

    work_dir=$(mktemp -d) || return 1
    trap 'rm -rf -- "$work_dir"' EXIT
    tar -xzf "$archive" -C "$work_dir" grpcurl || return 1
    [[ -f "$work_dir/grpcurl" ]] || {
        echo "grpcurl archive did not contain grpcurl" >&2
        return 1
    }
    chmod 0755 "$work_dir/grpcurl" || return 1
    reported_version=$("$work_dir/grpcurl" -version 2>&1) || return 1
    if [[ "$reported_version" != "grpcurl v${version}" ]]; then
        echo "unexpected grpcurl version: ${reported_version}" >&2
        return 1
    fi

    if [[ -d "$install_dir" && -w "$install_dir" ]] \
        || { [[ ! -e "$install_dir" ]] && [[ -w "$(dirname "$install_dir")" ]]; }; then
        mkdir -p "$install_dir"
        staged_target=$(mktemp "${install_dir}/.grpcurl.XXXXXX")
        trap 'rm -rf -- "$work_dir"; rm -f -- "$staged_target"' EXIT
        install -m 0755 "$work_dir/grpcurl" "$staged_target"
        mv -f -- "$staged_target" "$install_dir/grpcurl"
    else
        staged_target="${install_dir}/.grpcurl.$$.${RANDOM}"
        sudo mkdir -p "$install_dir"
        sudo install -m 0755 "$work_dir/grpcurl" "$staged_target"
        trap 'rm -rf -- "$work_dir"; sudo rm -f -- "$staged_target"' EXIT
        sudo mv -f -- "$staged_target" "$install_dir/grpcurl"
    fi

    reported_version=$("$install_dir/grpcurl" -version 2>&1) || return 1
    [[ "$reported_version" == "grpcurl v${version}" ]] || {
        echo "installed grpcurl version check failed: ${reported_version}" >&2
        return 1
    }
    printf '%s\n' "$reported_version"
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
        echo "using verified cached grpcurl archive"
        return 0
    fi
    if [[ -e "$archive" ]]; then
        echo "::warning::discarding invalid cached grpcurl archive" >&2
        rm -f -- "$archive"
    fi

    mkdir -p "$(dirname "$archive")"
    for ((attempt = 1; attempt <= GRPCURL_ATTEMPTS; attempt++)); do
        staged_archive=$(mktemp "${archive}.download.XXXXXX")
        if download_archive_once "$url" "$staged_archive" \
            && verify_archive "$sha256" "$staged_archive"; then
            mv -f -- "$staged_archive" "$archive"
            echo "downloaded and verified grpcurl archive"
            return 0
        fi
        rm -f -- "$staged_archive"
        if ((attempt < GRPCURL_ATTEMPTS)); then
            echo "::warning::grpcurl download/verify attempt ${attempt}/${GRPCURL_ATTEMPTS} failed; retrying" >&2
            sleep $((attempt * 5))
        fi
    done

    echo "::error::grpcurl download/verification failed after ${GRPCURL_ATTEMPTS} attempts: ${url}" >&2
    return 1
}

fail_self_test() {
    echo "grpcurl installer self-test failed: $*" >&2
    return 1
}

self_test() (
    local repo_root fixture_dir source_dir base_archive valid_archive checksum
    local truncated_size wrong_source wrong_archive wrong_checksum counter
    local cache_path target_path interop_calls setup_calls prepare_calls install_calls

    repo_root=$(git rev-parse --show-toplevel)
    fixture_dir=$(mktemp -d)
    trap 'rm -rf -- "$fixture_dir"' EXIT
    [[ "$GRPCURL_VERSION" == "1.9.1" ]] \
        || fail_self_test "version pin drifted"
    [[ "$GRPCURL_SHA256" == "588c9c429476d9ed66cd3b2ae32283a6da36e0cfbb7e446f5d6a1b68dc770214" ]] \
        || fail_self_test "checksum pin drifted"
    [[ "$GRPCURL_ASSET" == "grpcurl_1.9.1_linux_x86_64.tar.gz" ]] \
        || fail_self_test "archive name drifted"
    [[ "$GRPCURL_URL" == "https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_x86_64.tar.gz" ]] \
        || fail_self_test "release URL drifted"
    [[ "$GRPCURL_ATTEMPTS" -eq 3 ]] \
        || fail_self_test "retry bound drifted"

    source_dir="$fixture_dir/source"
    mkdir -p "$source_dir"
    cat >"$source_dir/grpcurl" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'grpcurl v1.9.1' >&2
EOF
    chmod +x "$source_dir/grpcurl"
    # The extra gzip member makes the full fixture distinct while its prefix
    # remains extractable. Only the checksum rejects that plausible truncation.
    base_archive="$fixture_dir/base.tar.gz"
    valid_archive="$fixture_dir/valid.tar.gz"
    tar -czf "$base_archive" -C "$source_dir" grpcurl
    cp "$base_archive" "$valid_archive"
    printf '' | gzip >>"$valid_archive"
    checksum=$(sha256sum "$valid_archive" | awk '{print $1}')

    install_from_archive \
        "$GRPCURL_VERSION" "$checksum" "$valid_archive" \
        "$fixture_dir/valid-install"
    [[ -x "$fixture_dir/valid-install/grpcurl" ]] \
        || fail_self_test "verified archive was not installed"

    truncated_size=$(wc -c <"$base_archive")
    head -c "$truncated_size" "$valid_archive" >"$fixture_dir/truncated.tar.gz"
    if install_from_archive \
        "$GRPCURL_VERSION" "$checksum" "$fixture_dir/truncated.tar.gz" \
        "$fixture_dir/truncated-install" 2>/dev/null; then
        fail_self_test "truncated archive was accepted"
    fi
    [[ ! -e "$fixture_dir/truncated-install/grpcurl" ]] \
        || fail_self_test "truncated archive installed a binary"

    if install_from_archive \
        "$GRPCURL_VERSION" \
        0000000000000000000000000000000000000000000000000000000000000000 \
        "$valid_archive" "$fixture_dir/wrong-checksum-install" 2>/dev/null; then
        fail_self_test "wrong checksum was accepted"
    fi
    [[ ! -e "$fixture_dir/wrong-checksum-install/grpcurl" ]] \
        || fail_self_test "wrong-checksum archive installed a binary"

    wrong_source="$fixture_dir/wrong-source"
    mkdir -p "$wrong_source"
    cat >"$wrong_source/grpcurl" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'grpcurl v1.9.0' >&2
EOF
    chmod +x "$wrong_source/grpcurl"
    wrong_archive="$fixture_dir/wrong-version.tar.gz"
    tar -czf "$wrong_archive" -C "$wrong_source" grpcurl
    wrong_checksum=$(sha256sum "$wrong_archive" | awk '{print $1}')
    if install_from_archive \
        "$GRPCURL_VERSION" "$wrong_checksum" "$wrong_archive" \
        "$fixture_dir/wrong-version-install" 2>/dev/null; then
        fail_self_test "wrong grpcurl version was accepted"
    fi
    [[ ! -e "$fixture_dir/wrong-version-install/grpcurl" ]] \
        || fail_self_test "wrong-version binary reached the install path"

    # Cache and retry cases replace only the network primitive and sleep, so
    # the self-test remains offline while exercising the real selection logic.
    counter="$fixture_dir/download-count"
    cache_path="$fixture_dir/cache/$GRPCURL_ASSET"
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

    target_path="$fixture_dir/transient/$GRPCURL_ASSET"
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

    target_path="$fixture_dir/persistent/$GRPCURL_ASSET"
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
    [[ $(cat "$counter") -eq "$GRPCURL_ATTEMPTS" ]] \
        || fail_self_test "persistent failure escaped retry bound"
    [[ ! -e "$target_path" ]] \
        || fail_self_test "persistent failure published an archive"

    (
        # shellcheck disable=SC2317
        curl() { fail_self_test "offline install invoked curl"; }
        # shellcheck disable=SC2317
        download_archive_once() { fail_self_test "offline install downloaded"; }
        install_from_archive \
            "$GRPCURL_VERSION" "$checksum" "$valid_archive" \
            "$fixture_dir/offline-install"
    ) || fail_self_test "offline artifact install failed"

    # Pinned to the current consumer roster; bump when a job that uses the
    # offline artifact path is added or removed (41st consumer: m84).
    interop_calls=$(grep -cF 'uses: ./.github/actions/install-grpcurl-artifact' \
        "$repo_root/.github/workflows/interop.yml")
    [[ "$interop_calls" -eq 41 ]] \
        || fail_self_test "Interop must have 41 offline grpcurl consumers"
    setup_calls=$(grep -cF 'uses: ./.github/actions/install-grpcurl-artifact' \
        "$repo_root/.github/actions/setup-dataplane-host/action.yml")
    [[ "$setup_calls" -eq 1 ]] \
        || fail_self_test "setup-dataplane-host must have one grpcurl consumer"
    prepare_calls=$(grep -R -F -- '.github/scripts/install-grpcurl.sh' \
        "$repo_root/.github/workflows/interop.yml" \
        "$repo_root/.github/workflows/kernel-dataplane.yml" | wc -l)
    [[ "$prepare_calls" -eq 2 ]] \
        || fail_self_test "heavy workflows must have two grpcurl producers"
    install_calls=$(grep -cF -- '--install-archive' \
        "$repo_root/.github/actions/install-grpcurl-artifact/action.yml")
    [[ "$install_calls" -eq 1 ]] \
        || fail_self_test "consumer action must have one offline install"

    if grep -R -F -n 'fullstorydev/grpcurl/releases' \
        "$repo_root/.github/workflows" "$repo_root/.github/actions"; then
        fail_self_test "grpcurl release URL remains outside the installer"
    fi
    if grep -R -F -n 'bash .github/scripts/install-grpcurl.sh' \
        "$repo_root/.github/workflows/interop.yml" \
        "$repo_root/.github/workflows/kernel-dataplane.yml" \
        "$repo_root/.github/actions"; then
        fail_self_test "legacy grpcurl installer invocation remains"
    fi

    printf '%s\n' 'grpcurl installer self-test passed'
)

usage() {
    echo "usage: $0 --prepare-archive ARCHIVE | --install-archive ARCHIVE INSTALL_DIR | --self-test" >&2
    exit 2
}

case ${1:-} in
    --prepare-archive)
        [[ $# -eq 2 ]] || usage
        prepare_archive "$GRPCURL_SHA256" "$GRPCURL_URL" "$2"
        ;;
    --install-archive)
        [[ $# -eq 3 ]] || usage
        install_from_archive "$GRPCURL_VERSION" "$GRPCURL_SHA256" "$2" "$3"
        ;;
    --self-test)
        [[ $# -eq 1 ]] || usage
        self_test
        ;;
    *)
        usage
        ;;
esac
