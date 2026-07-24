#!/usr/bin/env bash

set -euo pipefail

readonly GRPCURL_VERSION="1.9.1"
readonly GRPCURL_SHA256="588c9c429476d9ed66cd3b2ae32283a6da36e0cfbb7e446f5d6a1b68dc770214"
readonly GRPCURL_ASSET="grpcurl_${GRPCURL_VERSION}_linux_x86_64.tar.gz"
readonly GRPCURL_URL="https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/${GRPCURL_ASSET}"
readonly GRPCURL_ATTEMPTS=3

install_grpcurl() (
    local version=${1:?version}
    local sha256=${2:?sha256}
    local url=${3:?url}
    local install_dir=${4:?install directory}
    local work_dir archive reported_version

    work_dir=$(mktemp -d)
    trap 'rm -rf -- "$work_dir"' EXIT
    archive="$work_dir/grpcurl.tar.gz"

    # Download to a file rather than streaming into tar, so extraction cannot
    # see unverified bytes. Single retry mechanism: the caller's loop owns
    # retry and backoff, because only the checksum below catches a truncated
    # or corrupted 200-OK body that `curl --retry` treats as success. Nesting
    # `curl --retry` inside that loop would multiply the worst case past the
    # interop job timeout.
    curl -fsSL \
        --connect-timeout 10 \
        --max-time 120 \
        --output "$archive" \
        "$url"

    if ! printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --status; then
        echo "grpcurl ${version} archive checksum mismatch" >&2
        return 1
    fi

    if [[ -w "$install_dir" ]]; then
        tar -xzf "$archive" -C "$install_dir" grpcurl
    else
        sudo tar -xzf "$archive" -C "$install_dir" grpcurl
    fi

    reported_version=$("$install_dir/grpcurl" -version 2>&1)
    if [[ "$reported_version" != "grpcurl v${version}" ]]; then
        echo "unexpected grpcurl version: ${reported_version}" >&2
        return 1
    fi
    printf '%s\n' "$reported_version"
)

# The hosted release download is the only external fetch every Interop job
# shares, so one CDN hiccup reds a ~38-job run. Retry download *and*
# verification as a unit: a truncated or corrupted archive is re-fetched
# rather than accepted, because each attempt re-runs the checksum and version
# checks and a rejected archive is never installed. Persistent failure still
# fails closed after the bounded attempts, naming the URL.
install_grpcurl_with_retry() {
    local url=${3:?url}
    local attempt

    for ((attempt = 1; attempt <= GRPCURL_ATTEMPTS; attempt++)); do
        if install_grpcurl "$@"; then
            return 0
        fi
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
    local repo_root fixture_dir source_dir base_archive archive checksum truncated_size
    local wrong_version_archive wrong_version_checksum retry_counter
    local named_steps workflow_calls setup_calls

    repo_root=$(git rev-parse --show-toplevel)
    fixture_dir=$(mktemp -d)
    trap 'rm -rf -- "$fixture_dir"' EXIT
    [[ "$GRPCURL_SHA256" == "588c9c429476d9ed66cd3b2ae32283a6da36e0cfbb7e446f5d6a1b68dc770214" ]] \
        || fail_self_test "pinned grpcurl v1.9.1 checksum drifted"
    source_dir="$fixture_dir/source"
    mkdir -p "$source_dir"
    cat >"$source_dir/grpcurl" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'grpcurl v1.9.1' >&2
EOF
    chmod +x "$source_dir/grpcurl"
    # A second empty gzip member makes the full fixture distinct while the
    # prefix remains a valid, extractable archive. Removing that final member
    # therefore models a truncated transfer that tar alone would accept; only
    # the checksum can make the negative case fail before extraction.
    base_archive="$fixture_dir/grpcurl-base.tar.gz"
    archive="$fixture_dir/grpcurl-valid.tar.gz"
    tar -czf "$base_archive" -C "$source_dir" grpcurl
    cp "$base_archive" "$archive"
    printf '' | gzip >>"$archive"
    checksum=$(sha256sum "$archive" | awk '{print $1}')

    mkdir "$fixture_dir/valid-install"
    install_grpcurl \
        "$GRPCURL_VERSION" \
        "$checksum" \
        "file://$archive" \
        "$fixture_dir/valid-install"
    [[ -x "$fixture_dir/valid-install/grpcurl" ]] \
        || fail_self_test "verified archive was not installed"

    truncated_size=$(wc -c <"$base_archive")
    head -c "$truncated_size" "$archive" >"$fixture_dir/grpcurl-truncated.tar.gz"
    mkdir "$fixture_dir/truncated-install"
    if install_grpcurl \
        "$GRPCURL_VERSION" \
        "$checksum" \
        "file://$fixture_dir/grpcurl-truncated.tar.gz" \
        "$fixture_dir/truncated-install" 2>/dev/null; then
        fail_self_test "truncated archive was accepted"
    fi
    [[ ! -e "$fixture_dir/truncated-install/grpcurl" ]] \
        || fail_self_test "truncated archive was extracted"

    mkdir "$fixture_dir/wrong-checksum-install"
    if install_grpcurl \
        "$GRPCURL_VERSION" \
        "0000000000000000000000000000000000000000000000000000000000000000" \
        "file://$archive" \
        "$fixture_dir/wrong-checksum-install" 2>/dev/null; then
        fail_self_test "wrong checksum was accepted"
    fi
    [[ ! -e "$fixture_dir/wrong-checksum-install/grpcurl" ]] \
        || fail_self_test "wrong-checksum archive was extracted"

    mkdir "$fixture_dir/wrong-version-source" "$fixture_dir/wrong-version-install"
    cat >"$fixture_dir/wrong-version-source/grpcurl" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' 'grpcurl v1.9.0' >&2
EOF
    chmod +x "$fixture_dir/wrong-version-source/grpcurl"
    wrong_version_archive="$fixture_dir/grpcurl-wrong-version.tar.gz"
    tar -czf "$wrong_version_archive" \
        -C "$fixture_dir/wrong-version-source" grpcurl
    wrong_version_checksum=$(sha256sum "$wrong_version_archive" | awk '{print $1}')
    if install_grpcurl \
        "$GRPCURL_VERSION" \
        "$wrong_version_checksum" \
        "file://$wrong_version_archive" \
        "$fixture_dir/wrong-version-install" 2>/dev/null; then
        fail_self_test "wrong grpcurl version was accepted"
    fi

    # Retry cases stub the installer and `sleep` so the loop is exercised
    # without network access or real backoff waits.
    retry_counter="$fixture_dir/retry-attempts"
    printf '0' >"$retry_counter"
    (
        sleep() { :; }
        install_grpcurl() {
            local count
            count=$(($(cat "$retry_counter") + 1))
            printf '%s' "$count" >"$retry_counter"
            [[ "$count" -ge 2 ]]
        }
        install_grpcurl_with_retry \
            "$GRPCURL_VERSION" "$GRPCURL_SHA256" "$GRPCURL_URL" /usr/local/bin
    ) 2>/dev/null || fail_self_test "retry did not recover from a transient failure"
    [[ "$(cat "$retry_counter")" -eq 2 ]] \
        || fail_self_test "retry did not stop on the first success"

    printf '0' >"$retry_counter"
    if (
        sleep() { :; }
        install_grpcurl() {
            printf '%s' "$(($(cat "$retry_counter") + 1))" >"$retry_counter"
            return 1
        }
        install_grpcurl_with_retry \
            "$GRPCURL_VERSION" "$GRPCURL_SHA256" "$GRPCURL_URL" /usr/local/bin
    ) 2>/dev/null; then
        fail_self_test "persistent download failure was not surfaced"
    fi
    [[ "$(cat "$retry_counter")" -eq "$GRPCURL_ATTEMPTS" ]] \
        || fail_self_test "retry did not stop after ${GRPCURL_ATTEMPTS} attempts"

    named_steps=$(grep -cE '^[[:space:]]+- name: Install grpcurl' \
        "$repo_root/.github/workflows/interop.yml")
    workflow_calls=$(grep -cF 'bash .github/scripts/install-grpcurl.sh' \
        "$repo_root/.github/workflows/interop.yml")
    [[ "$workflow_calls" -eq "$named_steps" && "$workflow_calls" -gt 0 ]] \
        || fail_self_test \
            "every Interop grpcurl install step must call the shared helper (steps=${named_steps}, calls=${workflow_calls})"

    setup_calls=$(grep -cF 'bash .github/scripts/install-grpcurl.sh' \
        "$repo_root/.github/actions/setup-dataplane-host/action.yml")
    [[ "$setup_calls" -eq 1 ]] \
        || fail_self_test "setup-dataplane-host must call the shared helper exactly once"

    if grep -R -E -n \
        'fullstorydev/grpcurl/releases|grpcurl_.*linux_x86_64\.tar\.gz' \
        "$repo_root/.github/workflows" \
        "$repo_root/.github/actions"; then
        fail_self_test "legacy grpcurl download call site remains outside the helper"
    fi

    printf '%s\n' 'grpcurl installer self-test passed'
)

case ${1:-} in
    "")
        install_grpcurl_with_retry \
            "$GRPCURL_VERSION" \
            "$GRPCURL_SHA256" \
            "$GRPCURL_URL" \
            /usr/local/bin
        ;;
    --self-test)
        self_test
        ;;
    *)
        echo "usage: $0 [--self-test]" >&2
        exit 2
        ;;
esac
