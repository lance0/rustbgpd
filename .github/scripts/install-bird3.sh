#!/usr/bin/env bash

set -euo pipefail

BIRD3_VERSION="3.3.1"
BIRD3_SHA256="d5a8d651d6184c18252954932bb249dfee1fd213b3665cdd86226ac45edc0190"
BIRD3_COVERAGE_LABEL=""
while [[ ${1:-} == --version || ${1:-} == --sha256 || ${1:-} == --coverage-label ]]; do
    option=$1
    [[ $# -ge 2 ]] || {
        echo "install-bird3: ${option} requires a value" >&2
        exit 2
    }
    case "$option" in
        --version) BIRD3_VERSION=$2 ;;
        --sha256) BIRD3_SHA256=$2 ;;
        --coverage-label) BIRD3_COVERAGE_LABEL=$2 ;;
    esac
    shift 2
done
[[ $BIRD3_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "install-bird3: invalid BIRD version: ${BIRD3_VERSION}" >&2
    exit 2
}
[[ $BIRD3_SHA256 =~ ^[0-9a-f]{64}$ ]] || {
    echo "install-bird3: invalid BIRD SHA-256" >&2
    exit 2
}
if [[ -z $BIRD3_COVERAGE_LABEL ]]; then
    BIRD3_COVERAGE_LABEL="M43 (TCP-AO interop vs BIRD ${BIRD3_VERSION}) skipped"
fi
readonly BIRD3_VERSION BIRD3_SHA256 BIRD3_COVERAGE_LABEL
readonly BIRD3_ASSET="bird-${BIRD3_VERSION}.tar.gz"
readonly BIRD3_URL="https://bird.nic.cz/download/${BIRD3_ASSET}"
readonly BIRD3_ATTEMPTS=3
# prepare_archive separates a third-party outage from a supply-chain signal so
# callers can act on the difference. 3 = the archive bytes never arrived (every
# attempt failed to fetch); 4 = bytes arrived and failed the pinned checksum or
# source-version check. Only 3 is tolerated downstream; see the bird3_archive
# job in .github/workflows/kernel-dataplane.yml.
readonly BIRD3_RC_UNAVAILABLE=3
readonly BIRD3_RC_CORRUPT=4

verify_archive() {
    local sha256=${1:?sha256}
    local archive=${2:?archive}

    [[ -f "$archive" ]] || return 1
    if ! printf '%s  %s\n' "$sha256" "$archive" \
        | sha256sum --check --status; then
        echo "bird3 archive checksum mismatch: ${archive}" >&2
        return 1
    fi
}

verify_archive_contents() {
    local sha256=${1:?sha256}
    local archive=${2:?archive}
    local reported

    verify_archive "$sha256" "$archive" || return 1
    # Source tarball: the analogue of a binary --version check is the
    # version-named top directory plus the upstream VERSION file. grep runs
    # without -q so it drains the listing (pipefail would otherwise surface
    # tar's SIGPIPE on an early -q exit as a spurious failure).
    if ! tar -tzf "$archive" | grep -x "bird-${BIRD3_VERSION}/configure" >/dev/null; then
        echo "bird3 archive did not contain bird-${BIRD3_VERSION}/configure" >&2
        return 1
    fi
    reported=$(tar -xzOf "$archive" "bird-${BIRD3_VERSION}/VERSION") || return 1
    if [[ "$reported" != "$BIRD3_VERSION" ]]; then
        echo "unexpected bird3 source version: ${reported}" >&2
        return 1
    fi
}

stage_archive() (
    local sha256=${1:?sha256}
    local archive=${2:?archive}
    local stage_dir=${3:?stage directory}
    local staged_target

    # This path is deliberately offline. Only the producer may fetch the
    # release archive; consumers re-verify the same-run artifact before the
    # bird3 image build context sees any bytes. The archive itself is staged
    # (not extracted): Dockerfile.bird3 re-verifies the checksum inside the
    # build before extraction.
    verify_archive_contents "$sha256" "$archive" || return 1
    mkdir -p "$stage_dir"
    staged_target=$(mktemp "${stage_dir}/.${BIRD3_ASSET}.XXXXXX")
    trap 'rm -f -- "$staged_target"' EXIT
    install -m 0644 "$archive" "$staged_target"
    mv -f -- "$staged_target" "${stage_dir}/${BIRD3_ASSET}"
    printf 'staged verified bird %s source archive\n' "$BIRD3_VERSION"
)

# The upstream archive is a third party. When it will not serve the pinned
# tarball at all, say so where a human reading the run will see it: an
# annotation in the run UI plus a line in the job summary naming the scenario
# that loses coverage, the reason, and the URL that refused. This is the only
# site that holds the URL, so the loud text cannot drift from the real target.
announce_unavailable() {
    local url=${1:?url}
    local message

    message="${BIRD3_COVERAGE_LABEL}: the pinned"
    message+=" bird ${BIRD3_VERSION} source archive is unavailable upstream"
    message+=" after ${BIRD3_ATTEMPTS} attempts (${url})."
    message+=" This is third-party unavailability, not a rustbgpd failure;"
    message+=" re-run once upstream recovers."
    echo "::warning::${message}" >&2
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        printf '%s\n' "$message" >>"$GITHUB_STEP_SUMMARY"
    fi
}

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
    local fetched=0

    if verify_archive_contents "$sha256" "$archive" 2>/dev/null; then
        echo "using verified cached bird3 archive"
        return 0
    fi
    if [[ -e "$archive" ]]; then
        echo "::warning::discarding invalid cached bird3 archive" >&2
        rm -f -- "$archive"
    fi

    mkdir -p "$(dirname "$archive")"
    for ((attempt = 1; attempt <= BIRD3_ATTEMPTS; attempt++)); do
        staged_archive=$(mktemp "${archive}.download.XXXXXX")
        if download_archive_once "$url" "$staged_archive"; then
            fetched=1
            if verify_archive_contents "$sha256" "$staged_archive"; then
                mv -f -- "$staged_archive" "$archive"
                echo "downloaded and verified bird3 archive"
                return 0
            fi
        fi
        rm -f -- "$staged_archive"
        if ((attempt < BIRD3_ATTEMPTS)); then
            echo "::warning::bird3 download/verify attempt ${attempt}/${BIRD3_ATTEMPTS} failed; retrying" >&2
            sleep $((attempt * 5))
        fi
    done

    if ((fetched)); then
        # Bytes arrived and did not match the pinned checksum or the pinned
        # source version. That is a supply-chain signal, not an outage, and it
        # stays hard-red no matter how many times it repeats.
        echo "::error::bird3 archive failed verification after ${BIRD3_ATTEMPTS} attempts: ${url}" >&2
        return "$BIRD3_RC_CORRUPT"
    fi
    announce_unavailable "$url"
    return "$BIRD3_RC_UNAVAILABLE"
}

fail_self_test() {
    echo "bird3 installer self-test failed: $*" >&2
    return 1
}

self_test() (
    local fixture_dir source_dir valid_archive valid_checksum wrong_dir wrong_archive
    local wrong_checksum partial_archive expected_url staged_hash attempts
    local summary_file rc

    fixture_dir=$(mktemp -d)
    trap 'rm -rf -- "$fixture_dir"' EXIT
    [[ "$BIRD3_VERSION" == "3.3.1" ]] || fail_self_test "version pin drifted"
    [[ "$BIRD3_SHA256" == "d5a8d651d6184c18252954932bb249dfee1fd213b3665cdd86226ac45edc0190" ]] \
        || fail_self_test "checksum pin drifted"
    [[ "$BIRD3_ASSET" == "bird-3.3.1.tar.gz" ]] \
        || fail_self_test "archive name drifted"
    printf -v expected_url '%s%s' \
        'https://bird.nic.cz' \
        '/download/bird-3.3.1.tar.gz'
    [[ "$BIRD3_URL" == "$expected_url" ]] \
        || fail_self_test "release URL drifted"
    [[ "$BIRD3_ATTEMPTS" -eq 3 ]] || fail_self_test "retry bound drifted"

    source_dir="$fixture_dir/source/bird-3.3.1"
    mkdir -p "$source_dir"
    printf '#!/bin/sh\n' >"$source_dir/configure"
    printf '3.3.1\n' >"$source_dir/VERSION"
    valid_archive="$fixture_dir/valid.tar.gz"
    tar -czf "$valid_archive" -C "$fixture_dir/source" bird-3.3.1
    valid_checksum=$(sha256sum "$valid_archive" | awk '{print $1}')

    stage_archive "$valid_checksum" "$valid_archive" \
        "$fixture_dir/stage" >/dev/null
    [[ -f "$fixture_dir/stage/$BIRD3_ASSET" ]] \
        || fail_self_test "verified archive was not staged"
    cmp -s "$valid_archive" "$fixture_dir/stage/$BIRD3_ASSET" \
        || fail_self_test "staged archive bytes drifted"
    staged_hash=$(sha256sum "$fixture_dir/stage/$BIRD3_ASSET" | awk '{print $1}')

    if stage_archive "$BIRD3_SHA256" "$valid_archive" \
        "$fixture_dir/stage" 2>/dev/null; then
        fail_self_test "wrong checksum was accepted"
    fi
    [[ "$(sha256sum "$fixture_dir/stage/$BIRD3_ASSET" | awk '{print $1}')" == "$staged_hash" ]] \
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

    partial_archive="$fixture_dir/no-configure.tar.gz"
    rm -f -- "$source_dir/configure"
    tar -czf "$partial_archive" -C "$fixture_dir/source" bird-3.3.1
    printf '#!/bin/sh\n' >"$source_dir/configure"
    if stage_archive "$(sha256sum "$partial_archive" | awk '{print $1}')" \
        "$partial_archive" "$fixture_dir/partial" 2>/dev/null; then
        fail_self_test "archive without configure was accepted"
    fi

    wrong_dir="$fixture_dir/wrong/bird-3.3.1"
    mkdir -p "$wrong_dir"
    printf '#!/bin/sh\n' >"$wrong_dir/configure"
    printf '3.3.0\n' >"$wrong_dir/VERSION"
    wrong_archive="$fixture_dir/wrong-version.tar.gz"
    tar -czf "$wrong_archive" -C "$fixture_dir/wrong" bird-3.3.1
    wrong_checksum=$(sha256sum "$wrong_archive" | awk '{print $1}')
    if stage_archive "$wrong_checksum" "$wrong_archive" \
        "$fixture_dir/stage" 2>/dev/null; then
        fail_self_test "wrong source version was accepted"
    fi
    [[ "$(sha256sum "$fixture_dir/stage/$BIRD3_ASSET" | awk '{print $1}')" == "$staged_hash" ]] \
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
        | grep -Fxq "using verified cached bird3 archive" \
        || fail_self_test "warm cache attempted an upstream fetch"

    # Upstream refused to serve the bytes at all (a 403/5xx makes curl -f
    # exit non-zero). That is third-party unavailability: distinct exit code,
    # loud annotation, and a job-summary line naming scenario/reason/URL.
    attempts=0
    download_archive_once() {
        ((attempts += 1))
        return 22
    }
    summary_file="$fixture_dir/step-summary.md"
    : >"$summary_file"
    rc=0
    GITHUB_STEP_SUMMARY="$summary_file" \
        prepare_archive "$valid_checksum" "https://example.invalid/unavailable" \
        "$fixture_dir/cold-cache.tar.gz" >/dev/null 2>"$fixture_dir/unavailable.err" \
        || rc=$?
    [[ "$rc" -eq "$BIRD3_RC_UNAVAILABLE" ]] \
        || fail_self_test "unreachable upstream did not report BIRD3_RC_UNAVAILABLE"
    [[ "$attempts" -eq "$BIRD3_ATTEMPTS" ]] \
        || fail_self_test "cold-cache retry bound was not enforced"
    [[ ! -e "$fixture_dir/cold-cache.tar.gz" ]] \
        || fail_self_test "failed cold-cache fetch left an artifact"
    grep -Fq '::warning::M43' "$fixture_dir/unavailable.err" \
        || fail_self_test "unavailable upstream did not emit a warning annotation"
    grep -Fq 'https://example.invalid/unavailable' "$summary_file" \
        || fail_self_test "job summary did not name the upstream URL"
    grep -Fq 'M43' "$summary_file" \
        || fail_self_test "job summary did not name the skipped scenario"

    # Bytes arrived and failed verification. A checksum mismatch on a file that
    # DID download is a supply-chain signal, not an outage: separate exit code,
    # no skip annotation, no job-summary excuse.
    attempts=0
    download_archive_once() {
        ((attempts += 1))
        printf '<html>503</html>\n' >"$2"
    }
    : >"$summary_file"
    rc=0
    GITHUB_STEP_SUMMARY="$summary_file" \
        prepare_archive "$valid_checksum" "https://example.invalid/corrupt" \
        "$fixture_dir/corrupt-cache.tar.gz" >/dev/null 2>"$fixture_dir/corrupt.err" \
        || rc=$?
    [[ "$rc" -eq "$BIRD3_RC_CORRUPT" ]] \
        || fail_self_test "unverifiable download did not report BIRD3_RC_CORRUPT"
    [[ "$attempts" -eq "$BIRD3_ATTEMPTS" ]] \
        || fail_self_test "corrupt-download retry bound was not enforced"
    [[ ! -e "$fixture_dir/corrupt-cache.tar.gz" ]] \
        || fail_self_test "failed corrupt download left an artifact"
    [[ ! -s "$summary_file" ]] \
        || fail_self_test "corrupt download wrote a skip excuse to the job summary"
    if grep -Fq '::warning::M43' "$fixture_dir/corrupt.err"; then
        fail_self_test "corrupt download emitted a skip annotation"
    fi

    # shellcheck disable=SC2317
    curl() { fail_self_test "offline stage invoked curl"; }
    stage_archive "$valid_checksum" "$valid_archive" \
        "$fixture_dir/offline-stage" >/dev/null \
        || fail_self_test "offline archive stage failed"

    echo "bird3 installer self-test passed"
)

usage() {
    echo "usage: $0 [--version VERSION --sha256 SHA256] [--coverage-label LABEL] (--prepare-archive ARCHIVE | --stage-archive ARCHIVE STAGE_DIR | --self-test)" >&2
    return 2
}

case "${1:-}" in
    --prepare-archive)
        [[ $# -eq 2 ]] || usage
        prepare_archive "$BIRD3_SHA256" "$BIRD3_URL" "$2"
        ;;
    --stage-archive)
        [[ $# -eq 3 ]] || usage
        stage_archive "$BIRD3_SHA256" "$2" "$3"
        ;;
    --self-test)
        [[ $# -eq 1 ]] || usage
        self_test
        ;;
    *) usage ;;
esac
