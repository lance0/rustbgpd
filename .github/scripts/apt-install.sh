#!/usr/bin/env bash
# Install apt packages in CI within a fixed time budget.
#
#   apt-install.sh [--command CMD]... [--no-install-recommends] PKG...
#   apt-install.sh --self-test
#
# A slow package mirror must fail its own step with an error that names the
# stall, not hang until the job timeout cancels it. The network work
# (`apt-get update` plus `install --download-only`) runs per mirror in an
# equal slice of APT_INSTALL_BUDGET_SECONDS (default 300). Hosted runners list
# their mirrors in /etc/apt/apt-mirrors.txt (Azure first); when a slice runs
# out, that mirror is demoted to last and the next one gets a slice. Without a
# mirror list (container jobs), the configured sources get two slices. The
# install from the downloaded archives is local and bounded separately.
#
# Each --command names a binary the caller needs; when all of them are
# already on PATH (preinstalled on the runner image), apt is not touched.
# An apt error other than a timeout fails at once: a missing package is not
# a mirror stall. Index errors from `apt-get update` alone only warn, so a
# third-party repo outage does not block an Ubuntu package with fresh lists.

set -uo pipefail

usage() {
    echo "usage: $0 [--command CMD]... [--no-install-recommends] PKG... | --self-test" >&2
    exit 2
}

install_packages() {
    local commands=() install_opts=() packages=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            --command) [[ $# -ge 2 ]] || usage; commands+=("$2"); shift 2 ;;
            --no-install-recommends) install_opts+=("$1"); shift ;;
            -*) usage ;;
            *) packages+=("$1"); shift ;;
        esac
    done
    [[ ${#packages[@]} -gt 0 ]] || usage

    if [[ ${#commands[@]} -gt 0 ]]; then
        local cmd present=true
        for cmd in "${commands[@]}"; do
            command -v "$cmd" >/dev/null 2>&1 || present=false
        done
        if [[ $present == true ]]; then
            echo "already on PATH: ${commands[*]}; not installing ${packages[*]}"
            return 0
        fi
    fi

    local budget=${APT_INSTALL_BUDGET_SECONDS:-300}
    local mirrors_file=${APT_MIRRORS_FILE:-/etc/apt/apt-mirrors.txt}
    local sudo=() mirrors=() tried=()
    [[ $(id -u) -eq 0 ]] || sudo=(sudo)
    local apt=("${sudo[@]}" env DEBIAN_FRONTEND=noninteractive)
    local apt_opts=(-o Acquire::Retries=3 -o Acquire::http::Timeout=30
        -o Acquire::https::Timeout=30 -o DPkg::Lock::Timeout=60)
    if [[ -r $mirrors_file ]]; then
        mapfile -t mirrors < <(awk '$1 ~ /^https?:\/\// {print $1}' "$mirrors_file")
    fi
    local attempts=${#mirrors[@]}
    [[ $attempts -ge 2 ]] || attempts=2
    local slice=$((budget / attempts)) deadline=$((SECONDS + budget))
    local attempt rc end source

    for ((attempt = 0; attempt < attempts; attempt++)); do
        source=${mirrors[0]:-the configured apt sources}
        tried+=("$source")
        end=$((SECONDS + slice))
        [[ $attempt -lt $((attempts - 1)) ]] || end=$deadline
        "${apt[@]}" timeout -k 10 "$(left "$end")" apt-get "${apt_opts[@]}" update
        rc=$?
        if [[ $rc -ne 0 ]] && ! stalled "$rc"; then
            echo "::warning::apt-get update reported repo errors (exit ${rc}); trying the existing package lists"
        fi
        if ! stalled "$rc"; then
            "${apt[@]}" timeout -k 10 "$(left "$end")" apt-get "${apt_opts[@]}" \
                install -y --download-only "${install_opts[@]}" "${packages[@]}"
            rc=$?
            if [[ $rc -eq 0 ]]; then
                if "${apt[@]}" timeout -k 10 120 apt-get "${apt_opts[@]}" \
                    install -y "${install_opts[@]}" "${packages[@]}"; then
                    return 0
                fi
                echo "::error::apt-get install ${packages[*]} failed after a complete download"
                return 1
            fi
            if ! stalled "$rc"; then
                echo "::error::apt-get could not download ${packages[*]} (exit ${rc})"
                return 1
            fi
        fi
        echo "::warning::apt mirror ${source} did not serve ${packages[*]} within its $((slice))s slice"
        if [[ ${#mirrors[@]} -gt 1 ]]; then
            mirrors=("${mirrors[@]:1}" "${mirrors[0]}")
            demote_mirror "$mirrors_file" "${sudo[@]}" || return 1
        fi
    done
    echo "::error::apt mirror stall: ${packages[*]} not downloaded within ${budget}s (tried: ${tried[*]})"
    return 1
}

# Seconds left until $1, at least 1 so timeout never gets 0 (no limit).
left() {
    local rest=$(($1 - SECONDS))
    echo $((rest > 0 ? rest : 1))
}

# timeout exits 124, or 137 when the -k KILL was needed.
stalled() {
    [[ $1 -eq 124 || $1 -eq 137 ]]
}

# Move the first listed mirror to last and renumber priorities in line order,
# so apt's mirror method prefers the next one.
demote_mirror() {
    local file=$1
    shift
    awk '$1 ~ /^https?:\/\// {lines[n++] = $1}
        END {for (i = 1; i <= n; i++) printf "%s\tpriority:%d\n", lines[i % n], i}' "$file" \
        | "$@" tee "$file.next" >/dev/null && "$@" mv "$file.next" "$file"
}

fail_self_test() {
    echo "apt-install self-test failed: $*" >&2
    exit 1
}

# Fakes apt-get and sudo on PATH; never touches the host's apt state.
self_test() (
    local dir out rc
    dir=$(mktemp -d) || exit 1
    trap 'rm -rf -- "$dir"' EXIT
    mkdir "$dir/bin"
    printf '#!/bin/sh\nexec "$@"\n' >"$dir/bin/sudo"
    cat >"$dir/bin/apt-get" <<'EOF'
#!/bin/sh
echo "apt-get $*" >>"$FAKE_APT_LOG"
case "$*" in *update) echo "first mirror $(head -n 1 "$APT_MIRRORS_FILE")" >>"$FAKE_APT_LOG" ;; esac
case "$FAKE_APT_MODE:$*" in
    hang:*update*) exec sleep 30 ;;
    missing:*download-only*) exit 100 ;;
esac
exit 0
EOF
    chmod +x "$dir/bin/sudo" "$dir/bin/apt-get"
    printf 'http://a.example/ubuntu/\tpriority:1\nhttp://b.example/ubuntu/\tpriority:2\n' >"$dir/mirrors"
    export PATH="$dir/bin:$PATH" FAKE_APT_LOG="$dir/log" APT_MIRRORS_FILE="$dir/mirrors"

    out=$(FAKE_APT_MODE=hang APT_INSTALL_BUDGET_SECONDS=2 install_packages ripgrep 2>&1)
    rc=$?
    [[ $rc -ne 0 ]] || fail_self_test "a stalled mirror exited 0"
    grep -q '^::error::apt mirror stall: ripgrep not downloaded within 2s (tried: http://a.example/ubuntu/ http://b.example/ubuntu/)$' <<<"$out" \
        || fail_self_test "stall error did not name the mirrors: $out"
    [[ $(grep -c ' update$' "$dir/log") -eq 2 ]] || fail_self_test "each mirror did not get one attempt"
    grep -qx $'first mirror http://b.example/ubuntu/\tpriority:1' "$dir/log" \
        || fail_self_test "the stalled mirror was not demoted for apt"
    grep -q download-only "$dir/log" && fail_self_test "download ran after a stalled update"

    : >"$dir/log"
    out=$(FAKE_APT_MODE=missing install_packages no-such-package 2>&1)
    rc=$?
    [[ $rc -ne 0 ]] || fail_self_test "a failed download exited 0"
    grep -q '^::error::apt-get could not download no-such-package (exit 100)$' <<<"$out" \
        || fail_self_test "download failure was not reported: $out"
    [[ $(grep -c ' update$' "$dir/log") -eq 1 ]] || fail_self_test "a non-stall failure rotated mirrors"

    : >"$dir/log"
    FAKE_APT_MODE=ok install_packages --no-install-recommends pkg-a pkg-b >/dev/null \
        || fail_self_test "a healthy install failed"
    grep -qx 'apt-get .* install -y --no-install-recommends pkg-a pkg-b' "$dir/log" \
        || fail_self_test "install arguments were not passed through"

    : >"$dir/log"
    install_packages --command sh some-package >/dev/null || fail_self_test "present command failed"
    [[ -s $dir/log ]] && fail_self_test "apt ran for a command already on PATH"
    echo "apt-install self-test passed"
)

if [[ ${1:-} == --self-test ]]; then
    self_test
else
    install_packages "$@"
fi
