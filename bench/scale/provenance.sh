#!/usr/bin/env bash
# Shared byte-identity helpers for measured receipt inputs.

provenance_sha256_file() {
    local path=$1 digest
    [ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] || return 1
    digest=$(sha256sum -- "$path") || return 1
    digest=${digest%% *}
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$digest"
}

provenance_require_sha256() {
    local path=$1 expected=$2 actual
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || return 1
    actual=$(provenance_sha256_file "$path") || return 1
    [ "$actual" = "$expected" ]
}
