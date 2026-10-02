#!/usr/bin/env bash
# Print the canonical SHA-256 for one exact release archive, or the one BIRD 3 version.
set -euo pipefail

[[ $# == 1 ]] || { echo 'usage: archive-pin.sh ARCHIVE|--bird3-version' >&2; exit 2; }
manifest="$(dirname -- "${BASH_SOURCE[0]}")/../pinned-archives.sha256"
if [[ $1 == --bird3-version ]]; then
    awk '
      $1 !~ /^#/ && index($0, "bird-3.") {
        matches++
        if (NF != 2 || $1 !~ /^[0-9a-f]+$/ || length($1) != 64 ||
            $2 !~ /^bird-3[.][0-9]+[.][0-9]+[.]tar[.]gz$/) malformed = 1
        version = $2
      }
      END {
        if (matches != 1 || malformed) exit 1
        sub(/^bird-/, "", version)
        sub(/[.]tar[.]gz$/, "", version)
        print version
      }
    ' "$manifest" || { echo 'BIRD 3 archive version missing or invalid' >&2; exit 1; }
    exit 0
fi
awk -v archive="$1" '
  $2 == archive { digest = $1; matches++; if (NF != 2) malformed = 1 }
  END {
    if (matches != 1 || malformed || length(digest) != 64 || digest ~ /[^0-9a-f]/) exit 1
    print digest
  }
' "$manifest" || { echo "archive pin missing or invalid: $1" >&2; exit 1; }
