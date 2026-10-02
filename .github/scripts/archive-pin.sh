#!/usr/bin/env bash
# Print the canonical SHA-256 for one exact release archive.
set -euo pipefail

[[ $# == 1 ]] || { echo 'usage: archive-pin.sh ARCHIVE' >&2; exit 2; }
manifest="$(dirname -- "${BASH_SOURCE[0]}")/../pinned-archives.sha256"
awk -v archive="$1" '
  $2 == archive { digest = $1; matches++; if (NF != 2) malformed = 1 }
  END {
    if (matches != 1 || malformed || length(digest) != 64 || digest ~ /[^0-9a-f]/) exit 1
    print digest
  }
' "$manifest" || { echo "archive pin missing or invalid: $1" >&2; exit 1; }
