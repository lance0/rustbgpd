#!/bin/sh
set -eu

root=/harness
birdseye=/upstreams/birdseye
ixp_manager=/upstreams/ixp-manager
capture=$(mktemp -d)
server_log=$(mktemp)
server_pid=
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
  rm -rf "$capture" "$server_log"
}
trap cleanup EXIT INT TERM

validate_composer() {
  directory=$1
  expected=$2
  log=$(mktemp)
  if composer validate --strict --no-interaction --working-dir="$directory" >"$log" 2>&1; then
    [ "$expected" = clean ] || { cat "$log" >&2; exit 1; }
  elif [ "$expected" = ixp-gpl-warning ] && \
    [ "$(grep -c '^-' "$log")" -eq 1 ] && \
    grep -Fqx -- '- License "GPL-2.0" is a deprecated SPDX license identifier, use "GPL-2.0-only" or "GPL-2.0-or-later" instead' "$log"; then
    : # Pinned upstream warning; any additional strict warning is fatal.
  else
    cat "$log" >&2
    exit 1
  fi
  rm -f "$log"
}

validate_composer "$birdseye" clean
composer install --working-dir="$birdseye" --no-dev --no-interaction --no-progress --prefer-dist --no-scripts
cp "$root/birdseye.env" "$birdseye/.env"

cd "$birdseye"
php -d display_errors=0 -d log_errors=1 \
  -S 127.0.0.1:18080 -t public public/index.php >"$server_log" 2>&1 &
server_pid=$!
for _ in $(seq 1 30); do
  if curl --silent --fail http://127.0.0.1:18080/api/status >/dev/null; then break; fi
  sleep 1
done
if ! curl --silent --fail http://127.0.0.1:18080/api/status >/dev/null; then
  cat "$server_log" >&2
  exit 1
fi

capture_case() {
  name=$1
  path=$2
  curl --silent --show-error --header 'Accept: application/json' \
    --output "$capture/$name.body" \
    --write-out '%{http_code}\n%{content_type}\n' \
    "http://127.0.0.1:18080$path" >"$capture/$name.meta"
}

capture_case status /api/status
capture_case protocols /api/protocols/bgp
capture_case protocol /api/protocol/pb_as64496
capture_case symbols /api/symbols
capture_case protocol_routes /api/routes/protocol/pb_as64496
capture_case table_routes /api/routes/table/master4
capture_case export_routes /api/routes/export/pb_as64496
capture_case protocol_count /api/routes/count/protocol/pb_as64496
capture_case table_count /api/routes/count/table/master4
capture_case export_count /api/routes/count/export/pb_as64496
capture_case lookup_protocol /api/route/192.0.2.0%2F24/protocol/pb_as64496
capture_case lookup_table /api/route/192.0.2.0%2F24/table/master4
capture_case lookup_export /api/route/192.0.2.0%2F24/export/pb_as64496
capture_case wildcard /api/routes/lc-zwild/protocol/pb_as64496/64496/1101
capture_case bad_prefix /api/route/not-an-ip/table/master4
capture_case over_limit /api/routes/protocol/pb_large_as64498
capture_case missing_protocol /api/protocol/missing
capture_case bird_failure /api/routes/protocol/pb_fail_as64497

CAPTURE_FIXTURES=${CAPTURE_FIXTURES:-0} CAPTURE_OUTPUT=${CAPTURE_OUTPUT:-/capture-output} \
  python3 "$root/verify_capture.py" "$capture"

validate_composer "$ixp_manager" ixp-gpl-warning
composer install --working-dir="$ixp_manager" --no-dev --no-interaction --no-progress --prefer-dist --no-scripts
IXP_MANAGER_ROOT="$ixp_manager" BIRDSEYE_API=http://127.0.0.1:18080/api \
  php "$root/consumer.php" >"$capture/ixp-manager-consumer.json"
consumer_fixture="$root/fixtures/ixp-manager-consumer.json"
if [ "${CAPTURE_FIXTURES:-0}" = 1 ]; then
  cp "$capture/ixp-manager-consumer.json" "/capture-output/$(basename "$consumer_fixture")"
elif ! diff -u "$consumer_fixture" "$capture/ixp-manager-consumer.json"; then
  echo "pinned IXP Manager BirdsEye consumer drifted" >&2
  exit 1
fi

echo "IXP Manager/Bird's Eye pinned contract oracle passed"
