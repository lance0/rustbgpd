#!/bin/bash
# phase 0 preflight: boot a side's image with the rendered config and record
# behavioral event-history signals. usage: preflight.sh <side> <off|on>
# side base gets the [security.grpc] legacy block (see MANIFEST); head/c do not.
set -u
SIDE="$1"; MODE="$2"
S=<runs>
L996=<runs>
IMG="bgperf/rustbgpd:ab-${SIDE}"
DIR="$S/preflight/${SIDE}-${MODE}"
CTN="bgperf_preflight"
OUT="$S/preflight_${SIDE}_${MODE}.txt"

rm -rf "$DIR"; mkdir -p "$DIR"
# Rendered config surface = the prior rebaseline's, with the event_history block set per MODE.
awk -v mode="$MODE" '
    /^\[event_history\]/ { print; getline; print "enabled = " (mode=="on" ? "true" : "false"); next }
    { print }
' "$L996/config.toml" > "$DIR/config.toml"
if [ "$SIDE" = "base" ]; then
    # Insert the legacy authz block after the telemetry block, as the shim does.
    awk '
        { print }
        /^log_format/ { print ""; print "[security.grpc]"; print "enforcement = \"legacy\"" }
    ' "$DIR/config.toml" > "$DIR/config.tmp" && mv "$DIR/config.tmp" "$DIR/config.toml"
fi

docker rm -f "$CTN" >/dev/null 2>&1
{
    echo "== preflight side=$SIDE mode=$MODE img=$IMG $(docker inspect -f '{{.Id}}' "$IMG")"
    docker run -d --name "$CTN" -v "$DIR:/root/config" --entrypoint bash "$IMG" \
        -c 'ulimit -n 65536; cd /root/config && exec rustbgpd /root/config/config.toml > /root/config/rustbgpd.log 2>&1' >/dev/null
    sleep 6
    echo "running: $(docker inspect -f '{{.State.Running}}' "$CTN" 2>/dev/null)"
    echo "-- log event-history lines:"
    grep -i 'event.history\|outbox' "$DIR/rustbgpd.log" | head -5
    echo "-- db files in container:"
    docker exec "$CTN" bash -c "find / -xdev \( -name '*.sqlite*' -o -name '*events*.db*' -o -name '*.db' \) 2>/dev/null | grep -v proc" 2>/dev/null | head -5
    echo "-- outbox metrics:"
    IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CTN")
    curl -s --max-time 3 "http://$IP:9179/metrics" 2>/dev/null | grep -c '^bgp_event_outbox' || echo "metrics unreachable"
    echo "-- last log lines:"
    tail -3 "$DIR/rustbgpd.log"
} > "$OUT" 2>&1
docker rm -f "$CTN" >/dev/null 2>&1
cat "$OUT"
