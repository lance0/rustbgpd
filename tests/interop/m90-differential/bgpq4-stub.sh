#!/bin/sh
# M90 differential lab — canned bgpq4 replacement.
#
# arouteserver shells out to bgpq4 (configured via `bgpq3_path`) for
# two query shapes:
#   - origin-ASN expansion of an AS-SET (invoked with -t): JSON object
#     mapping the requested label to a list of AS numbers;
#   - prefix expansion (no -t): JSON object mapping the requested
#     label to a list of prefix records (bgpq4 -j shape: "exact" /
#     "greater-equal" / "less-equal" keys).
#
# The lab's AS-SETs are RFC 5398 documentation objects with no live
# IRR data, so this stub answers from the canned site model instead.
# The answers here MUST stay in lockstep with the irrdb_info bundles
# in context.yml — that lockstep is exactly what the differential
# verdicts prove end to end.
#
# Argument handling: the requested object is the last argument; the
# JSON label follows -l when present (bgpq4's default is "NN"); -t
# selects ASN mode. Unknown flags are skipped, so minor differences in
# arouteserver's bgpq4 invocation across versions do not break the
# stub as long as those three conventions hold.

label="NN"
asn_mode=0
object=""
prev=""
for arg in "$@"; do
    case "$prev" in
        -l) label="$arg" ;;
    esac
    case "$arg" in
        -t) asn_mode=1 ;;
    esac
    prev="$arg"
    object="$arg"
done

emit_asns() {
    printf '{"%s": [%s]}\n' "$label" "$1"
}

emit_prefixes() {
    printf '{"%s": [%s]}\n' "$label" "$1"
}

if [ "$asn_mode" = "1" ]; then
    case "$object" in
        AS-M90-ONE|AS64500)   emit_asns "64500" ;;
        AS-M90-TWO|AS64501)   emit_asns "64501" ;;
        AS-M90-THREE|AS64502) emit_asns "64502" ;;
        *) echo "bgpq4-stub: unknown ASN-mode object: $object" >&2; exit 1 ;;
    esac
else
    case "$object" in
        AS-M90-ONE|AS64500)
            emit_prefixes '{"prefix": "198.51.100.0/24", "exact": true}, {"prefix": "203.0.113.0/26", "exact": false, "greater-equal": 26, "less-equal": 28}' ;;
        AS-M90-TWO|AS64501)
            emit_prefixes '{"prefix": "203.0.113.128/25", "exact": true}' ;;
        AS-M90-THREE|AS64502)
            emit_prefixes '{"prefix": "203.0.113.64/26", "exact": true}' ;;
        *) echo "bgpq4-stub: unknown prefix-mode object: $object" >&2; exit 1 ;;
    esac
fi
