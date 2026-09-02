#!/bin/sh
# M106 differential lab — canned bgpq4 replacement (the M90 stub plus the
# white-listed origin AS64510, which arouteserver also expands).
#
# arouteserver shells out to bgpq4 (configured via `bgpq3_path`) for
# two query shapes (arouteserver 1.23.2, pierky/arouteserver image
# pinned in scripts/test-m106-rs-white-list-control-differential.sh):
#   - origin-ASN expansion of an AS-SET:
#         bgpq4 -h <host> -S <sources> -3 -j -f 1 -l asn_list <object>
#     answer: {"asn_list": [<asn>, ...]} (bare integers);
#   - prefix expansion:
#         bgpq4 -h <host> -S <sources> -3 -j -4|-6 -A -l prefix_list <object>
#     answer: {"prefix_list": [<record>, ...]} (bgpq4 -j shape:
#     "exact" / "greater-equal" / "less-equal" keys).
# The mode marker is the -l label, NOT a -t flag; queries for a bare
# ASxxx object skip bgpq4 entirely in ASN mode but still hit it in
# prefix mode. IPv6 prefix queries (-6) get an empty list: the site is
# IPv4-only, and answering them with IPv4 records would poison the
# rendered IPv6 prefix sets.
#
# The lab's AS-SETs are RFC 5398 documentation objects with no live
# IRR data, so this stub answers from the canned site model instead.
# The answers here MUST stay in lockstep with the irrdb_info bundles
# in context.yml — that lockstep is exactly what the differential
# verdicts prove end to end.

label=""
ip_ver=4
object=""
prev=""
for arg in "$@"; do
    case "$prev" in
        -l) label="$arg" ;;
    esac
    case "$arg" in
        -6) ip_ver=6 ;;
    esac
    prev="$arg"
    object="$arg"
done

emit() {
    printf '{"%s": [%s]}\n' "$label" "$1"
}

case "$label" in
    asn_list)
        case "$object" in
            AS-M90-ONE|AS64500)   emit "64500" ;;
            AS-M90-TWO|AS64501)   emit "64501" ;;
            AS-M90-THREE|AS64502) emit "64502" ;;
            AS64510)              emit "64510" ;;
            *) echo "bgpq4-stub: unknown ASN-mode object: $object" >&2; exit 1 ;;
        esac
        ;;
    prefix_list)
        if [ "$ip_ver" = "6" ]; then
            emit ""
            exit 0
        fi
        case "$object" in
            AS-M90-ONE|AS64500)
                emit '{"prefix": "198.51.100.0/24", "exact": true}, {"prefix": "203.0.113.0/26", "exact": false, "greater-equal": 26, "less-equal": 28}' ;;
            AS-M90-TWO|AS64501)
                emit '{"prefix": "203.0.113.128/25", "exact": true}' ;;
            AS-M90-THREE|AS64502)
                emit '{"prefix": "203.0.113.64/26", "exact": true}' ;;
            # The white-listed origin has no route objects of its own.
            AS64510) emit "" ;;
            *) echo "bgpq4-stub: unknown prefix-mode object: $object" >&2; exit 1 ;;
        esac
        ;;
    *)
        echo "bgpq4-stub: no -l label in query: $*" >&2
        exit 1
        ;;
esac
