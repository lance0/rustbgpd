#!/bin/sh
# M107 RFC 8950 uniform-fleet lab — canned bgpq4 replacement.
#
# Same query shapes as the M90 stub (tests/interop/m90-differential/
# bgpq4-stub.sh): `-l asn_list` for origin expansion, `-l prefix_list`
# with -4/-6 for prefixes. Unlike M90 this site is dual-family, so the
# IPv6 queries are answered too. The answers MUST stay in lockstep with
# the irrdb_info bundles in context.yml.

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
            AS-M107-ONE|AS64500) emit "64500" ;;
            AS-M107-TWO|AS64501) emit "64501" ;;
            *) echo "bgpq4-stub: unknown ASN-mode object: $object" >&2; exit 1 ;;
        esac
        ;;
    prefix_list)
        case "$ip_ver/$object" in
            4/AS-M107-ONE|4/AS64500)
                emit '{"prefix": "198.51.100.0/24", "exact": false, "greater-equal": 24, "less-equal": 25}' ;;
            6/AS-M107-ONE|6/AS64500)
                emit '{"prefix": "2001:db8:1::/48", "exact": true}' ;;
            4/AS-M107-TWO|4/AS64501)
                emit '{"prefix": "203.0.113.0/24", "exact": true}' ;;
            6/AS-M107-TWO|6/AS64501)
                emit '{"prefix": "2001:db8:2::/48", "exact": true}' ;;
            *) echo "bgpq4-stub: unknown prefix-mode object: $ip_ver/$object" >&2; exit 1 ;;
        esac
        ;;
    *)
        echo "bgpq4-stub: no -l label in query: $*" >&2
        exit 1
        ;;
esac
