def events($message; $interface):
    [.[] | select(.fields.message? == $message and .fields.interface? == $interface)];

def addresses($message; $interface; $address):
    [events($message; $interface)[] | select(.fields.address? == $address)];

($ARGS.named) as $a
| if ($a.mode // "next-hop") == "packets" then
    [.[] | select(.type == "RA" and .src == $a.ll)] as $ras
    | [.[] | select(.type == "RS" and .src == $a.own and .ns >= ($a.recovery | tonumber))] as $rss
    | ($rss | first) as $rs
    | ($ras | map(select(.ns < ($a.recovery | tonumber))) | last) as $prior
    | ($ras | map(select(.ns > $rs.ns)) | first) as $ra
    | ($ras | length) > ($a.before | tonumber) and $prior != null and $rs != null and $ra != null
        and ([$ras[] | select(.ns >= ($a.recovery | tonumber) and .ns < $rs.ns)] | length) == 0
        and ([.[] | select(.type == "RS" and .src != $a.own
            and .ns > $prior.ns and .ns < $ra.ns)] | length) == 0
        and $ra.ns - $rs.ns <= 10000000000
        and $ra.ns - $prior.ns < 200000000000
elif $a.mode == "own" then
    ([.[] | select(.fields.message? == "router discovery packet dropped"
        and .fields.reason? == "own_address" and .fields.source? == $a.source)] | length)
        > ($a.drop_before | tonumber)
    and (events("unnumbered: peer address learned"; "eth2") | length)
        == ($a.learned_before | tonumber)
    and (events("unnumbered: a second router advertises on an interface-only link"; "eth2") | length)
        == ($a.conflict_before | tonumber)
elif $a.mode == "conflict" then
    (addresses("unnumbered: peer address learned"; "eth2"; $a.other) | length)
        > ($a.learned_before | tonumber)
    and ([events("unnumbered: a second router advertises on an interface-only link"; "eth2")[]
        | select(.fields.bound? == $a.bound and .fields.other? == $a.other)] | length)
        > ($a.conflict_before | tonumber)
elif $a.mode == "expiry" then
    (addresses("unnumbered: peer address expired"; "eth2"; $a.bound) | length)
        > ($a.expired_before | tonumber)
    and (addresses("unnumbered: peer address expired"; "eth2"; $a.other) | length)
        == ($a.other_expired_before | tonumber)
    and (events("unnumbered: binding changed"; "eth2") | length)
        == ($a.binding_before | tonumber)
    and (events("unnumbered: bound peer added"; "eth2") | length)
        == ($a.added_before | tonumber)
    and (events("unnumbered: ending the bound session"; "eth2") | length)
        == ($a.ending_before | tonumber)
elif $a.mode == "down" then
    any(.neighbors[]?; .config.interface == "eth1" and .stale != true
        and (.state == "SESSION_STATE_ESTABLISHED" or .state == 6))
    and all(.neighbors[]?; .config.interface != "eth2"
        or (.stale != true and .state != "SESSION_STATE_ESTABLISHED" and .state != 6))
elif ($a.mode // "next-hop") == "next-hop" then
    .prefix == $a.prefix and
    (.paths // [] | any(.[]; .valid == true and
        any(.nexthops[]?; .afi == "ipv6" and .scope == "link-local" and .used == true and .ip == $a.nh)))
else
    error("unknown M53b oracle mode")
end
