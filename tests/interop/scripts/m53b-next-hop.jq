.prefix == $prefix and
(.paths // [] | any(.[]; .valid == true and
    any(.nexthops[]?; .afi == "ipv6" and .scope == "link-local" and .used == true and .ip == $nh)))
