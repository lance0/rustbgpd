### Fixed

- Bound the table resizes that can land inside one UPDATE while a full table
  is learned in other families too. The selected unicast, labeled-unicast and
  EVPN route maps, the received labeled-unicast key index, the per-route
  advertised next-hop overrides and the global attribute intern set now split
  into 16 hash shards past 16,384 entries, as the VPN maps already did, so a
  resize rehashes one shard instead of the whole table. Previously one insert
  near a million unicast prefixes rehashed the whole selected-route map and
  held the RIB actor for that time.
