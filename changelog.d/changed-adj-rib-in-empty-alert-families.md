### Changed

- The example `BgpPeerAdjRibInEmpty` alert rule now sums `bgp_rib_prefixes`
  across its `all`, `evpn` and `flowspec` series per peer, so an Established
  peer that sends only EVPN or only FlowSpec routes no longer fires it.
  VPN, labeled-unicast, BGP-LS and RTC paths are not counted by the gauge, so
  a peer that sends only those families still fires; silence the rule for
  such peers as for send-only peers. **Operator-visible:** the alert no
  longer carries an `afi_safi="all"` label; routes or silences that match on
  it need updating.
