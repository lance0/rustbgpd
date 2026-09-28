### Fixed

- Publish the locally injected FlowSpec rule count in
  `bgp_rib_prefixes{peer="0.0.0.0",afi_safi="flowspec"}` after injection
  and withdrawal. The count includes local rules out-selected by received
  routes and returns to zero when the last local rule is removed.
