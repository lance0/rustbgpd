### Fixed

- Forward aliased known unicast through a healthy bound Ethernet Segment
  when only an ES peer learned the CE MAC. Eligible peer Type 2 routes now
  create owned local-port FDB rows with pre-apply local/foreign ownership
  checks, VLAN scope, and duplicate-MAC quarantine. Withdrawal, drain, link failure,
  and segment removal remove that forwarding state. All-active CE forwarding
  requires `interface`; peer-only routes do not create new BGP advertisements.
