### Fixed

- Forward aliased known unicast through a healthy bound all-active Ethernet Segment
  when only an ES peer learned the CE MAC. Eligible peer Type 2 routes now
  create owned local-port FDB rows with pre-apply local/foreign ownership
  checks, VLAN scope, and duplicate-MAC quarantine. Withdrawal, drain, link failure,
  and segment removal remove that forwarding state. All-active CE forwarding
  requires `interface`; peer-only routes do not create new BGP advertisements.
  After restart, live peer forwarding retains validated local VLAN siblings
  and converts an adopted overlay row without waiting for orphan-reap grace.
  Single-active DF recovery retains ordinary local MAC relearning.
