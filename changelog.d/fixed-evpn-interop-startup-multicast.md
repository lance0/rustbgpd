### Fixed

- Disable host multicast membership before bridge and VXLAN link-up in EVPN
  interoperability fixtures, preventing startup IGMP reports from creating
  unrelated segment MAC advertisements in handover tests.
