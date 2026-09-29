### Fixed

- EVPN remote-MAC and MAC/IP projection now treats an absent MAC Mobility
  sequence as zero before selecting the lower VTEP address, matching
  RFC 7432 section 15. An explicit sequence zero no longer displaces a
  route from a lower VTEP solely because the community is present.
  Type 5 gateway-IP resolution uses the same effective sequence, including
  preserving ambiguity when distinct gateway MACs tie at sequence zero.
