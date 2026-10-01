### Added

- Alpha `rbgp evpn explain imet --argument-rd RD --argument-esi ESI` and
  additive `ExplainEvpnRoute` fields inspect one caller-selected IMET and
  EAD-per-ES pair from the same RIB snapshot. Results distinguish composed
  candidate SIDs, LOC:FUNC fallback, requested-pair Argument-length conflict,
  unavailable inputs and ambiguity. Original egress identity and forwarding
  are not established; existing raw SID and per-route views are unchanged.
