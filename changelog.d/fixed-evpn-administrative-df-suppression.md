### Fixed

- EVPN administrative DF preference, algorithm, and Don't-Preempt changes
  retain desired BUM suppression and bound single-active AC blocking while
  replacement routes await acknowledgement. Election still runs immediately
  after origination without a recovery timer, and the replacement EAD-per-EVI
  route is advertised even when the local PE remains non-DF.
