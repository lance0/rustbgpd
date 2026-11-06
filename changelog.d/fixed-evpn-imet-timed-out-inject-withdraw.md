### Fixed

- An EVPN Type 3 (IMET) inject whose RIB acknowledgement timed out is now
  tracked as possibly installed, so the rollback of a failed L2VNI converge
  and the shutdown withdraw sweep withdraw it. Previously a backlogged RIB
  could apply the inject after the timeout and leave the Type 3 route
  advertised after its VNI was rolled back or the daemon stopped, so remote
  VTEPs kept sending BUM traffic toward it. A withdraw of a route the RIB
  never installed still counts as withdrawn.
