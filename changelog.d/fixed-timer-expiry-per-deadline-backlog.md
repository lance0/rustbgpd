### Fixed

- Expire graceful-restart, long-lived graceful-restart, enhanced
  route-refresh, ORF and RT-Constrain End-of-RIB and conditional
  advertisement timers one deadline at a time. When the work queued at one
  peer's deadline took long enough to drain that a second peer's later
  deadline passed, the second peer was expired in the same turn, before its
  own End-of-RIB, re-advertisement or ROUTE-REFRESH queued ahead of its
  deadline was processed. The peer's routes were then withdrawn and
  announced again, or an End-of-RIB went out ahead of its table. A timer
  now expires only the deadlines that had passed when it was first seen
  due, once the work queued by then drains; a later deadline drains the
  work queued when it is first seen due before it expires.
