### Fixed

- End-of-RIB and EVPN End-of-Route-Refresh retries now examine up to eight
  peer entries per tick. The same allowance covers marker wakeups after a
  non-unicast selection release or an RT membership rebuild. Held markers
  no longer require a peer scan to arm the retry timer.
