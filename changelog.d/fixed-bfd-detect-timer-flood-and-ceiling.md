### Fixed

- The BFD runtime no longer keeps one timer entry per received control
  packet. Each packet re-armed the detection timer and left the superseded
  deadline queued until it was due, so a peer or on-link sender flooding
  packets with a long advertised interval grew memory by one entry per packet
  for up to about 71.6 minutes. Superseded deadlines are now dropped once they
  could outnumber the live ones, which bounds the queue by the session count.
- The peer's advertised Desired Min TX can no longer stretch BFD detection
  past five minutes. Before, one packet advertising the largest interval and
  multiplier set the detection time to about 71.6 minutes, so a peer that then
  failed went undetected for that long. The window is now at most the larger
  of five minutes and our `min_rx_interval` times the peer's multiplier. See
  [BFD configuration](../docs/reference/configuration.md).
