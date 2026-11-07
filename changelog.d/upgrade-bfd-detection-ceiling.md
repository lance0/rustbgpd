### Upgrade notes

- A BFD peer whose advertised Desired Min TX times its multiplier exceeds
  both five minutes and our `min_rx_interval` times its multiplier now has
  its detection window clamped to the larger of those two. If the peer really
  transmits that slowly, its regular packets keep the session up only while
  the gap between them fits inside the clamped window, and then fewer missed
  packets are tolerated. A peer whose transmit interval itself exceeds the
  window times out even with no loss: for example, a 600 s Desired Min TX
  against a 300 ms local `min_rx_interval` and multiplier 3 expires at the
  five-minute clamp. Lower the peer's transmit interval, or raise the local
  profile's `min_rx_interval` so the window covers the peer's multiplier.
