### Upgrade notes

- A BFD peer whose advertised Desired Min TX times its multiplier exceeds
  five minutes, and exceeds our `min_rx_interval` times its multiplier, is now
  detected down after five minutes without a packet. A peer that really
  transmits that slowly will flap. Lower the peer's transmit interval, or
  raise the local profile's `min_rx_interval` to cover it.
