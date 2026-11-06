### Upgrade notes

- A BFD peer whose advertised Desired Min TX times its multiplier exceeds
  both five minutes and our `min_rx_interval` times its multiplier now has
  its detection window clamped to the larger of those two. If the peer really
  transmits that slowly, its regular packets still keep the session up, but
  fewer consecutive missed packets fit in the window before it is declared
  down. Lower the peer's transmit interval, or raise the local profile's
  `min_rx_interval` so the window covers the peer's multiplier.
