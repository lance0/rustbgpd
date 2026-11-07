### Security

- An Init or Up BFD session now discards a packet with Your Discriminator
  zero unless its My Discriminator matches the peer's learned discriminator.
  Previously an on-link sender spoofing the peer's address with TTL 255 could
  force an Up session Down with one forged packet, and the session then
  echoed the sender's discriminator. Down sessions still accept the
  zero-discriminator bootstrap, and the real peer can still signal Down
  after its own detection timeout. See
  [BFD configuration](../docs/reference/configuration.md).
