### Security

- BFD local discriminators are now drawn at random from the operating
  system's CSPRNG instead of counting up from 1. A control packet selects its
  session by Your Discriminator alone (RFC 5880 §6.8.6), so with sequential
  values a configured peer could derive another session's discriminator from
  its own and send packets that moved that session's state. Random values
  stop that guessing. They do not authenticate the sender: a host that can
  observe a session's packets on the same segment can still forge its state
  (RFC 5880 §9). See [BFD configuration](../docs/reference/configuration.md).
