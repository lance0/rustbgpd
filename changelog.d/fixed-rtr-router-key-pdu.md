### Fixed

- An RTR cache that serves BGPsec router keys no longer breaks RPKI validation.
  The client rejected the RTR Router Key PDU (type 9) as an unsupported PDU type,
  which failed every transaction that carried one. StayRTR sends router keys by
  default whenever its input holds them, so rustbgpd accepted none of that
  cache's VRPs or ASPAs. Router Key PDUs are now decoded with their framing
  checked and then ignored, because BGPsec path validation is not implemented.
