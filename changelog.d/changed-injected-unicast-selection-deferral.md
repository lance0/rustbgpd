### Changed

- API-injected IPv4 and IPv6 unicast routes now participate in selection and
  export during planned-restart Graceful Restart selection deferral, subject
  to existing policy and admission checks. Received candidates remain held,
  and End-of-RIB still follows release selection and the existing completion
  gates. Delete and lease expiry withdraw local intent during the hold.
