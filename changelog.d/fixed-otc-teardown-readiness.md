### Fixed

- The RIB now answers readiness probes while a session with an RFC 9234
  local role goes down. Toward a provider, peer or route server every
  route carrying Only to Customer (OTC) is denied, so the session holds one
  egress-denied entry per blocked prefix, up to a full table learned from
  another provider. Teardown released those entries in one unit that
  served no readiness query until it finished. **Operator-visible:** the
  readiness endpoint stays answered through that teardown; the teardown
  itself is not shorter, and routes and wire output are unchanged.
