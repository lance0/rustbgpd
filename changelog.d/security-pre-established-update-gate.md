### Security

- An UPDATE received before the session is Established is no longer imported.
  A peer that completed TCP and sent an UPDATE before its KEEPALIVE, in
  OpenSent or OpenConfirm, had its routes imported under the configured
  neighbor before the OPEN was validated (peer ASN, role, hold time and
  capabilities). With no negotiated peer ASN the route was evaluated as
  internal, so an import policy that denies by remote ASN or external route
  type did not apply. The session then closed with an FSM Error NOTIFICATION
  but no peer-down, so the routes stayed selected and exported until the
  neighbor later completed a session and went down. A pre-Established
  End-of-RIB reached the RIB the same way. UPDATE, End-of-RIB and
  ROUTE-REFRESH received before Established now reach neither BMP nor the RIB:
  the session answers them with NOTIFICATION FSM Error (code 5, subcode 0) and
  closes.
