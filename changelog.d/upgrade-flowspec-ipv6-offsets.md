### Upgrade notes

- Nonzero IPv6 FlowSpec prefix offsets now use RFC 8956 pattern framing in
  both global and VPN rules. A peer still using the former full-prefix
  framing, including pinned GoBGP 4.11.0 and a rustbgpd that has not been
  upgraded yet, sends extra pattern octets for a nonzero offset. The
  receiver then misreads the next component, the MP_REACH_NLRI or
  MP_UNREACH_NLRI attribute fails to decode, and the session resets with
  NOTIFICATION 3/9. The reset drops every family on that session, not only
  FlowSpec, and repeats each time the rule is sent again. Before upgrading,
  withdraw every IPv6 FlowSpec rule with a nonzero prefix offset, global or
  VPN, on both sides, and keep such rules off until every peer uses RFC 8956
  framing. Offset-zero IPv6 and IPv4 rules are unaffected.
