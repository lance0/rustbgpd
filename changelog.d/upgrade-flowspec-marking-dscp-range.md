### Upgrade notes

- A FlowSpec controller that sends `traffic_marking.dscp` from 64 to 255
  now gets `INVALID_ARGUMENT` and no rule, where the add used to succeed
  and advertise the value's six low bits. Send the 0 to 63 DSCP itself.
  Raw `extended_communities` values and `rbgp flowspec add`, which
  already refused `mark-dscp` above 63, are unchanged.
