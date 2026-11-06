### Security

- Bound the work and log volume of an UPDATE that repeats a path attribute.
  RFC 7606 §3 (g) dispositions are unchanged: a duplicate `MP_REACH_NLRI` or
  `MP_UNREACH_NLRI` still resets the session, and other duplicates are still
  discarded after the first occurrence. Previously each repeated occurrence
  produced its own decode record and WARN line, so a single UPDATE could emit
  thousands of log lines while the session stayed up. Repeats of one type now
  share one record per cause. The malformed-attribute WARN is now one summary
  line per UPDATE, logged with the action finally applied and the decoder
  cause behind it, and is
  emitted at power-of-two counts per TCP connection; every cause is still
  logged at DEBUG. The treat-as-withdraw, validation, and ASPA warnings are
  unchanged at one line per UPDATE. `bgp_update_malformed_total` still counts
  every malformed UPDATE.
  **Operator-visible:** `bgp_update_malformed_causes_total` now reports a
  duplicated attribute type, and a prohibited AS-set in repeated `AS_PATH` or
  `AS4_PATH` copies, once per UPDATE rather than once per occurrence.
