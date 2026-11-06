### Fixed

- Outbound distribution to a peer with a prefix-ORF list (RFC 5292,
  `prefix_orf_receive = true`) no longer scans every installed entry for
  each prefix. A peer that installed the 4,096-entry cap made each
  distributed prefix cost up to 4,096 comparisons inside the shared RIB
  actor: 10,000 prefixes took about 63 ms instead of about 7 ms. The filter
  is now indexed by entry prefix when it changes, keeping the same
  first-match result, and an ORF message no longer copies the installed
  list.
