### Fixed

- Outbound distribution to a peer with a prefix-ORF list (RFC 5292,
  `prefix_orf_receive = true`) no longer scans every installed entry for
  each prefix. With the 4,096-entry cap installed, distribution to that peer
  ran about 12 times slower than to a peer without ORF in the benchmark
  shape; it is now no slower. The filter is indexed by entry
  prefix, with the same first-match result. A DEFER ORF message no longer
  copies the installed list; the index is rebuilt on the first lookup after
  a change.
