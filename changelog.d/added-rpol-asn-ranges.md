### Added

- `.rpol` asn-sets, ASN dataset files and test-block dataset overrides
  accept inclusive ranges (`64496..64511`) and `PRIVATE_AS`, the RFC 6996
  private-use ASNs (64512–65534 and 4200000000–4294967294). Exact members
  stay one hash probe; ranges add a binary search. A set that holds a range
  cannot be iterated with `for` and is a compile error there; probe it with
  `in`. See [ASN ranges](../docs/reference/rpol-language.md#asn-ranges).
  rs-config-render now emits the invalid-ASN hygiene check as a loop over
  `route.as-path` probing the range set `rs-invalid-asns`, in place of an
  AS-path regex. It rejects the same ASNs in paths up to `max_as_path_len`;
  a longer path is rejected by `reject-long-as-path` alone, which is now its
  recorded reject cause even when it also holds an invalid ASN. Existing
  sources and dataset files are unchanged.
