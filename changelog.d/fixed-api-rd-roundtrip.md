### Fixed

- RD-typed API requests and CLI selectors accept `0x` or `0X` followed by
  exactly 16 hexadecimal digits for every Route Distinguisher type. API
  output uses raw hexadecimal for Type 2 RDs with a small ASN so their
  text selects the same route instead of a different Type 0 RD. Published
  wire-crate parsing and ordinary RD output are unchanged.
