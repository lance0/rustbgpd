### Fixed

- Outbound UPDATEs now encode MP_REACH_NLRI as the first path attribute, as
  RFC 7606 §5.1 requires, instead of the last. A receiver that finds a later
  attribute malformed can then still locate the NLRI to treat as withdrawn.
  Receivers accept any attribute order, so this changes only byte layout.
