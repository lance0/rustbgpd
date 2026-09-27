### Changed

- `bgp_role_mismatch_total` now labels an OPEN refused for Role capabilities
  that carry only unassigned values (5-255) or a length other than 1 as
  `remote_role="unrecognized"` instead of `remote_role="none"`, and the
  warning log adds the first raw value as `remote_role_raw`, for example
  `[7]`. `remote_role="none"` now means only that the OPEN carried no Role
  capability. The warning log's `local_role` and `remote_role` fields now use
  the metric label values, such as `customer`, instead of Rust debug output.
  See [RFC notes](../docs/reference/rfc-notes.md#rfc-9234--roles-and-only-to-customer).
